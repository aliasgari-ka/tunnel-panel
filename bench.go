package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// BenchRequest asks to benchmark the viable methods between a pair of servers.
type BenchRequest struct {
	IranID    string   `json:"iranId"`
	ForeignID string   `json:"foreignId"` // "" = this panel host
	Family    string   `json:"family"`
	Methods   []string `json:"methods"` // empty = all that fit the family
	// Running: only the methods the route's tunnels run on the servers now (Methods is
	// filled from them) — the automatic benchmark and the pages' default
	Running bool `json:"running,omitempty"`
	// All: with no Methods, also the methods left out on the route (the dialog's "Every
	// method", see benchplan.go); without it a run of every method skips them
	All bool `json:"all,omitempty"`
	// Auto: started by the automatic benchmark (autobench.go), not by someone on the page
	Auto    bool `json:"-"`
	Seconds int  `json:"seconds"` // throughput probe length per method (default 5)
	MaxMB   int  `json:"maxMB"`   // and at most this much per direction (0 = no cap)
}

// BenchResult is one method's measured quality on the route.
type BenchResult struct {
	Method      string  `json:"method"`
	Title       string  `json:"title"`
	OK          bool    `json:"ok"`
	Skipped     bool    `json:"skipped,omitempty"` // not measurable here (needs config / UDP-only)
	Error       string  `json:"error,omitempty"`
	Kind        string  `json:"kind"` // l3 | forward
	RTTms       float64 `json:"rttMs"`
	Jitterms    float64 `json:"jitterMs"`
	LossPct     float64 `json:"lossPct"`
	LossKnown   bool    `json:"lossKnown"` // ICMP loss is only measurable on L3 tunnels
	Mbps        float64 `json:"mbps"`      // mean of up and down
	UpMbps      float64 `json:"upMbps"`    // Iran -> foreign
	DownMbps    float64 `json:"downMbps"`  // foreign -> Iran (what users downloading feel)
	Score       float64 `json:"score"`
	Recommended bool    `json:"recommended"`
	// At: when this method was measured (unix). A run of only some methods carries the
	// others over from earlier runs: without their own time an old result (even the ★ best)
	// showed as measured by the newest run. 0 = from before this was kept (the run's time).
	At int64 `json:"at,omitempty"`
	// Opts: the alternative options (carrier) it works with on this route, when the
	// defaults passed no traffic; apply and hot standby use them (routeOpts)
	Opts map[string]string `json:"opts,omitempty"`
}

// benchActive is the running benchmark, so the UI can re-attach after navigating away.
type benchActive struct {
	Job     string       `json:"job"`
	Req     BenchRequest `json:"req"`
	Running bool         `json:"running"`
}

func benchKey(iran, foreign, family string) string { return iran + "|" + foreign + "|" + family }

func (a *App) benchResults(iran, foreign, family string) []BenchResult {
	a.benchMu.Lock()
	r := a.benchRes[benchKey(iran, foreign, family)]
	a.benchMu.Unlock()
	if r != nil {
		return r
	}
	// after a restart: the newest saved run for this route
	var best []BenchResult
	a.store.View(func(st *State) {
		for i := len(st.BenchHistory) - 1; i >= 0; i-- {
			h := st.BenchHistory[i]
			if h.IranID == iran && h.ForeignID == foreign && h.Family == family {
				best = h.Results
				return
			}
		}
	})
	if best == nil {
		return []BenchResult{}
	}
	return best
}

// benchHistoryMax: saved runs, all routes together (the page draws each method's trend from
// them: at 60 a route had 2-3 points)
const benchHistoryMax = 120

// recordBench saves a finished run: which Iran server was tested against which foreign
// server, when, and the ranked results.
func (a *App) recordBench(req BenchRequest, rs []BenchResult, full bool) {
	rec := BenchRecord{ID: newID(), At: time.Now().Unix(), IranID: req.IranID, ForeignID: req.ForeignID,
		Family: req.Family, Results: rs, Full: full, Auto: req.Auto, IranName: serverName(a, req.IranID), ForeignName: "this panel host"}
	a.benchMu.Lock()
	delete(a.benchFails, benchKey(req.IranID, req.ForeignID, req.Family))
	a.benchMu.Unlock()
	if req.ForeignID != "" {
		rec.ForeignName = serverName(a, req.ForeignID)
	}
	_ = a.store.Update(func(st *State) error {
		st.BenchHistory = append(st.BenchHistory, rec)
		if n := len(st.BenchHistory); n > benchHistoryMax {
			st.BenchHistory = st.BenchHistory[n-benchHistoryMax:]
		}
		return nil
	})
}

// BenchFail is a benchmark of a route that measured nothing: it couldn't start, a server was
// unreachable, or every method was skipped. Such a run writes no history, so without this the
// page showed the route's old results as if the last attempt had not happened.
type BenchFail struct {
	IranID    string `json:"iranId"`
	ForeignID string `json:"foreignId"`
	Family    string `json:"family"`
	At        int64  `json:"at"`
	Error     string `json:"error"`
	Auto      bool   `json:"auto,omitempty"`
}

// benchFailed remembers the last attempt on a route that measured nothing (until a run of
// that route records results).
func (a *App) benchFailed(req BenchRequest, msg string) {
	fam := req.Family
	if fam != "v6" {
		fam = "v4"
	}
	a.benchMu.Lock()
	defer a.benchMu.Unlock()
	if a.benchFails == nil {
		a.benchFails = map[string]BenchFail{}
	}
	a.benchFails[benchKey(req.IranID, req.ForeignID, fam)] = BenchFail{IranID: req.IranID, ForeignID: req.ForeignID, Family: fam,
		At: time.Now().Unix(), Error: msg, Auto: req.Auto}
}

// benchFailList: the routes whose last attempt measured nothing.
func (a *App) benchFailList() []BenchFail {
	a.benchMu.Lock()
	defer a.benchMu.Unlock()
	out := []BenchFail{}
	for _, f := range a.benchFails {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out
}

// lastBenchAt: when the route's newest saved run was (0 = never).
func (a *App) lastBenchAt(iran, foreign, family string) (at int64) {
	a.store.View(func(st *State) {
		for _, h := range st.BenchHistory {
			if h.IranID == iran && h.ForeignID == foreign && h.Family == family {
				at = max(at, h.At)
			}
		}
	})
	return
}

func (a *App) setBench(iran, foreign, family string, rs []BenchResult) {
	a.benchMu.Lock()
	defer a.benchMu.Unlock()
	if a.benchRes == nil {
		a.benchRes = map[string][]BenchResult{}
	}
	a.benchRes[benchKey(iran, foreign, family)] = rs
}

// activeBench returns the running (or most recent) benchmark, or nil.
func (a *App) activeBench() *benchActive {
	a.benchMu.Lock()
	defer a.benchMu.Unlock()
	if a.benchRun == nil {
		return nil
	}
	j := a.jobs.get(a.benchRun.Job)
	if j == nil {
		return nil
	}
	cp := *a.benchRun
	cp.Running = j.snapshot().Status == "running"
	return &cp
}

// runningToMeasure picks what a Running benchmark measures: the route's running methods,
// less a Golden-GRE that a copy can't run beside (it would take the live tunnel's DNS
// packets). With nothing running there it measures every method (no methods, and a note for
// the log); when Golden-GRE is all that runs, there is nothing it can measure (an error).
func (a *App) runningToMeasure(iran, foreign, fam string) ([]string, string, error) {
	run := a.runningMethods(iran, foreign, fam)
	if len(run) == 0 {
		return nil, fmt.Sprintf("no tunnel runs over %s on this route — measuring every method", famName(fam)), nil
	}
	var out []string
	golden := false
	for _, m := range run {
		if m == "golden" {
			probe := &Tunnel{ID: "bench", ServerID: iran, ForeignID: foreign, Family: fam}
			a.store.View(func(st *State) { golden = goldenConflict(st, probe) != "" })
			if golden {
				continue
			}
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf("only Golden-GRE runs over %s on this route, and a test copy can't run beside it (it would take the live tunnel's DNS packets) — nothing to measure now", famName(fam))
	}
	if golden {
		return out, "Golden-GRE not measured: a tunnel runs it on this route and a test copy would take its DNS packets (its earlier result stays)", nil
	}
	return out, "", nil
}

// benchIsL3 reports whether a method gives a routed link (peer reachable at its tunnel
// IP); the others are port forwarders and are measured through a forwarded port.
func benchIsL3(m *Method, opts map[string]string) bool {
	switch m.ID {
	case "golden", "icmp", "bp_l3", "direct6", "ipsec6", "gre", "espsk", "wg":
		return true
	case "premium":
		get, _ := resolveOptions(m, opts)
		return get("mode") == "ipx"
	}
	return false
}

// Bench runs a disposable tunnel for each candidate method, measures it, then tears it down.
// It runs entirely on the server: leaving the page (or closing the browser) doesn't stop it.
// benchMaxMB caps a throughput test per method and direction.
const benchMaxMB = 6

func (a *App) Bench(req BenchRequest) (*Job, error) {
	srv := a.store.Server(req.IranID)
	if srv == nil {
		return nil, fmt.Errorf("pick an Iran server")
	}
	if req.Family != "v6" {
		req.Family = "v4"
	}
	j, err := a.bench(srv, req)
	if err != nil && j == nil && !errors.Is(err, errBenchBusy) {
		a.benchFailed(req, err.Error())
	}
	return j, err
}

// errBenchBusy: another benchmark holds the slot (not a failure of this route).
var errBenchBusy = errors.New("a benchmark is already running — wait for it to finish")

func (a *App) bench(srv *Server, req BenchRequest) (*Job, error) {
	if req.Seconds <= 0 || req.Seconds > 20 {
		req.Seconds = 5
	}
	// every benchmark is capped (the page's Measure buttons asked for none: a few seconds
	// on a fast path moved 20-30 MB each way per method, on traffic someone pays for)
	if req.MaxMB <= 0 || req.MaxMB > benchMaxMB {
		req.MaxMB = benchMaxMB
	}
	var note string
	if req.Running {
		var err error
		if req.Methods, note, err = a.runningToMeasure(req.IranID, req.ForeignID, req.Family); err != nil {
			return nil, err
		}
	}
	var cands []*Method
	// a run of every method: what can run on the route, the others named in the log with why
	var plan BenchPlan
	left := map[string]string{}
	if len(req.Methods) == 0 {
		plan = a.benchPlan(req.IranID, req.ForeignID, req.Family, req.All)
		for _, l := range plan.Left {
			left[l.Method] = l.Why
		}
	}
	for _, m := range methods {
		if !supportsFamily(m, req.Family) {
			continue
		}
		if len(req.Methods) > 0 && !contains(req.Methods, m.ID) {
			continue
		}
		cands = append(cands, m)
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("no methods match")
	}
	// one benchmark at a time: they all use the same throwaway tunnel slot
	j, err := a.jobs.start("bench", "bench")
	if err != nil {
		return nil, errBenchBusy
	}
	a.benchMu.Lock()
	a.benchRun = &benchActive{Job: j.ID, Req: req}
	a.benchMu.Unlock()
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(45 * time.Minute)
		defer cancel()
		probePort := 40000 + 250*4 + 2
		bt := &Tunnel{ID: "bench", Name: "route-benchmark", ServerID: req.IranID, ForeignID: req.ForeignID,
			Family: req.Family, Ports: strconv.Itoa(probePort), Index: 250,
			Options: map[string]map[string]string{}, Secrets: map[string]string{}}
		irHost, ipath, err := a.reach(ctx, srv, j)
		if err != nil {
			j.log("ERROR: Iran unreachable: %v", err)
			a.benchFailed(req, "Iran server unreachable: "+firstLine(err.Error()))
			j.finish("error")
			return
		}
		khHost, kpath, err := a.foreignHost(ctx, bt, j)
		if err != nil {
			j.log("ERROR: foreign unreachable: %v", err)
			a.benchFailed(req, "foreign server unreachable: "+firstLine(err.Error()))
			j.finish("error")
			return
		}
		if note != "" {
			j.log("%s", note)
		}
		nRun := len(cands) // the methods it measures (a run of every method: the plan's)
		if len(req.Methods) == 0 {
			nRun = len(plan.Methods)
		}
		j.log("benchmarking %s ⇄ %s (%s), %d methods", ipath, kpath, req.Family, nRun)
		if len(plan.Off) > 0 {
			j.log("measured though left out on this route (only measured — nothing is deployed): %s", strings.Join(plan.Off, ", "))
		}
		j.log("firewall — Iran: %s; foreign: %s (each tunnel opens what it needs)", firewallInfo(ctx, irHost), firewallInfo(ctx, khHost))

		// the probe binary on both ends + a probe server on the foreign side for the whole run
		probeOK := pushArtifacts(ctx, j, "IR", irHost, []Artifact{probeArt}) == nil &&
			pushArtifacts(ctx, j, "KH", khHost, []Artifact{probeArt}) == nil
		probeWhy := "" // why there's no probe, for the results (not only the job log)
		if probeOK {
			if perr := probeStarted(ctx, khHost, probeServerUp(probePort)); perr != nil {
				j.log("WARNING: probe server on the foreign side: %v — falling back to ping only (no throughput)", perr)
				probeOK, probeWhy = false, "the probe server on the foreign side didn't start: "+firstLine(perr.Error())
			}
		} else {
			j.log("WARNING: could not install the probe — falling back to ping only (no throughput)")
			probeWhy = "the probe couldn't be installed"
		}
		defer func() { _, _ = khHost.Run(context.Background(), probeServerDown(probePort), nil) }()

		var out []BenchResult
		// a run of only some methods keeps the route's earlier results for the others: the
		// Routes page, failover and hot standby read the latest run as the whole picture
		// (and so does a full run cut short — cancelled or out of time: its few new results
		// replaced the whole route's, and hot standby / failover then had 5 methods of 20)
		earlier := a.benchResults(req.IranID, req.ForeignID, req.Family)
		earlierAt := a.lastBenchAt(req.IranID, req.ForeignID, req.Family)
		keepEarlier := len(req.Methods) > 0
		measured := 0 // methods actually deployed and measured in this run
		for i, m := range cands {
			if ctx.Err() != nil {
				break // cancelled
			}
			r := BenchResult{Method: m.ID, Title: m.Title, Kind: "forward", At: time.Now().Unix()}
			if benchIsL3(m, nil) {
				r.Kind = "l3"
			}
			j.log("── [%d/%d] %s ──", i+1, len(cands), m.Title)
			if why, ok := left[m.ID]; ok {
				if why == benchRouteOff {
					// its earlier result stays (a run that measured it on purpose said whether it works)
					if e := benchEarlier(earlier, earlierAt, m.ID); e != nil {
						j.log("   skipped: left out on this route (Routes page) — keeps its earlier result")
						out = append(out, *e)
						continue
					}
					why = "excluded on this route"
				}
				r.Skipped, r.Error = true, why
				j.log("   skipped: %s", why)
				out = append(out, r)
				continue
			}
			if m.ID == "spoof" {
				r.Skipped = true
				r.Error = "UDP-only pipe with forged source IPs — set it up on a tunnel and test with your UDP app"
				j.log("   skipped: %s", r.Error)
				out = append(out, r)
				continue
			}
			measured++
			err := a.benchOne(ctx, j, bt, m, irHost, khHost, req.Seconds, req.MaxMB, probeOK, probePort, &r)
			if err != nil && probeWhy != "" && strings.HasPrefix(err.Error(), "probe unavailable") {
				err = fmt.Errorf("%v (%s)", err, probeWhy)
			}
			// (only when it deployed but carried nothing: a config or start error would just repeat)
			// (pings passing while bulk data stalls is an MTU problem: GRE's alternatives are
			// lower MTUs)
			if err != nil && m.Alts != nil && (strings.Contains(err.Error(), "no traffic passes") || strings.Contains(err.Error(), "no bulk data passes") || strings.Contains(err.Error(), "can't run on this")) && ctx.Err() == nil {
				// the default carrier passes nothing here: try the method's other carriers
				first, tried := err, []string{}
				for _, alt := range m.Alts(req.Family) {
					if ctx.Err() != nil {
						break
					}
					j.log("   %v", firstLine(first.Error()))
					j.log("   → trying %s instead", altLabel(alt))
					tctx, tcancel := context.WithTimeout(context.Background(), time.Minute)
					_, _ = irHost.Run(tctx, teardownScript(bt), nil)
					_, _ = khHost.Run(tctx, teardownScript(bt), nil)
					tcancel()
					bt.Options[m.ID] = alt
					kind := "forward" // an alternative may change the kind (Premium: ipx is L3, tcpmux forwards)
					if benchIsL3(m, alt) {
						kind = "l3"
					}
					ar := BenchResult{Method: m.ID, Title: m.Title, Kind: kind, At: time.Now().Unix()}
					err = a.benchOne(ctx, j, bt, m, irHost, khHost, req.Seconds, req.MaxMB, probeOK, probePort, &ar)
					tried = append(tried, altLabel(alt))
					if err == nil {
						ar.Opts, ar.Title = alt, m.Title+" · "+altLabel(alt)
						r = ar
						j.log("   ✓ works with %s — apply and hot standby will use it on this route", altLabel(alt))
						break
					}
				}
				delete(bt.Options, m.ID)
				if err != nil {
					err = fmt.Errorf("%v — also tried %s: no traffic either (this route likely filters these carriers)", firstLine(first.Error()), strings.Join(tried, " / "))
				}
			}
			// cancelled or out of time while measuring: that says nothing about the method — a
			// failure here replaced its earlier good result (and dropped it from failover)
			aborted := err != nil && ctx.Err() != nil
			if aborted {
				j.log("   stopped before the measurement ended — %s keeps its earlier result", m.Title)
			} else if err != nil {
				r.Error = benchFailHint(m.ID, err.Error())
				j.log("   FAILED: %v", r.Error)
			} else {
				j.log("   ok: ↓%.1f ↑%.1f Mbps, RTT %.1f ms, jitter %.1f ms", r.DownMbps, r.UpMbps, r.RTTms, r.Jitterms)
			}
			// always tear down the bench tunnel on both ends (even when cancelled)
			tctx, tcancel := context.WithTimeout(context.Background(), time.Minute)
			_, _ = irHost.Run(tctx, teardownScript(bt), nil)
			_, _ = khHost.Run(tctx, teardownScript(bt), nil)
			tcancel()
			if aborted {
				measured--
				break
			}
			out = append(out, r)
			// publish partial results so the page shows progress even after a reload
			partial := withEarlier(append([]BenchResult(nil), out...), earlier, earlierAt)
			rankBench(partial)
			a.setBench(req.IranID, req.ForeignID, req.Family, partial)
		}
		if keepEarlier || ctx.Err() != nil {
			out = withEarlier(out, earlier, earlierAt)
		}
		if measured == 0 {
			// nothing new (all skipped or cancelled at once): the route's results and history
			// stay as they were, so it doesn't look freshly measured
			j.log("DONE — nothing was measured")
			if ctx.Err() == nil {
				a.benchFailed(req, "nothing was measured: every method was skipped or left out on this route")
			}
			j.finish("ok")
			return
		}
		rankBench(out)
		a.setBench(req.IranID, req.ForeignID, req.Family, out)
		a.recordBench(req, out, len(req.Methods) == 0 && ctx.Err() == nil)
		if best := firstOK(out); best != nil {
			j.log("DONE — best: %s (score %.0f, ↓%.0f/↑%.0f Mbps, %.1f ms)",
				best.Title, best.Score, best.DownMbps, best.UpMbps, best.RTTms)
			a.pushInfo(fmt.Sprintf("📊 Route benchmark done — best: %s (↓%.0f Mbps, %.1f ms)", best.Title, best.DownMbps, best.RTTms))
		} else {
			j.log("DONE — no method succeeded on this route")
		}
		j.finish("ok")
	}()
	return j, nil
}

const probeBin = "/usr/local/lib/tunnel-panel/tp-probe"

// unitTail returns the last n meaningful log lines of a unit's current run, joined.
func unitTail(ctx context.Context, h Host, unit string, n int) string {
	out, _ := h.Run(ctx, fmt.Sprintf(`inv=$(systemctl show -p InvocationID --value %[1]s 2>/dev/null)
[ -n "$inv" ] && journalctl _SYSTEMD_INVOCATION_ID=$inv --no-pager -o cat 2>/dev/null | grep -v -e '^Started ' -e '^Starting ' | tail -%[2]d`, unit, n), nil)
	var keep []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			if len(l) > 160 {
				l = l[:160] + "…"
			}
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, " / ")
}

// firewallInfo summarises a host's inbound filtering in a few words.
func firewallInfo(ctx context.Context, h Host) string {
	out, _ := h.Run(ctx, `p=$(iptables -w -S INPUT 2>/dev/null | head -1 | awk '{print $3}')
u=$(ufw status 2>/dev/null | head -1 | awk '{print $2}')
f=$(firewall-cmd --state 2>/dev/null)
echo "INPUT=${p:-?} ufw=${u:-none} firewalld=${f:-none}"`, nil)
	return strings.TrimSpace(lastLine(out))
}

func probeServerUp(port int) string { return probeServerUpLife(port, 2700) }

// probeServerUpLife starts a probe server on port for life seconds (one per port, so a
// tunnel speed test and a benchmark never kill each other's server).
func probeServerUpLife(port, life int) string {
	return fmt.Sprintf(`pkill -f -- '-listen :%[1]d -life' 2>/dev/null || true
# the old server exits a moment after the signal: starting the new one before that failed
# with "address already in use" (seen live), so wait until it is gone (force after 3 s)
for i in $(seq 1 15); do pgrep -f -- '-listen :%[1]d -life' >/dev/null 2>&1 || break; sleep 0.2; done
pkill -9 -f -- '-listen :%[1]d -life' 2>/dev/null || true
%[4]s%[5]siptables -C INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || true
ip6tables -C INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || true
setsid nohup %[2]s probe serve -listen :%[1]d -life %[3]d >/tmp/tp-probe-%[1]d.log 2>&1 </dev/null &
# report whether it really listens: a probe that can't start (wrong binary, port taken)
# otherwise shows up later as "connection refused" inside every tunnel test
for i in 1 2 3 4 5 6 7 8 9 10; do
  if timeout 1 bash -c '</dev/tcp/127.0.0.1/%[1]d' 2>/dev/null; then echo probe-up; exit 0; fi
  sleep 0.3
done
echo "probe-failed: the probe server does not listen on port %[1]d: $(tail -c 300 /tmp/tp-probe-%[1]d.log 2>/dev/null | tr '\n' ' ')$(h=$(ss -Hltnp "( sport = :%[1]d )" 2>/dev/null | grep -o 'users:.*' | head -1); [ -n "$h" ] && echo " — the port is held by $h")$(c=$(ss -Htanp "( sport = :%[1]d )" 2>/dev/null | grep -v LISTEN | head -1 | awk '{print $1" "$4" → "$5" "$6}'); [ -n "$c" ] && echo " — a connection still uses it as its local port ($c)")"
`, port, probeBin, life, panelPortsSetup, freePort(port))
}

// probeStarted runs probeServerUp(Life) and turns a probe that doesn't listen into an error.
func probeStarted(ctx context.Context, h Host, script string) error {
	out, err := h.Run(ctx, script, nil)
	if strings.Contains(out, "probe-up") {
		return nil
	}
	if i := strings.Index(out, "probe-failed: "); i >= 0 {
		return fmt.Errorf("%s", strings.TrimSpace(out[i+len("probe-failed: "):]))
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("the probe server did not start")
}

func probeServerDown(port int) string {
	return fmt.Sprintf(`pkill -f -- '-listen :%[1]d -life' 2>/dev/null || true
iptables -D INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || true
ip6tables -D INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || true
`, port)
}

// benchOne deploys one method on the bench tunnel and measures it end to end.
func (a *App) benchOne(ctx context.Context, j *Job, bt *Tunnel, m *Method, irHost, khHost Host, secs, maxMB int, probeOK bool, port int, r *BenchResult) error {
	if m.ID == "golden" {
		var o string
		a.store.View(func(st *State) { o = goldenConflict(st, bt) })
		if o != "" {
			// testing it here would take the live tunnel's DNS packets for the duration
			return fmt.Errorf("not tested: tunnel %q already runs Golden-GRE on this route", o)
		}
	}
	irP, khP, err := buildPlans(m, bt, a.store.Server(bt.ServerID), a.store.Server(bt.ForeignID), a.settings())
	if err != nil {
		return err
	}
	_, _ = irHost.Run(ctx, teardownScript(bt), nil)
	_, _ = khHost.Run(ctx, teardownScript(bt), nil)
	if err := a.deploy(ctx, j, "KH", khHost, bt, khP); err != nil {
		return fmt.Errorf("foreign deploy: %w", err)
	}
	if err := a.deploy(ctx, j, "IR", irHost, bt, irP); err != nil {
		return fmt.Errorf("Iran deploy: %w", err)
	}
	d := deriveFor(bt, a.store.Server(bt.ServerID), a.store.Server(bt.ForeignID), a.settings())
	l3 := r.Kind == "l3"
	// L3: talk to the foreign tunnel IP directly. Forwarders: Iran's forwarded port.
	target := fmt.Sprintf("127.0.0.1:%d", port)
	if l3 {
		target = fmt.Sprintf("%s:%d", d.KHv4, port)
	}

	if !probeOK {
		if !l3 {
			return fmt.Errorf("probe unavailable — port forwarders can't be measured with ping")
		}
		return a.benchPing(ctx, j, irHost, d.KHv4, r)
	}

	// wait for the tunnel to come up (IKE, reverse dial-in, handshakes take a few seconds)
	j.log("   waiting for the tunnel to pass traffic (%s)…", target)
	var rt probeRTT
	var lastErr error
	deadline := time.Now().Add(25 * time.Second)
	for {
		rt, lastErr = runProbe[probeRTT](ctx, irHost, fmt.Sprintf("probe rtt -addr %s -n 20", target), 25)
		if lastErr == nil || time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	if lastErr != nil {
		// the daemons usually say why (dial timeout, auth, bind) — show it
		why := ""
		if l := unitTail(ctx, khHost, unitName(bt), 2); l != "" {
			why += " | foreign: " + l
		}
		if l := unitTail(ctx, irHost, unitName(bt), 2); l != "" {
			why += " | Iran: " + l
		}
		return fmt.Errorf("unit is running but no traffic passes through the tunnel within 25s (%v)%s", lastErr, why)
	}
	r.RTTms, r.Jitterms = rt.RTTms, rt.Jitterms
	if l3 {
		out, _ := irHost.Run(ctx, fmt.Sprintf("ping -n -i 0.2 -c 25 -w 8 %s 2>/dev/null | tail -3", d.KHv4), nil)
		if _, _, loss, perr := parsePing(out); perr == nil || loss >= 100 {
			if perr == nil {
				r.LossPct, r.LossKnown = loss, true
			}
		}
	}
	limit := ""
	if maxMB > 0 {
		limit = fmt.Sprintf(" -max %d", maxMB)
		j.log("   RTT %.1f ms, jitter %.1f ms — measuring throughput (%ds / at most %d MB each way)", r.RTTms, r.Jitterms, secs, maxMB)
	} else {
		j.log("   RTT %.1f ms, jitter %.1f ms — measuring throughput (%ds each way)", r.RTTms, r.Jitterms, secs)
	}
	up, upErr := runProbe[probeBW](ctx, irHost, fmt.Sprintf("probe bw -addr %s -secs %d%s", target, secs, limit), secs+30)
	if upErr == nil {
		r.UpMbps = up.Mbps
	} else {
		j.log("   upload test failed: %v", upErr)
	}
	dn, dnErr := runProbe[probeBW](ctx, irHost, fmt.Sprintf("probe bw -down -addr %s -secs %d%s", target, secs, limit), secs+30)
	if dnErr == nil {
		r.DownMbps = dn.Mbps
	} else {
		j.log("   download test failed: %v", dnErr)
	}
	// small echoes passed but no bulk data either way: users would get a path that answers
	// pings and stalls on every real transfer, so it must not rank as working
	if upErr != nil && dnErr != nil {
		// the RTT probe had just connected and echoed through the tunnel; when even a new
		// connection (a small SYN) no longer gets through, the route cut the tunnel after it
		// started — a filter that recognizes the protocol (seen live: WireGuard on every
		// Iran route, 15 s after the handshake), not a packet size a lower MTU would fix
		if strings.Contains(upErr.Error(), "dial tcp") && strings.Contains(dnErr.Error(), "dial tcp") {
			return fmt.Errorf("passed traffic at first (RTT %.0f ms), then stopped passing even new connections (%v) — the route cut the tunnel off after it started: a filter that recognizes this protocol (DPI), not an MTU problem", r.RTTms, dnErr)
		}
		return fmt.Errorf("answers small packets (RTT %.0f ms) but no bulk data passes either way (%v) — typically an MTU problem on this route: try a lower MTU in the method's options", r.RTTms, dnErr)
	}
	// one direction passing is no working tunnel either: every download starts with a
	// request upstream (seen live: an upload that timed out next to a download that passed,
	// and the method came out "best" on the route)
	if upErr != nil {
		return fmt.Errorf("download passes (↓%.1f Mbit/s) but the upload stalls (%v) — users' requests and uploads would hang on this route", r.DownMbps, upErr)
	}
	if dnErr != nil {
		return fmt.Errorf("upload passes (↑%.1f Mbit/s) but the download stalls (%v) — users' downloads would hang on this route", r.UpMbps, dnErr)
	}
	r.Mbps = (r.UpMbps + r.DownMbps) / 2
	r.OK = true
	return nil
}

// benchPing is the no-probe fallback for L3 tunnels: latency/loss only.
func (a *App) benchPing(ctx context.Context, j *Job, irHost Host, khTun string, r *BenchResult) error {
	var out string
	for i := 0; i < 10; i++ {
		out, _ = irHost.Run(ctx, fmt.Sprintf("ping -n -i 0.2 -c 25 -w 8 %s 2>/dev/null | tail -3", khTun), nil)
		if _, _, loss, err := parsePing(out); err == nil && loss < 100 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	rtt, jit, loss, err := parsePing(out)
	if err != nil {
		return fmt.Errorf("no connectivity through tunnel (%v)", err)
	}
	r.RTTms, r.Jitterms, r.LossPct, r.LossKnown, r.OK = rtt, jit, loss, true, true
	return nil
}

type probeRTT struct {
	RTTms    float64 `json:"rttMs"`
	Jitterms float64 `json:"jitterMs"`
	Error    string  `json:"error"`
}

type probeBW struct {
	Mbps  float64 `json:"mbps"`
	Error string  `json:"error"`
}

// runProbe runs the probe binary on a host and decodes its one-line JSON answer.
func runProbe[T any](ctx context.Context, h Host, args string, timeout int) (T, error) {
	var v T
	out, _ := h.Run(ctx, fmt.Sprintf("timeout %d %s %s 2>&1 | tail -1", timeout, probeBin, args), nil)
	line := strings.TrimSpace(lastLine(out))
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		if line == "" || line == "unknown" {
			line = "no output (timed out)"
		}
		return v, fmt.Errorf("%s", line)
	}
	if e.Error != "" {
		return v, fmt.Errorf("%s", e.Error)
	}
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		return v, err
	}
	return v, nil
}

// rankBench scores results and flags the best. Higher score = better.
// Throughput dominates (log scale, so 400 vs 500 Mbps matters less than 5 vs 50);
// latency, jitter and loss subtract. Without a throughput figure it ranks on latency.
// withEarlier adds the earlier results of methods this run didn't measure, each keeping
// when it was measured (one saved before results had a time gets at: its run's time).
func withEarlier(out, earlier []BenchResult, at int64) []BenchResult {
	have := map[string]bool{}
	for _, r := range out {
		have[r.Method] = true
	}
	for _, r := range earlier {
		if !have[r.Method] {
			if r.At == 0 {
				r.At = at
			}
			out = append(out, r)
		}
	}
	return out
}

func rankBench(rs []BenchResult) {
	for i := range rs {
		r := &rs[i]
		r.Recommended = false
		if !r.OK {
			continue
		}
		base := 60.0
		if r.Mbps > 0 {
			// weight download (foreign -> Iran) higher: that's what users mostly pull
			tp := 0.65*r.DownMbps + 0.35*r.UpMbps
			base = 100 * math.Log10(1+tp)
		}
		r.Score = math.Max(1, base-r.RTTms*0.15-r.Jitterms*1.0-r.LossPct*8)
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].OK != rs[j].OK {
			return rs[i].OK
		}
		if rs[i].Skipped != rs[j].Skipped {
			return rs[j].Skipped
		}
		return rs[i].Score > rs[j].Score
	})
	if len(rs) > 0 && rs[0].OK {
		rs[0].Recommended = true
	}
}

func firstOK(rs []BenchResult) *BenchResult {
	for i := range rs {
		if rs[i].OK {
			return &rs[i]
		}
	}
	return nil
}

// parsePing extracts avg RTT, mdev (jitter) and loss% from `ping` tail output.
func parsePing(out string) (rtt, jit, loss float64, err error) {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "packet loss") {
			if i := strings.Index(l, "%"); i > 0 {
				j := i - 1
				for j >= 0 && (l[j] >= '0' && l[j] <= '9' || l[j] == '.') {
					j--
				}
				loss, _ = strconv.ParseFloat(l[j+1:i], 64)
			}
		}
		if strings.Contains(l, "rtt") || strings.Contains(l, "round-trip") {
			if i := strings.Index(l, "="); i > 0 {
				nums := strings.Split(strings.TrimSpace(strings.Split(l[i+1:], "ms")[0]), "/")
				if len(nums) >= 4 {
					rtt, _ = strconv.ParseFloat(nums[1], 64)
					jit, _ = strconv.ParseFloat(nums[3], 64)
				}
			}
		}
	}
	if rtt == 0 && loss >= 100 {
		return 0, 0, 100, fmt.Errorf("100%% loss")
	}
	if rtt == 0 {
		return 0, 0, 0, fmt.Errorf("no rtt line")
	}
	return rtt, jit, loss, nil
}

// parseBytes reads the "N bytes" figure dd writes to stderr.
func parseBytes(s string) float64 {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// routeOpts is the alternative carrier the benchmark found working for method mid on the
// tunnel's route (family fam), limited to the options the user left at their default —
// a carrier picked on purpose is never overridden.
func (a *App) routeOpts(t *Tunnel, mid, fam string) map[string]string {
	m := methodByID[mid]
	if m == nil {
		return nil
	}
	for _, r := range a.benchResults(t.ServerID, t.ForeignID, fam) {
		if r.Method != mid || !r.OK || len(r.Opts) == 0 {
			continue
		}
		out := map[string]string{}
		for k, v := range r.Opts {
			if t.manualOpt(mid, k) {
				continue // set by hand: the benchmark's pick never replaces it
			}
			cur := t.Options[mid][k]
			if f := methodField(m, k); cur == "" || (f != nil && cur == f.Default) {
				out[k] = v
			}
		}
		return out
	}
	return nil
}

// benchFailHint adds what a method's "no traffic" failure usually means on a route.
func benchFailHint(methodID, e string) string {
	if methodID == "ipsec6" && strings.Contains(e, "no traffic passes") { // (the IKE IPsec method)
		e += " — IPsec needs UDP 500/4500 (IKE) between the servers; if the UDP-based methods fail on this route too, the network drops UDP"
	}
	return e
}
