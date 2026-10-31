package main

import (
	"context"
	"encoding/json"
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
	Seconds   int      `json:"seconds"` // throughput probe length per method (default 5)
	MaxMB     int      `json:"maxMB"`   // and at most this much per direction (0 = no cap)
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

const benchHistoryMax = 60

// recordBench saves a finished run: which Iran server was tested against which foreign
// server, when, and the ranked results.
func (a *App) recordBench(req BenchRequest, rs []BenchResult) {
	rec := BenchRecord{ID: newID(), At: time.Now().Unix(), IranID: req.IranID, ForeignID: req.ForeignID,
		Family: req.Family, Results: rs, IranName: serverName(a, req.IranID), ForeignName: "this panel host"}
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

// benchIsL3 reports whether a method gives a routed link (peer reachable at its tunnel
// IP); the others are port forwarders and are measured through a forwarded port.
func benchIsL3(m *Method, opts map[string]string) bool {
	switch m.ID {
	case "golden", "icmp", "bp_l3", "direct6", "ipsec6", "gre", "espsk":
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
	if req.Seconds <= 0 || req.Seconds > 20 {
		req.Seconds = 5
	}
	// every benchmark is capped (the page's Measure buttons asked for none: a few seconds
	// on a fast path moved 20-30 MB each way per method, on traffic someone pays for)
	if req.MaxMB <= 0 || req.MaxMB > benchMaxMB {
		req.MaxMB = benchMaxMB
	}
	var cands []*Method
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
		return nil, fmt.Errorf("a benchmark is already running — wait for it to finish")
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
			j.finish("error")
			return
		}
		khHost, kpath, err := a.foreignHost(ctx, bt, j)
		if err != nil {
			j.log("ERROR: foreign unreachable: %v", err)
			j.finish("error")
			return
		}
		j.log("benchmarking %s ⇄ %s (%s), %d methods", ipath, kpath, req.Family, len(cands))
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
		for i, m := range cands {
			if ctx.Err() != nil {
				break // cancelled
			}
			r := BenchResult{Method: m.ID, Title: m.Title, Kind: "forward"}
			if benchIsL3(m, nil) {
				r.Kind = "l3"
			}
			j.log("── [%d/%d] %s ──", i+1, len(cands), m.Title)
			if len(req.Methods) == 0 && a.routeSkipped(req.IranID, req.ForeignID, m.ID, req.Family) {
				r.Skipped, r.Error = true, "excluded on this route"
				j.log("   skipped: excluded on this route (Routes page)")
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
					ar := BenchResult{Method: m.ID, Title: m.Title, Kind: kind}
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
			if err != nil {
				r.Error = err.Error()
				if m.ID == "ipsec" && strings.Contains(r.Error, "no traffic passes") {
					r.Error += " — IPsec needs UDP 500/4500 (IKE) between the servers; if the UDP-based methods fail on this route too, the network drops UDP"
				}
				j.log("   FAILED: %v", r.Error)
			} else {
				j.log("   ok: ↓%.1f ↑%.1f Mbps, RTT %.1f ms, jitter %.1f ms", r.DownMbps, r.UpMbps, r.RTTms, r.Jitterms)
			}
			// always tear down the bench tunnel on both ends (even when cancelled)
			tctx, tcancel := context.WithTimeout(context.Background(), time.Minute)
			_, _ = irHost.Run(tctx, teardownScript(bt), nil)
			_, _ = khHost.Run(tctx, teardownScript(bt), nil)
			tcancel()
			out = append(out, r)
			// publish partial results so the page shows progress even after a reload
			partial := append([]BenchResult(nil), out...)
			rankBench(partial)
			a.setBench(req.IranID, req.ForeignID, req.Family, partial)
		}
		rankBench(out)
		a.setBench(req.IranID, req.ForeignID, req.Family, out)
		a.recordBench(req, out)
		if best := firstOK(out); best != nil {
			j.log("DONE — best: %s (score %.0f, ↓%.0f/↑%.0f Mbps, %.1f ms)",
				best.Title, best.Score, best.DownMbps, best.UpMbps, best.RTTms)
			a.push(fmt.Sprintf("📊 Route benchmark done — best: %s (↓%.0f Mbps, %.1f ms)", best.Title, best.DownMbps, best.RTTms))
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
		if lastErr == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Second)
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
		return fmt.Errorf("answers small packets (RTT %.0f ms) but no bulk data passes either way (%v) — typically an MTU problem on this route: try a lower MTU in the method's options", r.RTTms, dnErr)
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
			cur := t.Options[mid][k]
			if f := methodField(m, k); cur == "" || (f != nil && cur == f.Default) {
				out[k] = v
			}
		}
		return out
	}
	return nil
}
