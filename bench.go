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
	case "golden", "bp_l3", "direct6", "ipsec6", "gre":
		return true
	case "premium":
		get, _ := resolveOptions(m, opts)
		return get("mode") == "ipx"
	}
	return false
}

// Bench runs a disposable tunnel for each candidate method, measures it, then tears it down.
// It runs entirely on the server: leaving the page (or closing the browser) doesn't stop it.
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
		if probeOK {
			_, _ = khHost.Run(ctx, probeServerUp(probePort), nil)
		} else {
			j.log("WARNING: could not install the probe — falling back to ping only (no throughput)")
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
			if m.ID == "spoof" {
				r.Skipped = true
				r.Error = "UDP-only pipe with forged source IPs — set it up on a tunnel and test with your UDP app"
				j.log("   skipped: %s", r.Error)
				out = append(out, r)
				continue
			}
			if err := a.benchOne(ctx, j, bt, m, irHost, khHost, req.Seconds, probeOK, probePort, &r); err != nil {
				r.Error = err.Error()
				j.log("   FAILED: %v", err)
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
iptables -C INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || true
ip6tables -C INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || true
setsid nohup %[2]s probe serve -listen :%[1]d -life %[3]d >/dev/null 2>&1 </dev/null &
sleep 0.5; echo probe-up
`, port, probeBin, life)
}

func probeServerDown(port int) string {
	return fmt.Sprintf(`pkill -f -- '-listen :%[1]d -life' 2>/dev/null || true
iptables -D INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || true
ip6tables -D INPUT -p tcp --dport %[1]d -j ACCEPT 2>/dev/null || true
`, port)
}

// benchOne deploys one method on the bench tunnel and measures it end to end.
func (a *App) benchOne(ctx context.Context, j *Job, bt *Tunnel, m *Method, irHost, khHost Host, secs int, probeOK bool, port int, r *BenchResult) error {
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
	j.log("   RTT %.1f ms, jitter %.1f ms — measuring throughput (%ds each way)", r.RTTms, r.Jitterms, secs)
	if up, err := runProbe[probeBW](ctx, irHost, fmt.Sprintf("probe bw -addr %s -secs %d", target, secs), secs+30); err == nil {
		r.UpMbps = up.Mbps
	} else {
		j.log("   upload test failed: %v", err)
	}
	if dn, err := runProbe[probeBW](ctx, irHost, fmt.Sprintf("probe bw -down -addr %s -secs %d", target, secs), secs+30); err == nil {
		r.DownMbps = dn.Mbps
	} else {
		j.log("   download test failed: %v", err)
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
