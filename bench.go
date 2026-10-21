package main

import (
	"context"
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
	Error       string  `json:"error,omitempty"`
	RTTms       float64 `json:"rttMs"`
	Jitterms    float64 `json:"jitterMs"`
	LossPct     float64 `json:"lossPct"`
	Mbps        float64 `json:"mbps"`
	Score       float64 `json:"score"`
	Recommended bool    `json:"recommended"`
}

func benchKey(iran, foreign, family string) string { return iran + "|" + foreign + "|" + family }

func (a *App) benchResults(iran, foreign, family string) []BenchResult {
	a.benchMu.Lock()
	defer a.benchMu.Unlock()
	return a.benchRes[benchKey(iran, foreign, family)]
}

func (a *App) setBench(iran, foreign, family string, rs []BenchResult) {
	a.benchMu.Lock()
	defer a.benchMu.Unlock()
	if a.benchRes == nil {
		a.benchRes = map[string][]BenchResult{}
	}
	a.benchRes[benchKey(iran, foreign, family)] = rs
}

// Bench runs a disposable tunnel for each candidate method, measures it, then tears it down.
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
	j, err := a.jobs.start("", "bench")
	if err != nil {
		return nil, err
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		// a throwaway tunnel object, high index so it never collides with real ones
		bt := &Tunnel{ID: "bench", Name: "route-benchmark", ServerID: req.IranID, ForeignID: req.ForeignID,
			Family: req.Family, Ports: "0", Index: 250, Options: map[string]map[string]string{}, Secrets: map[string]string{}}
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
		j.log("benchmarking %s ⇄ %s (%s)", ipath, kpath, req.Family)
		var out []BenchResult
		for _, m := range cands {
			r := BenchResult{Method: m.ID, Title: m.Title}
			j.log("── %s ──", m.Title)
			if err := a.benchOne(ctx, j, bt, m, irHost, khHost, req.Seconds, &r); err != nil {
				r.Error = err.Error()
				j.log("   skipped: %v", err)
			}
			// always tear down the bench tunnel on both ends
			_, _ = irHost.Run(ctx, teardownScript(bt), nil)
			_, _ = khHost.Run(ctx, teardownScript(bt), nil)
			out = append(out, r)
		}
		rankBench(out)
		a.setBench(req.IranID, req.ForeignID, req.Family, out)
		if best := firstOK(out); best != nil {
			j.log("DONE — best: %s (score %.0f, %.0f Mbps, %.1f ms, loss %.1f%%)",
				best.Title, best.Score, best.Mbps, best.RTTms, best.LossPct)
			a.push(fmt.Sprintf("📊 Route benchmark done — best: %s (%.0f Mbps, %.1f ms)", best.Title, best.Mbps, best.RTTms))
		} else {
			j.log("DONE — no method succeeded on this route")
		}
		j.finish("ok")
	}()
	return j, nil
}

// benchOne deploys one method on the bench tunnel, measures RTT/jitter/loss and throughput.
func (a *App) benchOne(ctx context.Context, j *Job, bt *Tunnel, m *Method, irHost, khHost Host, secs int, r *BenchResult) error {
	irP, khP, err := buildPlans(m, bt, a.store.Server(bt.ServerID), a.store.Server(bt.ForeignID), a.settings())
	if err != nil {
		return err
	}
	_ = a.store.Save()
	_, _ = irHost.Run(ctx, teardownScript(bt), nil)
	_, _ = khHost.Run(ctx, teardownScript(bt), nil)
	if err := a.deploy(ctx, j, "KH", khHost, bt, khP); err != nil {
		return fmt.Errorf("foreign deploy: %w", err)
	}
	if err := a.deploy(ctx, j, "IR", irHost, bt, irP); err != nil {
		return fmt.Errorf("Iran deploy: %w", err)
	}
	d := deriveFor(bt, a.store.Server(bt.ServerID), a.store.Server(bt.ForeignID), a.settings())
	// private tunnel endpoints
	irTun, khTun := d.IRv4, d.KHv4
	if bt.Family == "v6" && (m.ID == "direct6") {
		irTun, khTun = d.IRv6, d.KHv6
	}
	_ = irTun
	time.Sleep(2 * time.Second)

	// latency/jitter/loss: ping from Iran to the foreign tunnel IP
	pingCmd := fmt.Sprintf("ping -n -i 0.2 -c 25 -w 8 %s 2>/dev/null | tail -3", khTun)
	out, _ := irHost.Run(ctx, pingCmd, nil)
	rtt, jit, loss, perr := parsePing(out)
	if perr != nil {
		return fmt.Errorf("no connectivity through tunnel (%v)", perr)
	}
	r.RTTms, r.Jitterms, r.LossPct = rtt, jit, loss

	// throughput: nc-based bulk transfer foreign→Iran over the tunnel
	mbps := a.benchThroughput(ctx, j, irHost, khHost, irTun, khTun, d.BasePort+3, secs)
	r.Mbps = mbps
	r.OK = true
	return nil
}

// benchThroughput pushes zeros through a one-shot nc listener on the foreign tunnel IP.
func (a *App) benchThroughput(ctx context.Context, j *Job, irHost, khHost Host, irTun, khTun string, port, secs int) float64 {
	if !hasNC(ctx, irHost) || !hasNC(ctx, khHost) {
		j.log("   (throughput skipped: nc not installed on both sides)")
		return 0
	}
	// listener on foreign, sinks to /dev/null
	go func() {
		_, _ = khHost.Run(ctx, fmt.Sprintf("timeout %d nc -l -p %d >/dev/null 2>&1 || timeout %d nc -l %d >/dev/null 2>&1 || true", secs+3, port, secs+3, port), nil)
	}()
	time.Sleep(600 * time.Millisecond)
	cmd := fmt.Sprintf(`timeout %d sh -c 'head -c %d /dev/zero | nc -w %d %s %d' 2>/dev/null; echo DONE`,
		secs+2, 1<<30, secs, khTun, port)
	start := time.Now()
	// measure how many bytes we actually sent by counting via pv-less method: send fixed, time it
	// Simpler: send for `secs` seconds and report bytes/time using dd on Iran.
	cmd = fmt.Sprintf(`timeout %d sh -c 'dd if=/dev/zero bs=1M 2>/tmp/bw | nc -w %d %s %d' >/dev/null 2>&1; sleep 0.2; awk "/copied/{print \$1}" /tmp/bw 2>/dev/null | tail -1`, secs, secs, khTun, port)
	out, _ := irHost.Run(ctx, cmd, nil)
	elapsed := time.Since(start).Seconds()
	bytes := parseBytes(out)
	if bytes <= 0 || elapsed <= 0 {
		return 0
	}
	return (float64(bytes) * 8) / (elapsed * 1e6)
}

func hasNC(ctx context.Context, h Host) bool {
	out, _ := h.Run(ctx, "command -v nc >/dev/null && echo yes || echo no", nil)
	return strings.Contains(out, "yes")
}

// rankBench scores results and flags the best. Higher score = better.
func rankBench(rs []BenchResult) {
	for i := range rs {
		r := &rs[i]
		if !r.OK {
			continue
		}
		// throughput dominates; latency, jitter and loss subtract.
		tp := r.Mbps
		if tp <= 0 {
			tp = 1 // latency-only ranking when nc is unavailable
		}
		r.Score = math.Max(0, 100*math.Log10(1+tp)-
			r.RTTms*0.4-r.Jitterms*1.0-r.LossPct*8)
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].OK != rs[j].OK {
			return rs[i].OK
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
