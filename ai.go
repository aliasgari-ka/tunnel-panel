package main

// AI analysis: the panel's state (tunnels, their paths and how they measure, recent outages
// and alerts, the servers' load, the last benchmarks) goes to Claude, which writes a report
// in Persian with what to improve. The few changes it may suggest that cannot cut anyone off
// (a hot-standby switch to a running path, the switcher's auto/manual mode) come back as
// actions the admin applies with one click; everything else is advice. Server addresses
// and every secret stay out of what is sent.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/shared/constant"
)

const aiModel = "claude-opus-5-5"

// AIReport is the last analysis, kept in the state.
type AIReport struct {
	At       int64       `json:"at"`
	Summary  string      `json:"summary"`
	Findings []AIFinding `json:"findings"`
	Actions  []AIAction  `json:"actions"`
	Error    string      `json:"error,omitempty"`
}

type AIFinding struct {
	Severity string `json:"severity"` // high | medium | low
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
}

// AIAction is a change the panel can make without cutting users (see aiApply).
type AIAction struct {
	Kind    string `json:"kind"`   // switch_path | hs_mode
	Tunnel  string `json:"tunnel"` // tunnel id
	Path    string `json:"path"`   // switch_path: "method|family" of a running path
	Auto    bool   `json:"auto"`   // hs_mode
	Why     string `json:"why"`
	Applied int64  `json:"applied,omitempty"`
	Result  string `json:"result,omitempty"`
}

// ---- recent alerts (what the switcher and the monitors reported), for the analysis

var aiAlerts = struct {
	sync.Mutex
	l []aiAlert
}{}

type aiAlert struct {
	At  int64  `json:"at"`
	Msg string `json:"msg"`
}

func aiNoteAlert(msg string) {
	aiAlerts.Lock()
	aiAlerts.l = append(aiAlerts.l, aiAlert{time.Now().Unix(), clipTo(msg, 400)})
	if n := len(aiAlerts.l); n > 300 {
		aiAlerts.l = append([]aiAlert(nil), aiAlerts.l[n-300:]...)
	}
	aiAlerts.Unlock()
}

// ---- the snapshot

var aiIPRe = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b|\b[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){3,7}\b`)

// aiRedact keeps addresses out of the text sent (names identify the servers well enough).
func aiRedact(s string) string { return aiIPRe.ReplaceAllString(s, "<ip>") }

func (a *App) aiSnapshot() map[string]any {
	type pathV struct {
		Key     string   `json:"key"`
		OK      bool     `json:"ok"`
		RTTms   int      `json:"rttMs"`
		LossPct *float64 `json:"lossPct,omitempty"`
		Mbps    float64  `json:"mbps,omitempty"`
		Users   bool     `json:"usersOnIt,omitempty"`
		Failed  string   `json:"failedToStart,omitempty"`
	}
	type tunV struct {
		ID         string         `json:"id"`
		Name       string         `json:"name"`
		Iran       string         `json:"iranServer"`
		Foreign    string         `json:"foreignServer"`
		Method     string         `json:"method"`
		Family     string         `json:"family"`
		Running    bool           `json:"running"`
		HotStandby bool           `json:"hotStandby"`
		Auto       bool           `json:"autoMode,omitempty"`
		Health     string         `json:"monitorVerdict"`
		Failover   *FailoverState `json:"failover,omitempty"`
		Paths      []pathV        `json:"paths,omitempty"`
		DownMbps   float64        `json:"usersDownMbpsNow,omitempty"`
		UpMbps     float64        `json:"usersUpMbpsNow,omitempty"`
	}
	type srvV struct {
		Name     string  `json:"name"`
		Role     string  `json:"role"`
		Country  string  `json:"country,omitempty"`
		Reach    bool    `json:"reachable"`
		Cores    int     `json:"cores,omitempty"`
		CPU      float64 `json:"cpuPct,omitempty"`
		Steal    float64 `json:"stealPct,omitempty"`
		SoftIRQ  float64 `json:"softirqPct,omitempty"`
		IRQHint  string  `json:"irqHint,omitempty"`
		MemPct   float64 `json:"memPct,omitempty"`
		Conntrk  int64   `json:"conntrack,omitempty"`
		CTMax    int64   `json:"conntrackMax,omitempty"`
		Load1    float64 `json:"load1,omitempty"`
		Resource string  `json:"resourceError,omitempty"`
	}
	snap := a.Traffic()
	since := time.Now().Add(-7 * 24 * time.Hour).Unix()
	var tuns []tunV
	var srvs []srvV
	var outs []Outage
	var bench []map[string]any
	names := map[string]string{}
	a.store.View(func(st *State) {
		for _, s := range st.Servers {
			names[s.ID] = s.Name
		}
		for _, s := range st.Servers {
			if s.Owner != "" {
				continue
			}
			v := srvV{Name: s.Name, Role: s.Role, Country: s.Country, Reach: a.serverReachable(s.ID)}
			if r := snap.Res[s.ID]; r != nil {
				v.Cores, v.CPU, v.Steal, v.SoftIRQ, v.IRQHint, v.Conntrk, v.CTMax, v.Load1, v.Resource = r.Cores, r.CPU, r.Steal, r.SoftIRQ, r.IRQHint, r.Conntrack, r.CTMax, r.Load[0], r.Error
				if r.MemTotal > 0 {
					v.MemPct = float64(r.MemUsed) * 100 / float64(r.MemTotal)
				}
			}
			srvs = append(srvs, v)
		}
		for _, t := range st.Tunnels {
			if t.Owner != "" {
				continue
			}
			v := tunV{ID: t.ID, Name: t.Name, Iran: names[t.ServerID], Foreign: names[t.ForeignID], Method: t.Active, Family: t.Family,
				Running: t.Active != "", HotStandby: t.HotStandby, Auto: t.HSAuto, Failover: t.Failover}
			if v.Method == "" {
				v.Method = t.Selected
			}
			if v.Foreign == "" {
				v.Foreign = "panel host"
			}
			if h, ok := a.cachedHealth(t.ID); ok {
				v.Health = h
				if h == "" {
					v.Health = "ok"
				}
			} else {
				v.Health = "not checked yet"
			}
			if hv := a.hsViewOf(t.ID); hv != nil {
				for i, k := range hv.Keys {
					p := pathV{Key: k, Users: i == hv.Active}
					if i < len(hv.OK) {
						p.OK = hv.OK[i]
					}
					if i < len(hv.RTT) {
						p.RTTms = hv.RTT[i]
					}
					if i < len(hv.Loss) && hv.Loss[i] >= 0 {
						l := hv.Loss[i]
						p.LossPct = &l
					}
					if i < len(hv.Kbps) && hv.Kbps[i] > 0 {
						p.Mbps = float64(hv.Kbps[i]) / 1000
					}
					v.Paths = append(v.Paths, p)
				}
			}
			for _, p := range t.Paths {
				if p.Failed != "" {
					v.Paths = append(v.Paths, pathV{Key: p.Method + "|" + p.Family, Failed: aiRedact(clipTo(p.Failed, 160))})
				}
			}
			if ts := snap.Tunnels[t.ID]; ts != nil {
				v.DownMbps, v.UpMbps = ts.Down/1e6, ts.Up/1e6
			}
			tuns = append(tuns, v)
		}
		for _, o := range st.Outages {
			if o.Start >= since || o.End == 0 {
				o.Reason, o.Cause = aiRedact(o.Reason), aiRedact(clipTo(o.Cause, 300))
				outs = append(outs, o)
			}
		}
		// the newest benchmark of each route
		seen := map[string]bool{}
		for i := len(st.BenchHistory) - 1; i >= 0 && len(bench) < 12; i-- {
			b := st.BenchHistory[i]
			k := b.IranID + "|" + b.ForeignID + "|" + b.Family
			if seen[k] || b.At < since {
				continue
			}
			seen[k] = true
			var rs []map[string]any
			for _, r := range b.Results {
				if r.Skipped {
					continue
				}
				m := map[string]any{"method": r.Method, "ok": r.OK}
				if r.OK {
					m["rttMs"], m["downMbps"], m["upMbps"], m["score"] = r.RTTms, r.DownMbps, r.UpMbps, r.Score
					if r.LossKnown {
						m["lossPct"] = r.LossPct
					}
				} else {
					m["error"] = aiRedact(clipTo(r.Error, 120))
				}
				rs = append(rs, m)
			}
			bench = append(bench, map[string]any{"at": time.Unix(b.At, 0).UTC().Format(time.RFC3339), "iran": b.IranName, "foreign": b.ForeignName, "family": b.Family, "results": rs})
		}
	})
	sort.Slice(tuns, func(i, j int) bool { return tuns[i].Name < tuns[j].Name })
	aiAlerts.Lock()
	var alerts []aiAlert
	for _, al := range aiAlerts.l {
		alerts = append(alerts, aiAlert{al.At, aiRedact(al.Msg)})
	}
	aiAlerts.Unlock()
	return map[string]any{
		"now": time.Now().UTC().Format(time.RFC3339),
		"switcher": map[string]any{"checkEverySec": hsEvery, "failsToDown": hsFails, "graceSec": hsGrace, "backAfterStableSec": hsFailback,
			"holdAfterManualSec": hsHold, "autoFailoverAfter": failoverAfter.String(), "failoverRetry": failoverRetry.String()},
		"tunnels": tuns, "servers": srvs, "outagesLast7Days": outs, "recentAlerts": alerts, "benchmarks": bench,
	}
}

// ---- the call

const aiSystem = `You review a tunnel panel that connects servers in Iran to servers abroad (VPN traffic for
Iranian users). Iran filters and throttles: paths die, get lossy, or get cut a few seconds in by DPI.
Tunnels with hot standby run several paths ("method|family", e.g. "espsk|v4") at once; a switcher on
the Iran server moves users between them make-before-break. In manual mode users stay on the chosen
path until it is down; in auto mode they also move to a clearly faster or cleaner path.

You get a JSON snapshot. Find what hurts users most — outages, flapping, slow or lossy paths, a path
the users sit on while a clearly better one runs, overloaded servers (CPU, steal, softirq on one core,
conntrack near its max), failovers stuck on a backup, paths that never start — and say what to do.
Be concrete: name the tunnel, the server, the path, the numbers. Only claim what the data shows; say
when the data is too thin to tell. Do not invent settings the panel does not have.

Write all text in Persian (Farsi), short and plain, for an admin reading on a phone. Keep technical
names (method ids, server and tunnel names, numbers) as they are.

actions: only changes that cut nobody off, and only when the data clearly supports them:
- kind "switch_path": tunnel id + the key of one of its running paths that is ok now ("path"); moves
  the users there make-before-break. Not when the users' path is fine and the gain is small.
- kind "hs_mode": tunnel id + auto true/false for a hot-standby tunnel.
Leave actions empty when none is clearly worth it. Everything else goes into findings as advice.`

var aiSchema = json.RawMessage(`{
 "type": "object",
 "additionalProperties": false,
 "required": ["summary", "findings", "actions"],
 "properties": {
  "summary": {"type": "string"},
  "findings": {"type": "array", "items": {"type": "object", "additionalProperties": false,
   "required": ["severity", "title", "detail", "fix"],
   "properties": {"severity": {"type": "string", "enum": ["high", "medium", "low"]},
    "title": {"type": "string"}, "detail": {"type": "string"}, "fix": {"type": "string"}}}},
  "actions": {"type": "array", "items": {"type": "object", "additionalProperties": false,
   "required": ["kind", "tunnel", "path", "auto", "why"],
   "properties": {"kind": {"type": "string", "enum": ["switch_path", "hs_mode"]},
    "tunnel": {"type": "string"}, "path": {"type": "string"}, "auto": {"type": "boolean"}, "why": {"type": "string"}}}}
 }
}`)

var aiRun = struct {
	sync.Mutex
	running bool
}{}

// aiStart starts one analysis in the background (false: one is running already). It is
// marked running at once, so the page polling right after sees it.
func (a *App) aiStart() bool {
	aiRun.Lock()
	defer aiRun.Unlock()
	if aiRun.running {
		return false
	}
	aiRun.running = true
	go a.aiAnalyze()
	return true
}

// aiAnalyze runs one analysis and keeps its report (also when it fails, with the error).
func (a *App) aiAnalyze() {
	defer func() { aiRun.Lock(); aiRun.running = false; aiRun.Unlock() }()
	rep := &AIReport{At: time.Now().Unix()}
	if err := a.aiCall(rep); err != nil {
		rep.Error = err.Error()
	}
	_ = a.store.Update(func(st *State) error { st.AIReport = rep; return nil })
}

func (a *App) aiCall(rep *AIReport) error {
	key := strings.TrimSpace(a.settings().ClaudeKey)
	if key == "" {
		return errors.New("no Claude API key — set it in Settings")
	}
	body, _ := json.MarshalIndent(a.aiSnapshot(), "", " ")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	client := anthropic.NewClient(option.WithAPIKey(key))
	stream := client.Beta.Messages.NewStreaming(ctx, anthropic.BetaMessageNewParams{
		Model:     aiModel,
		MaxTokens: 32000,
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
		Fallbacks: anthropic.BetaFallbacksParamUnion{OfDefault: constant.ValueOf[constant.Default]()},
		System:    []anthropic.BetaTextBlockParam{{Text: aiSystem}},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Effort: anthropic.BetaOutputConfigEffortHigh,
			Format: anthropic.BetaJSONOutputFormatParam{Schema: aiSchema},
		},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock("Panel snapshot:\n" + string(body))),
		},
	})
	var msg anthropic.BetaMessage
	for stream.Next() {
		if err := msg.Accumulate(stream.Current()); err != nil {
			return err
		}
	}
	if err := stream.Err(); err != nil {
		var ae *anthropic.Error
		if errors.As(err, &ae) {
			switch ae.StatusCode {
			case 401, 403:
				return errors.New("Claude refused the API key (check it in Settings)")
			case 429:
				return errors.New("Claude rate limit — try again in a minute")
			}
			return fmt.Errorf("Claude API error %d", ae.StatusCode)
		}
		return fmt.Errorf("Claude API: %v", err)
	}
	switch msg.StopReason {
	case anthropic.BetaStopReasonRefusal:
		return errors.New("Claude declined this request")
	case anthropic.BetaStopReasonMaxTokens:
		return errors.New("the answer was cut off (too long) — try again")
	}
	var text strings.Builder
	for _, b := range msg.Content {
		if t, ok := b.AsAny().(anthropic.BetaTextBlock); ok {
			text.WriteString(t.Text)
		}
	}
	var out struct {
		Summary  string      `json:"summary"`
		Findings []AIFinding `json:"findings"`
		Actions  []AIAction  `json:"actions"`
	}
	if err := json.Unmarshal([]byte(text.String()), &out); err != nil {
		return fmt.Errorf("could not read Claude's answer: %v", err)
	}
	rep.Summary, rep.Findings = out.Summary, out.Findings
	for _, x := range out.Actions {
		if a.aiCheck(x) == nil { // only what the panel can really carry out
			rep.Actions = append(rep.Actions, x)
		}
	}
	return nil
}

// aiCheck: an action names a real hot-standby tunnel, and a switch a running, working path.
func (a *App) aiCheck(x AIAction) error {
	t := a.store.Tunnel(x.Tunnel)
	if t == nil {
		return errors.New("no such tunnel")
	}
	var hot, running bool
	a.store.View(func(*State) { hot, running = t.HotStandby, t.Active != "" && len(t.Paths) > 0 })
	if !hot || !running {
		return errors.New("the tunnel is not running hot standby")
	}
	switch x.Kind {
	case "hs_mode":
		return nil
	case "switch_path":
		v := a.hsViewOf(t.ID)
		if v == nil {
			return errors.New("the switcher's state is not known yet")
		}
		for i, k := range v.Keys {
			if k == x.Path {
				if i == v.Active {
					return errors.New("the users already are on it")
				}
				if i >= len(v.OK) || !v.OK[i] {
					return errors.New("that path doesn't answer now")
				}
				return nil
			}
		}
		return errors.New("not a running path of this tunnel")
	}
	return errors.New("unknown action")
}

// aiApply carries out action i of the last report.
func (a *App) aiApply(i int) (string, error) {
	var x AIAction
	var ok bool
	a.store.View(func(st *State) {
		if st.AIReport != nil && i >= 0 && i < len(st.AIReport.Actions) {
			x, ok = st.AIReport.Actions[i], true
		}
	})
	if !ok {
		return "", errors.New("no such action")
	}
	if err := a.aiCheck(x); err != nil {
		return "", err
	}
	t := a.store.Tunnel(x.Tunnel)
	var res string
	switch x.Kind {
	case "hs_mode":
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		r, err := a.setHSMode(ctx, t, x.Auto)
		if err != nil {
			return "", err
		}
		res = r
	case "switch_path":
		mid, fam, _ := strings.Cut(x.Path, "|")
		if _, err := a.hsSwitchJob(t, mid, fam); err != nil {
			return "", err
		}
		res = "users are being moved to " + x.Path
	}
	_ = a.store.Update(func(st *State) error {
		if st.AIReport != nil && i < len(st.AIReport.Actions) {
			st.AIReport.Actions[i].Applied, st.AIReport.Actions[i].Result = time.Now().Unix(), res
		}
		return nil
	})
	return res, nil
}

// ---- HTTP

func (s *Server2) aiGet(w http.ResponseWriter, r *http.Request) {
	var rep *AIReport
	s.app.store.View(func(st *State) {
		if st.AIReport != nil {
			cp := *st.AIReport
			cp.Actions = append([]AIAction(nil), st.AIReport.Actions...)
			rep = &cp
		}
	})
	aiRun.Lock()
	running := aiRun.running
	aiRun.Unlock()
	writeJSON(w, map[string]any{"report": rep, "running": running, "hasKey": strings.TrimSpace(s.app.settings().ClaudeKey) != ""})
}

func (s *Server2) aiRunH(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.app.settings().ClaudeKey) == "" {
		httpErr(w, 400, "Set the Claude API key in Settings first")
		return
	}
	s.app.aiStart()
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server2) aiApplyH(w http.ResponseWriter, r *http.Request) {
	var in struct{ I int }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	res, err := s.app.aiApply(in.I)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]string{"result": res})
}
