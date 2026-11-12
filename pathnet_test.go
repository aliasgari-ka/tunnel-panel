package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// pnHost is optHost (both servers and the switcher) that also answers the live
// kernel-settings script and keeps every script run.
type pnHost struct {
	*optHost
	rmu  sync.Mutex
	runs []string
}

func (h *pnHost) Label() string { return "pn" }
func (h *pnHost) WriteFile(p string, b []byte, m os.FileMode) error {
	h.rmu.Lock()
	h.runs = append(h.runs, "WRITE "+p+"\n"+string(b))
	h.rmu.Unlock()
	return h.optHost.WriteFile(p, b, m)
}
func (h *pnHost) Run(ctx context.Context, s string, log func(string)) (string, error) {
	h.rmu.Lock()
	h.runs = append(h.runs, s)
	h.rmu.Unlock()
	if strings.Contains(s, "echo TP-NET-DONE") {
		return "net tp1: mtu 1476\nTP-NET-DONE\n", nil
	}
	return h.optHost.Run(ctx, s, log)
}

func (h *pnHost) all() string {
	h.rmu.Lock()
	defer h.rmu.Unlock()
	return strings.Join(h.runs, "\n----\n")
}

func pnSetup(t *testing.T, ok func(string, string) bool) (*App, *Tunnel, *pnHost) {
	t.Helper()
	a, tn, h := optSetup(t, ok)
	p := &pnHost{optHost: h}
	a.hostFor = func(*Server) Host { return p }
	return a, tn, p
}

func pnDone(t *testing.T, a *App, res map[string]string) (*Job, string) {
	t.Helper()
	if res["job"] == "" {
		t.Fatalf("no job: %v", res)
	}
	j := optDone(t, a, res["job"])
	return j, strings.Join(j.Lines, "\n")
}

// The users' path: they move to the other working path, the interface changes live on both
// servers (nothing restarts, nothing is torn down), they come back; the other path is untouched.
func TestPathNetUsersMovedOffAndBack(t *testing.T) {
	defer func(d time.Duration) { optWaitUp = d }(optWaitUp)
	optWaitUp = 2 * time.Second
	a, tn, h := pnSetup(t, func(string, string) bool { return true })
	res, code, err := a.SavePathNet(tn, "gre|v4", map[string]string{"mss": "۱۳۰۰", "qdisc": "fq", "txqlen": "2000"}, false)
	if err != nil || code != 200 {
		t.Fatalf("save: %v %d %v", res, code, err)
	}
	j, log := pnDone(t, a, res)
	if j.Status != "ok" || !strings.Contains(log, "DONE") {
		t.Fatalf("status %s:\n%s", j.Status, log)
	}
	if len(h.pins) != 2 || h.pins[0] != "wg|v4" || h.pins[1] != "gre|v4" {
		t.Fatalf("users not moved off and back: pins %v\n%s", h.pins, log)
	}
	if tn.HSPin != "" {
		t.Fatalf("the users' choice changed: %q", tn.HSPin)
	}
	if h.deploy != 0 || h.tears != 0 {
		t.Fatalf("restarted/torn down: deploys %d teardowns %d", h.deploy, h.tears)
	}
	all := h.all()
	if !strings.Contains(all, "--set-mss 1300") || !strings.Contains(all, "-o tp1") {
		t.Fatalf("MSS rule not swapped in the switcher chain:\n%s", all)
	}
	if !strings.Contains(h.cfg[1], "tc qdisc replace dev $IF root fq") || !strings.Contains(h.cfg[1], "txqueuelen 2000") {
		t.Fatalf("net.sh not written for the path: %q", h.cfg[1])
	}
	if !strings.Contains(all, "ExecStartPost=-/etc/tunnel-panel/t/aaaaaaaaaaaax1/net.sh start") {
		t.Fatalf("no drop-in that keeps it after a restart:\n%s", all)
	}
	if h.cfg[2] != "" || strings.Contains(all, "tp2") {
		t.Fatalf("the other path was touched: %q", h.cfg[2])
	}
	if n := tn.PathNet["gre|v4"]; n.MSS != 1300 || n.Qdisc != "fq" || n.TxQLen != 2000 {
		t.Fatalf("stored %+v", n)
	}
}

// A path the users aren't on: changed without moving anybody.
func TestPathNetStandbyPathNoMove(t *testing.T) {
	defer func(d time.Duration) { optWaitUp = d }(optWaitUp)
	optWaitUp = 2 * time.Second
	a, tn, h := pnSetup(t, func(string, string) bool { return true })
	res, _, err := a.SavePathNet(tn, "wg|v4", map[string]string{"qdisc": "cake"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if j, log := pnDone(t, a, res); j.Status != "ok" {
		t.Fatalf("%s\n%s", j.Status, log)
	}
	if len(h.pins) != 0 {
		t.Fatalf("users moved for a standby path: %v", h.pins)
	}
	if h.cfg[1] != "" {
		t.Fatalf("the users' path was touched: %q", h.cfg[1])
	}
}

// Settings the path doesn't answer with: kept as set, the job says FAILING, users stay on
// the working path. ↺ Defaults puts the interface back and removes the drop-in.
func TestPathNetKeptWhenFailingAndReset(t *testing.T) {
	defer func(d time.Duration) { optWaitUp = d }(optWaitUp)
	optWaitUp = 300 * time.Millisecond
	a, tn, h := pnSetup(t, func(key, cfg string) bool { return key != "gre|v4" || !strings.Contains(cfg, "txqueuelen 20 ") })
	res, _, err := a.SavePathNet(tn, "gre|v4", map[string]string{"txqlen": "20"}, false)
	if err != nil {
		t.Fatal(err)
	}
	j, log := pnDone(t, a, res)
	if j.Status != "error" || !strings.Contains(log, "FAILING") || !strings.Contains(log, "kept as you set them") {
		t.Fatalf("want FAILING, got %s:\n%s", j.Status, log)
	}
	if tn.PathNet["gre|v4"].TxQLen != 20 {
		t.Fatalf("not kept: %+v", tn.PathNet)
	}
	if h.active != 1 {
		t.Fatalf("users not kept on the working path: active %d", h.active)
	}
	h.cfg[1] = ""
	res, _, err = a.SavePathNet(tn, "gre|v4", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	pnDone(t, a, res)
	all := h.all()
	if !strings.Contains(all, "read om oq") || !strings.Contains(all, "rm -f /etc/systemd/system/tp-aaaaaaaaaaaax1.service.d/50-tp-net.conf") {
		t.Fatalf("Defaults didn't put the interface back:\n%s", all)
	}
	if tn.PathNet != nil {
		t.Fatalf("Defaults kept settings: %+v", tn.PathNet)
	}
}

// The settings are in the path's unit plans and the switcher's MSS rule: a rebuild, Repair
// or a reboot keeps them.
func TestPathNetInUnitAndSwitcher(t *testing.T) {
	a, tn, _ := pnSetup(t, func(string, string) bool { return true })
	_ = a.store.Update(func(*State) error { tn.setPathNet("gre|v4", PathNet{MSS: 1200, Qdisc: "fq_codel"}); return nil })
	pt := pathTunnel(tn, tn.Paths[0])
	ir, kh, err := a.build(methodByID["gre"], pt, a.store.Server("ir1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []SidePlan{ir, kh} {
		sh, drop := p.Files[pathNetSh(pt)], p.Files[pathNetDropIn(pt)]
		if !strings.Contains(string(sh.Content), "root fq_codel") || !strings.Contains(string(drop.Content), "net.sh start") {
			t.Fatalf("plan without the path's settings: %v", p.Files)
		}
	}
	// the other path's plan carries nothing
	ir2, _, _ := a.build(methodByID["wg"], pathTunnel(tn, tn.Paths[1]), a.store.Server("ir1"))
	for k := range ir2.Files {
		if strings.Contains(k, "net.sh") || strings.Contains(k, "50-tp-net") {
			t.Fatalf("other path got settings: %s", k)
		}
	}
	base := hsBase(tn, tn.Paths)
	if !strings.Contains(base, "-o tp1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200") || !strings.Contains(base, "-o tp2 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu") {
		t.Fatalf("switcher MSS rules:\n%s", base)
	}
}

// Checked before anything is stored; Persian digits are numbers.
func TestPathNetValidation(t *testing.T) {
	a, tn, h := pnSetup(t, func(string, string) bool { return true })
	bad := []map[string]string{
		{"mtu": "1400"}, // GRE sets its MTU in its own options
		{"mss": "100"},
		{"txqlen": "abc"},
		{"qdisc": "nope"},
	}
	for _, in := range bad {
		if _, code, err := a.SavePathNet(tn, "gre|v4", in, false); err == nil || code != 400 {
			t.Fatalf("%v accepted: %d", in, code)
		}
	}
	if _, code, err := a.SavePathNet(tn, "frp|v4", map[string]string{"qdisc": "fq"}, false); err == nil || code == 200 {
		t.Fatalf("a path that isn't on the tunnel accepted: %d", code)
	}
	if tn.PathNet != nil || h.deploy != 0 || len(h.all()) != 0 {
		t.Fatalf("a refused value changed something: %+v", tn.PathNet)
	}
	if n, err := parsePathNet(map[string]string{"mtu": "۱۴۰۰", "mss": "1360"}, "v4", false); err != nil || n.MTU != 1400 || n.MSS != 1360 {
		t.Fatalf("Persian digits: %+v %v", n, err)
	}
	if _, err := parsePathNet(map[string]string{"mtu": "1400", "mss": "1380"}, "v4", false); err == nil {
		t.Fatal("MSS bigger than MTU-40 accepted")
	}
	if _, err := parsePathNet(map[string]string{"mtu": "1000"}, "v6", false); err == nil {
		t.Fatal("IPv6 MTU under 1280 accepted")
	}
	// a path that forwards in user space has no interface: refused with where to look instead
	_ = a.store.Update(func(*State) error {
		tn.Paths = append(tn.Paths, HSPath{Method: "frp", Family: "v4", Index: 3})
		return nil
	})
	if _, code, err := a.SavePathNet(tn, "frp|v4", map[string]string{"qdisc": "fq"}, false); code != 400 || err == nil || !strings.Contains(err.Error(), "Optimize") {
		t.Fatalf("user-space path: %d %v", code, err)
	}
	// unchanged: nothing starts
	if res, _, _ := a.SavePathNet(tn, "gre|v4", map[string]string{}, false); res["job"] != "" {
		t.Fatalf("unchanged settings started a job")
	}
}

// Method options from a path row: when the users' path would restart and no other path
// answers, nothing is saved until the user confirms.
func TestOptionsAskWhenNoOtherPath(t *testing.T) {
	defer func(d time.Duration) { optWaitUp = d }(optWaitUp)
	optWaitUp = 300 * time.Millisecond
	a, tn, _ := pnSetup(t, func(key, _ string) bool { return key == "gre|v4" })
	a.hsViews[tn.ID] = &hsView{Active: 0, Keys: []string{"gre|v4", "wg|v4"}, OK: []bool{true, false}, RTT: []int{40, -1}}
	res, _, err := a.SaveOptionsAsk(tn, "gre", map[string]string{"mtu": "1400"}, false, false)
	if err != nil || res["confirm"] == "" || res["job"] != "" || tn.Options["gre"]["mtu"] != "1436" {
		t.Fatalf("want a question, nothing saved: %v %v %v", res, err, tn.Options)
	}
	res, _, err = a.SaveOptionsAsk(tn, "gre", map[string]string{"mtu": "۱۴۰۰"}, false, true)
	if err != nil || res["job"] == "" || tn.Options["gre"]["mtu"] != "1400" {
		t.Fatalf("confirmed: %v %v %v", res, err, tn.Options)
	}
	optDone(t, a, res["job"])
	// another path answers: no question
	a.hsViews[tn.ID] = &hsView{Active: 0, Keys: []string{"gre|v4", "wg|v4"}, OK: []bool{true, true}, RTT: []int{40, 50}}
	if res, _, _ := a.SaveOptionsAsk(tn, "gre", map[string]string{"mtu": "1420"}, false, false); res["confirm"] != "" {
		t.Fatalf("asked with another working path: %v", res)
	}
}

func TestHSBestOther(t *testing.T) {
	v := &hsView{Keys: []string{"a|v4", "b|v4", "c|v4", "d|v4"}, OK: []bool{true, true, false, true}, RTT: []int{30, 90, 10, 60}}
	if got := hsBestOther(v, map[string]bool{"a|v4": true}); got != "d|v4" {
		t.Fatalf("got %q", got)
	}
	if got := hsBestOther(v, map[string]bool{"a|v4": true, "b|v4": true, "d|v4": true}); got != "" {
		t.Fatalf("got %q", got)
	}
}

// Another account can't read or change a path's settings.
func TestPathNetAccess(t *testing.T) {
	a, tn, _ := pnSetup(t, func(string, string) bool { return true })
	hash, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = a.store.Update(func(st *State) error {
		tn.Owner = "boss"
		st.Users = []User{{Username: "admin", Hash: string(hash)}, {Username: "ali", Hash: string(hash), Role: roleUser}, {Username: "boss", Hash: string(hash), Role: roleUser}}
		return nil
	})
	a.agents = newAgentHub()
	s := &Server2{app: a, failures: map[string][]time.Time{}}
	cookie := func(user string) *http.Cookie {
		w := httptest.NewRecorder()
		s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"`+user+`","password":"password1"}`)))
		for _, k := range w.Result().Cookies() {
			if k.Name == "tp_session" {
				return k
			}
		}
		t.Fatal("no session")
		return nil
	}
	ali := cookie("ali")
	for _, h := range []http.HandlerFunc{s.tunnelPathNet, s.tunnelPathNetInfo} {
		r := httptest.NewRequest("POST", "/api/tunnels/pathnet", strings.NewReader(`{"ID":"aaaaaaaaaaaa","Path":"gre|v4","Net":{"qdisc":"fq"}}`))
		r.AddCookie(ali)
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code == http.StatusOK || tn.PathNet != nil {
			t.Fatalf("another account got through: %d %s", w.Code, w.Body.String())
		}
	}
	// the owner can
	r := httptest.NewRequest("POST", "/api/tunnels/pathnet", strings.NewReader(`{"ID":"aaaaaaaaaaaa","Path":"wg|v4","Net":{"qdisc":"fq"}}`))
	r.AddCookie(cookie("boss"))
	w := httptest.NewRecorder()
	s.tunnelPathNet(w, r)
	if w.Code != http.StatusOK || tn.PathNet["wg|v4"].Qdisc != "fq" {
		t.Fatalf("the owner couldn't: %d %s", w.Code, w.Body.String())
	}
	if id := a.jobs.running(tn.ID); id != "" {
		optDone(t, a, id)
	}
}
