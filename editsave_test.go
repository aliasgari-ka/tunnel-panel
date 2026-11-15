package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// editServer is a panel with two Iran and one foreign server, tunnels tns, every host lcHost
// (teardowns answer, file writes fail), logged in as the admin.
func editServer(t *testing.T, tns ...*Tunnel) (*Server2, func(body string) (int, map[string]string)) {
	t.Helper()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}}
		s.Servers = []*Server{
			{ID: "s1", Name: "iran", IPv4: "192.0.2.1", IPv6: "2001:db8::1", Role: "iran"},
			{ID: "s3", Name: "iran2", IPv4: "192.0.2.3", Role: "iran"},
			{ID: "s2", Name: "de", IPv4: "198.51.100.2", IPv6: "2001:db8::2", Role: "foreign"},
		}
		for _, tn := range tns {
			if tn.Options == nil {
				tn.Options = map[string]map[string]string{}
			}
			if tn.Secrets == nil {
				tn.Secrets = map[string]string{}
			}
		}
		s.Tunnels = tns
		return nil
	})
	host := &lcHost{}
	a := &App{store: st, jobs: newJobs(), agents: newAgentHub(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}, hsViews: map[string]*hsView{}}
	a.notify = func(string) {}
	a.hostFor = func(*Server) Host { return host }
	s := &Server2{app: a, failures: map[string][]time.Time{}}
	lw := httptest.NewRecorder()
	s.login(lw, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"boss","password":"password1"}`)))
	save := func(body string) (int, map[string]string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/tunnels/save", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		for _, c := range lw.Result().Cookies() {
			r.AddCookie(c)
		}
		s.tunnelSave(w, r)
		var out map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != 200 {
			out = map[string]string{"error": w.Body.String()}
		}
		return w.Code, out
	}
	return s, save
}

// Seen live: a running tunnel with "Keep users connected" whose users the switcher had moved
// to an IPv6 path; the edit form (opened on IPv4) changed only the port and Save answered
// "Stop the tunnel before changing its servers or address family."
func TestEditPortHotStandbyFamilyMoved(t *testing.T) {
	tn := &Tunnel{ID: "t1", Name: "finland", ServerID: "s1", ForeignID: "s2", Family: "v6", Ports: "443", Index: 1,
		Active: "gre", Selected: "gre", HotStandby: true, HSAuto: true, Paths: []HSPath{
			{Method: "gre", Family: "v4", Index: 1}, {Method: "gre", Family: "v6", Index: 2}}}
	s, save := editServer(t, tn)
	code, out := save(`{"ID":"t1","name":"finland","serverId":"s1","foreignId":"s2","family":"v4","ports":"8443","hotStandby":true,"hsAuto":true}`)
	if code != 200 {
		t.Fatalf("port edit refused: %v", out)
	}
	var fam, ports, srv string
	s.app.store.View(func(*State) { fam, ports, srv = tn.Family, tn.Ports, tn.ServerID })
	if fam != "v6" || ports != "8443" || srv != "s1" {
		t.Errorf("after save: family %s ports %s server %s", fam, ports, srv)
	}
	if out["job"] == "" {
		t.Fatalf("a running tunnel's new port wasn't applied: %v", out)
	}
	j := s.app.jobs.get(out["job"])
	if j.Kind != "ports" {
		t.Errorf("job kind %q, want ports", j.Kind)
	}
	waitJob(t, j)
	// a family left out (or the same) changes nothing either
	if code, out := save(`{"ID":"t1","name":"finland2","serverId":"s1","foreignId":"s2","ports":"8443","hotStandby":true,"hsAuto":true}`); code != 200 || out["job"] != "" {
		t.Errorf("rename: %d %v", code, out)
	}
}

// A port change rebuilds only the paths whose own files use the port: an L3 path (GRE) keeps
// running (only the switcher's rules change), a forwarder (FRP) is rebuilt.
func TestEditPortPlanOnlyChangedPaths(t *testing.T) {
	tn := &Tunnel{ID: "t1", Name: "x", ServerID: "s1", ForeignID: "s2", Family: "v4", Ports: "443", Index: 1,
		Active: "gre", Selected: "gre", HotStandby: true, Paths: []HSPath{
			{Method: "gre", Family: "v4", Index: 1}, {Method: "frp", Family: "v4", Index: 2}}}
	s, _ := editServer(t, tn)
	before := *tn
	after := *tn
	after.Ports = "8443"
	plan := s.app.editPortPlan(&before, &after)
	if len(plan["gre"]) != 0 {
		t.Errorf("GRE path rebuilt for a port change: %v", plan)
	}
	if len(plan["frp"]) != 1 {
		t.Errorf("FRP path not rebuilt for a port change: %v", plan)
	}
	if p := s.app.editPortPlan(&before, &before); len(p) != 0 {
		t.Errorf("no change, still a plan: %v", p)
	}
	// the switcher's rules follow the new listening port
	good := hsGood(&before)
	if a, b := s.app.hsSwitcherPlan(&before, good), s.app.hsSwitcherPlan(&after, good); jsonEq(a.Files, b.Files) {
		t.Error("switcher files equal after a port change")
	}
}

func jsonEq(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// Without hot standby a port change re-applies the one method; another family switches it.
func TestEditPlainPortAndFamily(t *testing.T) {
	tn := &Tunnel{ID: "t1", Name: "plain", ServerID: "s1", ForeignID: "s2", Family: "v4", Ports: "443", Index: 1, Active: "gre", Selected: "gre"}
	s, save := editServer(t, tn)
	_, out := save(`{"ID":"t1","name":"plain","serverId":"s1","foreignId":"s2","family":"v4","ports":"8443"}`)
	j := s.app.jobs.get(out["job"])
	if j == nil || j.Kind != "apply:gre" {
		t.Fatalf("port change on a plain tunnel: %v %+v", out, j)
	}
	waitJob(t, j)
	_ = s.app.store.Update(func(*State) error { tn.Active = "gre"; return nil }) // the test host fails every deploy
	code, out := save(`{"ID":"t1","name":"plain","serverId":"s1","foreignId":"s2","family":"v6","ports":"8443"}`)
	if code != 200 || out["job"] == "" {
		t.Fatalf("family change on a running tunnel: %d %v", code, out)
	}
	j = s.app.jobs.get(out["job"])
	if j.Kind != "apply:gre" {
		t.Errorf("family change job %q", j.Kind)
	}
	var fam string
	s.app.store.View(func(*State) { fam = tn.Family })
	if fam != "v6" {
		t.Errorf("family %s after switching to IPv6", fam)
	}
	waitJob(t, j)
}

// Other servers for a running tunnel: stopped on the old ones, then started on the new — the
// servers are written only after the stop (it tears down where the tunnel ran).
func TestEditServersMovesRunningTunnel(t *testing.T) {
	tn := &Tunnel{ID: "t1", Name: "m", ServerID: "s1", ForeignID: "s2", Family: "v6", Ports: "443", Index: 1, Active: "gre", Selected: "gre"}
	s, save := editServer(t, tn)
	code, out := save(`{"ID":"t1","name":"m","serverId":"s3","foreignId":"s2","family":"v6","ports":"443"}`)
	if code != 200 || out["job"] == "" {
		t.Fatalf("server change on a running tunnel: %d %v", code, out)
	}
	j := s.app.jobs.get(out["job"])
	if j.Kind != "move" || j.Tunnel != "t1" {
		t.Fatalf("job %+v", j)
	}
	waitJob(t, j)
	var srv, fam string
	s.app.store.View(func(*State) { srv, fam = tn.ServerID, tn.Family })
	if srv != "s3" {
		t.Errorf("server %s after the move", srv)
	}
	if fam != "v4" { // s3 has no IPv6: the move starts it over IPv4
		t.Errorf("family %s on a route without IPv6", fam)
	}
	log := strings.Join(j.snapshot().Lines, "\n")
	if !strings.Contains(log, "1/2 stopping") || !strings.Contains(log, "2/2 starting") || !strings.Contains(log, "stopped") {
		t.Errorf("move log:\n%s", log)
	}
	if s.app.jobs.running(moveJobKey+"t1") != "" {
		t.Error("move slot still busy")
	}
	// a stopped tunnel just stores other servers
	_ = s.app.store.Update(func(*State) error { tn.Active = ""; return nil })
	if code, out := save(`{"ID":"t1","name":"m","serverId":"s1","foreignId":"s2","family":"v4","ports":"443"}`); code != 200 || out["job"] != "" {
		t.Errorf("stopped tunnel: %d %v", code, out)
	}
}
