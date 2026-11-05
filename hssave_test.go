package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Switching "Keep users connected" on a running tunnel used to save only the flag: the
// tunnel showed hot standby but ran one path (seen live on Xe107). Saving now rebuilds it.
func TestSaveHotStandbyRebuilds(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}}
		s.Servers = []*Server{
			{ID: "s1", Name: "iran", IPv4: "192.0.2.1", Role: "iran"},
			{ID: "s2", Name: "de", IPv4: "198.51.100.2", Role: "foreign"},
		}
		s.Tunnels = []*Tunnel{
			{ID: "t1", Name: "plain", ServerID: "s1", ForeignID: "s2", Family: "v4", Ports: "443", Index: 1, Active: "gre", Selected: "gre"},
			{ID: "t2", Name: "stopped", ServerID: "s1", ForeignID: "s2", Family: "v4", Ports: "8443", Index: 2},
		}
		return nil
	})
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub()}, failures: map[string][]time.Time{}}
	lw := httptest.NewRecorder()
	s.login(lw, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"boss","password":"password1"}`)))
	save := func(body string) map[string]string {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/tunnels/save", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		for _, c := range lw.Result().Cookies() {
			r.AddCookie(c)
		}
		s.tunnelSave(w, r)
		if w.Code != 200 {
			t.Fatalf("save: %d %s", w.Code, w.Body.String())
		}
		var out map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}

	// a stopped tunnel only stores the switch
	if out := save(`{"ID":"t2","name":"stopped","serverId":"s1","foreignId":"s2","family":"v4","ports":"8443","hotStandby":true}`); out["job"] != "" || out["warn"] != "" {
		t.Errorf("stopped tunnel was rebuilt: %v", out)
	}
	// renaming a running tunnel without touching the switch rebuilds nothing
	if out := save(`{"ID":"t1","name":"renamed","serverId":"s1","foreignId":"s2","family":"v4","ports":"443"}`); out["job"] != "" {
		t.Errorf("rename rebuilt the tunnel: %v", out)
	}
	// switching it on for a running tunnel re-applies its method
	out := save(`{"ID":"t1","name":"renamed","serverId":"s1","foreignId":"s2","family":"v4","ports":"443","hotStandby":true}`)
	if out["job"] == "" {
		t.Fatalf("switching hot standby on started no job: %v", out)
	}
	j := s.app.jobs.get(out["job"])
	if j == nil || j.Kind != "apply:gre" || j.Tunnel != "t1" {
		t.Fatalf("job: %+v", j)
	}
	_, _ = s.app.jobs.cancel(j.ID)
}
