package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake Telegram API: records every call, answers ok.
type fakeTG struct {
	mu    sync.Mutex
	calls []url.Values
	names []string
}

func (f *fakeTG) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.calls = append(f.calls, r.PostForm)
	f.names = append(f.names, r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
	n := len(f.calls)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":` + string(rune('0'+n%10)) + `}}`))
}

func TestBotFlows(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir1", Name: "ir-xe101", IPv4: "192.0.2.1", IPv6: "2001:db8::1", Country: "IR"}, {ID: "kh1", Name: "germany", IPv4: "198.51.100.1", IPv6: "2001:db8::2", Role: "foreign", Country: "DE"}}
		s.Tunnels = []*Tunnel{
			{ID: "aaaaaaaaaaaa", Name: "tehran-de", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443", Index: 1, Active: "bp_reverse", Selected: "bp_reverse",
				Failover: &FailoverState{Method: "gre", Family: "v6", Reason: "tunnel link down"}},
			{ID: "bbbbbbbbbbbb", Name: "tehran-backup", ServerID: "ir1", ForeignID: "kh1", Family: "v6", Ports: "8443", Index: 2, Selected: "gre"},
		}
		s.BenchHistory = []BenchRecord{{ID: "h1", At: time.Now().Unix(), IranID: "ir1", IranName: "ir-xe101", ForeignID: "kh1", ForeignName: "germany", Family: "v4",
			Results: []BenchResult{{Method: "bp_reverse", Title: "BackPack reverse", OK: true, Recommended: true, DownMbps: 125, UpMbps: 122, RTTms: 159}}}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}, healthCache: map[string]string{"aaaaaaaaaaaa": ""}}
	f := &fakeTG{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	b := newBot(a, "TOKEN", "42")
	b.base = srv.URL

	b.onText("42", "/menu")
	b.onCallback("42", 7, "cb", "t:aaaaaaaaaaaa")
	b.onCallback("42", 7, "cb", "m:aaaaaaaaaaaa")
	b.onCallback("42", 7, "cb", "m:aaaaaaaaaaaa:v6")
	b.onCallback("42", 7, "cb", "a:bbbbbbbbbbbb:golden:v6") // Golden is IPv4 only → refused, family unchanged
	b.onCallback("42", 7, "cb", "sq:aaaaaaaaaaaa")
	b.onCallback("42", 7, "cb", "t:bbbbbbbbbbbb")
	b.onCallback("42", 7, "cb", "home:bh")
	b.onCallback("42", 7, "cb", "home")
	b.onCallback("42", 7, "cb", "t:zzzzzzzzzzzz") // deleted tunnel
	b.onText("99", "/menu")                       // not an admin

	f.mu.Lock()
	defer f.mu.Unlock()
	var all strings.Builder
	for i, c := range f.calls {
		txt := c.Get("text")
		if len(txt) > 4096 {
			t.Errorf("%s: text too long (%d)", f.names[i], len(txt))
		}
		all.WriteString(f.names[i] + ": " + txt + "\n")
		if mk := c.Get("reply_markup"); mk != "" {
			var m struct {
				Inline [][]ikey `json:"inline_keyboard"`
			}
			if err := json.Unmarshal([]byte(mk), &m); err != nil {
				t.Errorf("bad markup: %v", err)
			}
			for _, row := range m.Inline {
				for _, k := range row {
					if len(k.Data) > 64 || k.Data == "" {
						t.Errorf("callback_data %q invalid (len %d)", k.Data, len(k.Data))
					}
					all.WriteString("   [" + k.Text + "]\n")
				}
			}
		}
	}
	out := all.String()
	for _, want := range []string{"▶ 1/2 running", "🔁 1 on backup", "★ BackPack reverse", "L3 tunnels", "Yes, stop it", "Benchmark history", "Not authorized", "no longer exists",
		"● IPv4", "○ IPv6", "● IPv6", "Golden-GRE", "Direct v6", "does not work over IPv6"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in bot output", want)
		}
	}
	if f := st.Tunnel("bbbbbbbbbbbb").Family; f != "v6" {
		t.Errorf("a refused apply changed the family to %s", f)
	}
	if testing.Verbose() {
		t.Log("\n" + out)
	}
}

func TestBotOptions(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir1", Name: "ir", IPv4: "192.0.2.1"}, {ID: "kh1", Name: "de", IPv4: "198.51.100.1", Role: "foreign"}}
		s.Tunnels = []*Tunnel{
			{ID: "aaaaaaaaaaaa", Name: "bh", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443", Index: 1, Active: "backhaul", Selected: "backhaul", Options: map[string]map[string]string{}},
			{ID: "cccccccccccc", Name: "other", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "8443", Index: 2, Active: "gre", Options: map[string]map[string]string{}},
		}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}, healthCache: map[string]string{}}
	f := &fakeTG{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	b := newBot(a, "TOKEN", "42")
	b.base = srv.URL
	opt := func(k string) string { return st.Tunnel("aaaaaaaaaaaa").Options["backhaul"][k] }
	idx := func(k string) int {
		for i, f := range methodBackhaul.Fields {
			if f.Key == k {
				return i
			}
		}
		return -1
	}
	b.onCallback("42", 7, "cb", "o:aaaaaaaaaaaa")
	b.onCallback("42", 7, "cb", fmt.Sprintf("of:aaaaaaaaaaaa:backhaul:%d", idx("transport")))
	b.onCallback("42", 7, "cb", fmt.Sprintf("ov:aaaaaaaaaaaa:backhaul:%d:%d", idx("transport"), 2)) // ws
	if opt("transport") != "ws" {
		t.Errorf("transport = %q, want ws", opt("transport"))
	}
	b.onCallback("42", 7, "cb", fmt.Sprintf("of:aaaaaaaaaaaa:backhaul:%d", idx("sniffer"))) // bool toggles
	if opt("sniffer") != "true" {
		t.Errorf("sniffer = %q", opt("sniffer"))
	}
	b.onCallback("42", 7, "cb", fmt.Sprintf("of:aaaaaaaaaaaa:backhaul:%d", idx("tunnel_port")))
	b.onText("42", "8443") // another tunnel forwards 8443 on this Iran server → refused
	if opt("tunnel_port") != "" {
		t.Errorf("clashing port saved: %q", opt("tunnel_port"))
	}
	b.onCallback("42", 7, "cb", fmt.Sprintf("of:aaaaaaaaaaaa:backhaul:%d", idx("tunnel_port")))
	b.onText("42", "2096")
	if opt("tunnel_port") != "2096" {
		t.Errorf("tunnel_port = %q", opt("tunnel_port"))
	}
	b.onCallback("42", 7, "cb", fmt.Sprintf("of:aaaaaaaaaaaa:backhaul:%d", idx("mux_con")))
	b.onText("42", "lots") // not a number
	b.onCallback("42", 7, "cb", fmt.Sprintf("of:aaaaaaaaaaaa:backhaul:%d", idx("tunnel_port")))
	b.onText("42", "-") // back to the default
	if v, ok := st.Tunnel("aaaaaaaaaaaa").Options["backhaul"]["tunnel_port"]; !ok || v != "" {
		t.Errorf("reset: %q %v", v, ok)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var all strings.Builder
	for _, c := range f.calls {
		all.WriteString(c.Get("text") + c.Get("reply_markup") + "\n")
	}
	out := all.String()
	for _, want := range []string{"Backhaul (reverse) settings", "Transport: tcpmux", "● tcpmux", "Send the new value for", "already used by tunnel", "must be a number", "✅ saved", "Apply changes"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}
