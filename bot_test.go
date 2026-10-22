package main

import (
	"encoding/json"
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
		s.Servers = []*Server{{ID: "ir1", Name: "ir-xe101", IPv4: "192.0.2.1", Country: "IR"}, {ID: "kh1", Name: "germany", IPv4: "198.51.100.1", Role: "foreign", Country: "DE"}}
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
	for _, want := range []string{"▶ 1/2 running", "🔁 1 on backup", "★ BackPack reverse", "L3 tunnels", "Yes, stop it", "Benchmark history", "Not authorized", "no longer exists"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in bot output", want)
		}
	}
	if testing.Verbose() {
		t.Log("\n" + out)
	}
}
