package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// downHost is a server that can't be reached (every command fails at once).
type downHost struct{}

func (downHost) Label() string { return "down" }
func (downHost) Run(context.Context, string, func(string)) (string, error) {
	return "", errors.New("unreachable (test)")
}
func (downHost) WriteFile(string, []byte, os.FileMode) error { return errors.New("unreachable (test)") }

var tgTag = regexp.MustCompile(`</?([a-zA-Z0-9-]+)[^>]*>`)

// tgHTML reports what Telegram's HTML parse mode would reject: unknown tags, unclosed or
// crossed tags, and a stray < or & that isn't an entity.
func tgHTML(s string) string {
	allowed := map[string]bool{"b": true, "strong": true, "i": true, "em": true, "u": true, "ins": true, "s": true, "strike": true, "del": true,
		"code": true, "pre": true, "a": true, "tg-spoiler": true, "blockquote": true, "span": true}
	var stack []string
	for _, m := range tgTag.FindAllStringSubmatch(s, -1) {
		name := strings.ToLower(m[1])
		if !allowed[name] {
			return "tag <" + name + "> not allowed"
		}
		if strings.HasPrefix(m[0], "</") {
			if len(stack) == 0 || stack[len(stack)-1] != name {
				return "closing </" + name + "> without its opening tag"
			}
			stack = stack[:len(stack)-1]
		} else {
			stack = append(stack, name)
		}
	}
	if len(stack) > 0 {
		return "unclosed <" + stack[len(stack)-1] + ">"
	}
	rest := tgTag.ReplaceAllString(s, "")
	if strings.Contains(rest, "<") || strings.Contains(rest, ">") {
		return "stray < or >"
	}
	if regexp.MustCompile(`&(?:[a-z]+|#[0-9]+);`).ReplaceAllString(rest, "") != strings.ReplaceAll(rest, "&", "") && strings.Contains(regexp.MustCompile(`&(?:[a-z]+|#[0-9]+);`).ReplaceAllString(rest, ""), "&") {
		return "stray &"
	}
	return ""
}

// Every button and command of the bot, on tunnels of every kind (hot standby with paths,
// failover, stopped), with servers that can't be reached: nothing may panic, and every
// message must be one Telegram accepts.
func TestBotEveryButton(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir1", Name: "ir <xe101> & co", IPv4: "192.0.2.1", IPv6: "2001:db8::1", Country: "IR"}, {ID: "kh1", Name: "germany", IPv4: "198.51.100.1", IPv6: "2001:db8::2", Role: "foreign", Country: "DE"}}
		s.Tunnels = []*Tunnel{
			{ID: "aaaaaaaaaaaa", Name: "tehran-de <main>", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443", Index: 1, Active: "bp_reverse", Selected: "bp_reverse",
				Failover: &FailoverState{Method: "gre", Family: "v6", Reason: "tunnel link down"}},
			{ID: "bbbbbbbbbbbb", Name: "tehran-backup", ServerID: "ir1", ForeignID: "kh1", Family: "v6", Ports: "8443", Index: 2, Selected: "gre"},
			{ID: "cccccccccccc", Name: "hot & fast", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "2053", Index: 3, Active: "gre", Selected: "gre", HotStandby: true, HSAuto: true,
				Paths: []HSPath{{Method: "gre", Family: "v4", Index: 3}, {Method: "golden", Family: "v4", Index: 4}, {Method: "premium1", Family: "v6", Index: 5}, {Method: "bp_l3", Family: "v4", Index: 6, Failed: "no <traffic>"}}},
		}
		s.Outages = []Outage{{ID: "o1", Kind: "server", Target: "ir1", Name: "ir <xe101>", Start: time.Now().Add(-time.Hour).Unix(), End: time.Now().Unix(), Reason: "SSH port 192.0.2.1:22 doesn't answer"},
			{ID: "o2", Kind: "tunnel", Target: "aaaaaaaaaaaa", Name: "tehran-de <main>", Start: time.Now().Add(-time.Minute).Unix(), Reason: "link <down>", Cause: "both servers answer"}}
		s.BenchHistory = []BenchRecord{{ID: "h1", At: time.Now().Unix(), IranID: "ir1", IranName: "ir <xe101>", ForeignID: "kh1", ForeignName: "germany", Family: "v4",
			Results: []BenchResult{{Method: "bp_reverse", Title: "BackPack reverse", OK: true, Recommended: true, DownMbps: 125, UpMbps: 122, RTTms: 159},
				{Method: "bp_l3", Title: "BackPack L3 (TUN) · carrier sni", OK: true, DownMbps: 31, Opts: map[string]string{"carrier": "sni"}},
				{Method: "ipsec", Title: "IPsec", Error: "no traffic passes <x> & y"}}}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}, healthCache: map[string]string{"aaaaaaaaaaaa": "", "cccccccccccc": "link <down>"}, benchRes: map[string][]BenchResult{}}
	a.hostFor = func(*Server) Host { return downHost{} }
	a.notify = func(string) {}
	a.hsViews = map[string]*hsView{"cccccccccccc": {Active: 1, Paths: []string{"Plain GRE (v4)", "Golden-GRE (DNS/ICMP) (v4)", "Backhaul Premium v1 (legacy) (v6)"}, OK: []bool{true, true, false},
		RTT: []int{80, 90, -1}, Loss: []float64{0, 2.5, -1}, Kbps: []int{50000, -1, -1}, Keys: []string{"gre|v4", "golden|v4", "premium1|v6"}, Pin: 1, Auto: true}}
	f := &fakeTG{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	b := newBot(a, "TOKEN", "42")
	b.base = srv.URL

	for _, txt := range []string{"/start", "/menu", "/help", btnStatus, btnTunnels, btnTraffic, btnServers, "/status", "/tunnels", "/traffic", "/servers", "hello", "/nonsense"} {
		b.onText("42", txt)
	}
	cbs := []string{"home", "home:st", "home:bh", "home:bk", "home:out", "home:res", "noop"}
	for _, id := range []string{"aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"} {
		for _, c := range []string{"t:", "m:", "m:%:v6", "m:%:v4", "o:", "sq:", "dg:", "sp:", "tr:", "st:", "lg:", "hm:%:0", "hm:%:1", "hp:%:0", "hp:%:2", "hp:%:9", "hh:%:1", "hh:%:0", "s:"} {
			if strings.Contains(c, "%") {
				cbs = append(cbs, strings.ReplaceAll(c, "%", id))
			} else {
				cbs = append(cbs, c+id)
			}
		}
		cbs = append(cbs, "a:"+id+":gre:v4", "a:"+id+":golden:v6", "a:"+id+":nosuch:v4", "o:"+id+":bp_l3", "of:"+id+":bp_l3:carrier", "ov:"+id+":bp_l3:carrier:sni", "of:"+id+":bp_l3:mtu")
	}
	cbs = append(cbs, "t:zzzzzzzzzzzz", "x", "", "a:", "hp:cccccccccccc:-1", "hp:cccccccccccc:abc")
	for _, c := range cbs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("callback %q panicked: %v", c, r)
				}
			}()
			b.onCallback("42", 7, "cb", c)
		}()
	}
	b.onText("42", "1300")                                                // a typed option value, if one was asked for
	b.push("🔴 Server unreachable: A&B <iran>\nreason: dial <nil> & more") // alerts carry names and errors as they are
	time.Sleep(3 * time.Second)                                           // jobs (apply, diagnose…) fail fast on the unreachable host and report
	b.onText("99", "/menu")

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) < 40 {
		t.Fatalf("only %d Telegram calls", len(f.calls))
	}
	bad := 0
	for i, c := range f.calls {
		txt := c.Get("text")
		if txt == "" {
			txt = c.Get("caption")
		}
		if len(txt) > 4096 {
			t.Errorf("%s: text too long (%d)", f.names[i], len(txt))
		}
		if c.Get("parse_mode") == "HTML" || strings.Contains(txt, "<b>") {
			if e := tgHTML(txt); e != "" && bad < 15 {
				bad++
				t.Errorf("%s: Telegram would reject the HTML (%s):\n%s", f.names[i], e, txt)
			}
		}
		if mk := c.Get("reply_markup"); mk != "" {
			var m struct {
				Inline [][]ikey `json:"inline_keyboard"`
			}
			if err := json.Unmarshal([]byte(mk), &m); err != nil {
				t.Errorf("bad markup: %v", err)
			}
			for _, row := range m.Inline {
				for _, k := range row {
					if len(k.Data) > 64 {
						t.Errorf("button %q: callback data %d bytes (Telegram allows 64): %s", k.Text, len(k.Data), k.Data)
					}
					if k.Data == "" {
						t.Errorf("button %q has no callback data", k.Text)
					}
				}
			}
		}
	}
	t.Logf("%d Telegram calls checked", len(f.calls))
}
