package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestIgProxyNorm(t *testing.T) {
	ok := []struct{ t, h, p, u, pw, want string }{
		{"", "1.2.3.4", "8080", "", "", "http 1.2.3.4 8080 - -"},
		{"SOCKS", "proxy.example.com", "۱۰۸۰", "bob", "p@ss:w/rd%41", "socks5 proxy.example.com 1080 bob p@ss:w/rd%41"},
		{"socks5h", "2001:db8::7", "3128", "u", "p", "socks5 [2001:db8::7] 3128 u p"},
		{"http", "[2001:DB8::7]", "٨٠", "", "", "http [2001:db8::7] 80 - -"},
		{"http", " gate.nodemaven.com ", " 8080 ", "nodemaven-a_b@x", "x'y", "http gate.nodemaven.com 8080 nodemaven-a_b@x x'y"},
	}
	for _, c := range ok {
		p, err := igProxyNorm(c.t, c.h, c.p, c.u, c.pw)
		if err != nil || p.line() != c.want {
			t.Errorf("%v: got %q %v, want %q", c, p.line(), err, c.want)
		}
	}
	bad := []struct{ t, h, p, u, pw string }{
		{"https", "1.2.3.4", "80", "", ""},       // was silently HTTP
		{"http", "1.2.3.4:80", "80", "", ""},     // host:port in the host box
		{"http", "http://1.2.3.4", "80", "", ""}, // a URL in the host box
		{"http", "1.2.3.4", "0", "", ""},         // port range
		{"http", "1.2.3.4", "65536", "", ""},     // port range
		{"http", "1.2.3.4", "80", "us:er", "pw"}, // curl -U split it into user "us"
		{"http", "1.2.3.4", "80", "", "secret"},  // password dropped without a user
		{"http", "1.2.3.4", "80", "bob", "-"},    // "-" = no password for the agent
		{"http", "1.2.3.4", "80", "bob", "a b"},  // the agent's file is split on spaces
		{"http", "1.2.3.4;id", "80", "", ""},     // shell
		{"http", "", "80", "", ""},               // empty
	}
	for _, c := range bad {
		if p, err := igProxyNorm(c.t, c.h, c.p, c.u, c.pw); err == nil {
			t.Errorf("%v accepted as %q", c, p.line())
		}
	}
	if igMaskUser("nodemaven5Jfgq") != "node…gq" || igMaskUser("bob") != "b…" || igMaskUser("-") != "" {
		t.Errorf("mask: %q %q", igMaskUser("nodemaven5Jfgq"), igMaskUser("bob"))
	}
}

// igPxFake is a server with an agent and a proxy file: it answers the panel's list / test /
// guard scripts and "igproxy proxy add|del" like the agent does.
type igPxFake struct {
	mu      sync.Mutex
	name    string
	lines   []string // "type host port user pass"
	down    bool     // unreachable
	broken  bool     // every proxy test fails
	ran     []string
	removed []string
}

var (
	rxPxInput = regexp.MustCompile(`printf '%s\\n' ('(?:[^']|'"'"')*') \| timeout`)
	rxPxGuard = regexp.MustCompile(`(?s)#igpx-guard n=(\d+).*? = ('(?:[^']|'"'"')*') \] \|\|.*?igproxy (.*?) </dev/null`)
)

func unq(s string) string { return strings.ReplaceAll(strings.Trim(s, "'"), `'"'"'`, "'") }

func (h *igPxFake) Label() string                               { return h.name }
func (h *igPxFake) WriteFile(string, []byte, os.FileMode) error { return nil }
func (h *igPxFake) Run(ctx context.Context, script string, log func(string)) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.down {
		return "", errors.New("dial tcp: i/o timeout")
	}
	h.ran = append(h.ran, script)
	var out []string
	switch {
	case strings.Contains(script, "#igpx-guard"):
		m := rxPxGuard.FindStringSubmatch(script)
		n, _ := strconv.Atoi(m[1])
		cur := ""
		if n >= 1 && n <= len(h.lines) {
			f := strings.Fields(h.lines[n-1])
			cur = strings.Join(f[:4], " ")
		}
		if cur != unq(m[2]) {
			out = []string{"__CHANGED", "__RC=0"}
			break
		}
		args := strings.Fields(strings.ReplaceAll(m[3], "'", ""))
		if args[0] == "proxy" && args[1] == "del" {
			h.removed = append(h.removed, h.lines[n-1])
			h.lines = append(h.lines[:n-1:n-1], h.lines[n:]...)
			out = []string{"  proxy " + args[2] + " removed", "__RC=0"}
		} else {
			out = []string{"  route " + args[1] + " -> " + args[2], "__RC=0"}
		}
	case strings.Contains(script, "#igpx-list"):
		for i, l := range h.lines {
			f := strings.Fields(l)
			out = append(out, strings.Join([]string{"P", strconv.Itoa(i + 1), f[0], f[1], f[2], f[3], "0"}, "\t"))
		}
		if strings.Contains(script, "#igpx-test") {
			for i := range h.lines {
				if h.broken {
					out = append(out, "T\t"+strconv.Itoa(i+1)+"\t-\t\t\t000")
				} else {
					out = append(out, "T\t"+strconv.Itoa(i+1)+"\t210\t203.0.113.50\tDE\t204")
				}
			}
		}
		out = append(out, "__RC=0")
	case strings.Contains(script, "igproxy 'proxy' 'add' '-'"):
		l := unq(rxPxInput.FindStringSubmatch(script)[1])
		out = append(out, "  testing ...")
		if h.broken {
			out = append(out, "  !! proxy does not work - not added", "__RC=1")
			break
		}
		out = append(out, "  OK - exit IP 203.0.113.50 (DE)  210ms")
		dup := false
		for _, x := range h.lines {
			dup = dup || x == l
		}
		if dup {
			out = append(out, "  already in the list", "__RC=0")
			break
		}
		h.lines = append(h.lines, l)
		out = append(out, "  proxy "+strconv.Itoa(len(h.lines))+" added", "__RC=0")
	default:
		out = []string{"ig=direct router=active redirect=ON sum=-", "__RC=0"}
	}
	for _, l := range out {
		if log != nil {
			log(l)
		}
	}
	return strings.Join(out, "\n"), nil
}

func igPxSetup(t *testing.T) (*Server2, map[string]*igPxFake, func(user, h string, body string) *httptest.ResponseRecorder) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	pw, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(pw)}, {Username: "ali", Hash: string(pw), Role: roleUser}}
		s.Servers = []*Server{
			{ID: "a1", Name: "de", IPv4: "198.51.100.1", Role: "foreign", Igproxy: true},
			{ID: "a2", Name: "nl", IPv4: "198.51.100.2", Role: "foreign", Igproxy: true},
			{ID: "a3", Name: "fi", IPv4: "198.51.100.3", Role: "foreign", Igproxy: true},
			{ID: "u1", Name: "ali-de", IPv4: "198.51.100.9", Role: "foreign", Owner: "ali", Igproxy: true},
		}
		return nil
	})
	app := &App{store: st, jobs: newJobs(), agents: newAgentHub()}
	hosts := map[string]*igPxFake{}
	for _, id := range []string{"a1", "a2", "a3", "u1"} {
		hosts[id] = &igPxFake{name: id}
	}
	app.hostFor = func(s *Server) Host { return hosts[s.ID] }
	s := &Server2{app: app, failures: map[string][]time.Time{}}
	cookies := map[string]*http.Cookie{}
	for _, u := range []string{"boss", "ali"} {
		w := httptest.NewRecorder()
		s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"`+u+`","password":"password1"}`)))
		for _, k := range w.Result().Cookies() {
			if k.Name == "tp_session" {
				cookies[u] = k
			}
		}
	}
	call := func(user, path, body string) *httptest.ResponseRecorder {
		h := map[string]http.HandlerFunc{"list": s.igProxyList, "add": s.igProxyAdd, "cmd": s.igProxyCmd}[path]
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/igproxy/"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(cookies[user])
		s.auth(s.json(s.guard("self", h)))(w, r)
		return w
	}
	return s, hosts, call
}

type igPxList struct {
	Proxies []igProxyRow `json:"proxies"`
}

func pxList(t *testing.T, call func(string, string, string) *httptest.ResponseRecorder, srv string, test bool) igPxList {
	t.Helper()
	b := `{"srv":"` + srv + `"}`
	if test {
		b = `{"srv":"` + srv + `","test":1}`
	}
	w := call("boss", "list", b)
	if w.Code != 200 {
		t.Fatalf("list %s: %d %s", srv, w.Code, w.Body)
	}
	var v igPxList
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	return v
}

// The list never carries a password or a whole user; a test result is shown per proxy and
// stays with that proxy.
func TestIgProxyListMasked(t *testing.T) {
	_, hosts, call := igPxSetup(t)
	hosts["a1"].lines = []string{"http 151.242.115.57 11000 nodemaven5Jfgq S3cr3t-pass", "socks5 [2001:db8::7] 1080 - -"}
	w := call("boss", "list", `{"srv":"a1","test":1}`)
	if strings.Contains(w.Body.String(), "S3cr3t") || strings.Contains(w.Body.String(), "nodemaven5Jfgq") {
		t.Fatalf("password or full user in the answer: %s", w.Body)
	}
	v := pxList(t, call, "a1", false)
	if len(v.Proxies) != 2 || v.Proxies[0].User != "node…gq" || v.Proxies[1].User != "" || v.Proxies[1].Host != "[2001:db8::7]" {
		t.Fatalf("rows: %+v", v.Proxies)
	}
	if tt := v.Proxies[0].Test; tt == nil || !tt.OK || tt.MS != 210 || tt.IP != "203.0.113.50" || tt.Loc != "DE" || !tt.Google {
		t.Errorf("the last test is not kept with the proxy: %+v", tt)
	}
	// ali cannot read the admin's server
	if w := call("ali", "list", `{"srv":"a1"}`); w.Code == 200 {
		t.Errorf("a user read the admin's proxies: %s", w.Body)
	}
}

// Deleting by number deleted the wrong proxy once the list had changed under the page: the
// page listed 1=A 2=B 3=C, someone removed A elsewhere, "Delete" on C sent "proxy del 3"
// (out of range) and "Delete" on B sent "proxy del 2" = C.
func TestIgProxyDeleteAfterListChanged(t *testing.T) {
	_, hosts, call := igPxSetup(t)
	A, B, C := "http 192.0.2.1 8001 ua pa", "http 192.0.2.2 8002 ub pb", "http 192.0.2.3 8003 uc pc"
	hosts["a1"].lines = []string{A, B, C}
	v := pxList(t, call, "a1", false)
	keyB := v.Proxies[1].Key
	hosts["a1"].lines = []string{B, C} // A removed by another page
	if w := call("boss", "cmd", `{"srv":"a1","do":"del","key":"`+keyB+`"}`); w.Code != 200 {
		t.Fatalf("del: %d %s", w.Code, w.Body)
	}
	if got := hosts["a1"].lines; len(got) != 1 || got[0] != C || hosts["a1"].removed[0] != B {
		t.Fatalf("wrong proxy deleted: left %v, removed %v", got, hosts["a1"].removed)
	}
	// a proxy that is gone is reported, nothing is deleted
	if w := call("boss", "cmd", `{"srv":"a1","do":"del","key":"`+keyB+`"}`); w.Code != 409 || len(hosts["a1"].lines) != 1 {
		t.Errorf("gone proxy: %d %s, left %v", w.Code, w.Body, hosts["a1"].lines)
	}
	// "use" pins the proxy by its number now
	keyC := pxList(t, call, "a1", false).Proxies[0].Key
	w := call("boss", "cmd", `{"srv":"a1","do":"use","svc":"IG","key":"`+keyC+`"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "proxy1") {
		t.Errorf("use: %d %s", w.Code, w.Body)
	}
}

// The guard on the server itself: the line changed between the panel's read and the delete.
func TestIgProxyGuardScript(t *testing.T) {
	sc := igPxGuard(&igProxyRow{N: 2, Type: "http", Host: "192.0.2.2", Port: "8002", user: "u'b"}, []string{"proxy", "del", "2"}, 180)
	if !strings.Contains(sc, `[ "$t $h $p $u" = 'http 192.0.2.2 8002 u'"'"'b' ]`) || !strings.Contains(sc, "sed -n '2p' /etc/igproxy/proxies") || !strings.Contains(sc, "igproxy 'proxy' 'del' '2' </dev/null") {
		t.Errorf("guard script:\n%s", sc)
	}
	if sc := igPxScript(true, 0); strings.Contains(sc, "-U ") || !strings.Contains(sc, "#igpx-test") || !strings.Contains(sc, `hh="[$hh]"`) {
		t.Errorf("test script:\n%s", sc)
	}
}

// "On every server in view": each server's own result; ok only when every server has it.
// The same proxy with another password is not added a second time.
func TestIgProxyAddEveryServer(t *testing.T) {
	_, hosts, call := igPxSetup(t)
	hosts["a1"].lines = []string{"http 192.0.2.9 8080 bob oldpass"}
	hosts["a2"].broken = true
	hosts["a3"].down = true
	w := call("boss", "add", `{"srv":"all","view":"-","type":"http","host":"192.0.2.9","port":"۸۰۸۰","user":"bob","pass":"n@w:p/a%ss"}`)
	if w.Code != 200 {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	var v struct {
		Results []igPxResult
		OK      bool
		Failed  int
	}
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	got := map[string]string{}
	for _, r := range v.Results {
		got[r.ID] = r.Status
	}
	if v.OK || v.Failed != 2 || got["a1"] != "exists" || got["a2"] != "failed" || got["a3"] != "unreachable" || len(v.Results) != 3 {
		t.Fatalf("results: %s", w.Body)
	}
	if len(hosts["a1"].lines) != 1 {
		t.Errorf("same proxy added twice: %v", hosts["a1"].lines)
	}
	for _, r := range v.Results {
		if r.ID == "a2" && !strings.Contains(r.Msg, "does not work") {
			t.Errorf("the agent's reason is lost: %+v", r)
		}
	}
	// a server that takes it: added, with the tested exit
	hosts["a2"].broken = false
	w = call("boss", "add", `{"srv":"a2","type":"socks","host":"2001:db8::7","port":"1080","user":"bob","pass":"n@w:p/a%ss"}`)
	if !strings.Contains(w.Body.String(), `"status":"added"`) || !strings.Contains(w.Body.String(), `"ok":true`) || !strings.Contains(w.Body.String(), `"ip":"203.0.113.50"`) {
		t.Fatalf("add a2: %s", w.Body)
	}
	if got := hosts["a2"].lines; len(got) != 1 || got[0] != "socks5 [2001:db8::7] 1080 bob n@w:p/a%ss" {
		t.Errorf("stored: %v", got)
	}
	if w := call("boss", "add", `{"srv":"a2","type":"http","host":"192.0.2.9","port":"80","pass":"x"}`); w.Code != 400 {
		t.Errorf("password without user: %d %s", w.Code, w.Body)
	}
	// a user's "all" is its own servers only
	w = call("ali", "add", `{"srv":"all","view":"","type":"http","host":"192.0.2.9","port":"80"}`)
	if !strings.Contains(w.Body.String(), `"id":"u1"`) || strings.Contains(w.Body.String(), `"id":"a`) {
		t.Errorf("ali's all: %s", w.Body)
	}
}
