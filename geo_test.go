package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type geoRT func(*http.Request) (*http.Response, error)

func (f geoRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func geoOK(body string) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
}

// stubGeo swaps the geo client for one fn answers, and clears the cache; undone at the end.
func stubGeo(t *testing.T, fn func(*http.Request) (*http.Response, error)) {
	t.Helper()
	old := geo.client
	geo.Lock()
	geo.cache, geo.failed = map[string]geoInfo{}, map[string]time.Time{}
	geo.Unlock()
	geo.client = &http.Client{Transport: geoRT(fn)}
	t.Cleanup(func() { geo.client = old })
}

// A failed lookup isn't kept for good: after geoRetry the next one asks again and keeps
// the answer.
func TestGeoRetriesAfterFailure(t *testing.T) {
	var mu sync.Mutex
	calls, down := 0, true
	stubGeo(t, func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if down {
			return nil, errors.New("endpoint down")
		}
		return geoOK(`{"success":true,"country_code":"DE","city":"Nuremberg"}`)
	})
	oldRetry := geoRetry
	defer func() { geoRetry = oldRetry }()
	const ip = "203.0.113.77"
	ctx := context.Background()
	geoRetry = time.Hour
	if g := lookupGeo(ctx, ip); g.Country != "" {
		t.Fatalf("first lookup should fail: %+v", g)
	}
	n := calls
	if n != len(geoSources) {
		t.Fatalf("every source should be tried once: %d calls", n)
	}
	if g := lookupGeo(ctx, ip); g.Country != "" || calls != n {
		t.Fatalf("within geoRetry: %+v, %d calls", g, calls)
	}
	geo.Lock()
	geo.failed[ip] = time.Now().Add(-time.Second) // geoRetry has passed
	geo.Unlock()
	down = false
	if g := lookupGeo(ctx, ip); g.Country != "DE" {
		t.Fatalf("after geoRetry: %+v", g)
	}
	if g := lookupGeo(ctx, ip); g.Country != "DE" || calls != n+1 {
		t.Errorf("the answer should be cached: %+v, %d calls", g, calls)
	}
}

// One source down, rate-limited or answering junk: the next one gives the country.
// And only the IP leaves the panel: no cookie, no body, nothing but the IP in the URL.
func TestGeoFallsBackToNextSource(t *testing.T) {
	var hosts []string
	stubGeo(t, func(r *http.Request) (*http.Response, error) {
		hosts = append(hosts, r.URL.Host)
		if r.Body != nil && r.Body != http.NoBody {
			t.Errorf("%s: a body was sent", r.URL)
		}
		if len(r.Header.Values("Cookie")) > 0 || r.Header.Get("Authorization") != "" {
			t.Errorf("%s: credentials were sent", r.URL)
		}
		if !strings.Contains(r.URL.String(), "203.0.113.9") {
			t.Errorf("%s: the IP is not what is asked", r.URL)
		}
		if q := r.URL.Query(); len(q) > 1 || (len(q) == 1 && q.Get("fields") == "") {
			t.Errorf("%s: more than the IP and the fields wanted", r.URL)
		}
		switch r.URL.Host {
		case "ipwho.is":
			return &http.Response{StatusCode: 429, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("slow down"))}, nil
		case "ip-api.com":
			return geoOK(`{"status":"fail","message":"quota"}`)
		case "api.country.is":
			return geoOK(`{"ip":"203.0.113.9","country":"tr"}`)
		}
		t.Errorf("asked %s after an answer", r.URL.Host)
		return nil, errors.New("no")
	})
	g := lookupGeo(context.Background(), "203.0.113.9")
	if g.Country != "TR" {
		t.Fatalf("got %+v, want TR (lower case answers are made upper case)", g)
	}
	if strings.Join(hosts, ",") != "ipwho.is,ip-api.com,api.country.is" {
		t.Errorf("sources asked: %v", hosts)
	}
	if g := lookupGeo(context.Background(), "10.0.0.1"); g.Country != "" {
		t.Errorf("a private address is never looked up: %+v", g)
	}
}

func TestNormCC(t *testing.T) {
	for in, want := range map[string]string{"de": "DE", " Tr ": "TR", "uk": "GB", "D": "", "DEU": "", "1A": "", "": "", "auto": ""} {
		if got := normCC(in); got != want {
			t.Errorf("normCC(%q) = %q, want %q", in, got, want)
		}
	}
}

func geoTestApp(t *testing.T) *App {
	t.Helper()
	dataDir = t.TempDir()
	st, err := LoadStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	return &App{store: st, jobs: newJobs(), agents: newAgentHub()}
}

// A country set by hand stays whatever detection finds; an automatic one follows the
// server's address; a country from before CountryIP existed is kept as it is.
func TestGeoManualNeverReplaced(t *testing.T) {
	stubGeo(t, func(r *http.Request) (*http.Response, error) {
		cc := map[string]string{"198.51.100.1": "DE", "198.51.100.2": "NL", "198.51.100.3": "US", "198.51.100.4": "FI"}
		for ip, c := range cc {
			if strings.Contains(r.URL.Path, ip) {
				return geoOK(`{"success":true,"country_code":"` + c + `"}`)
			}
		}
		return nil, errors.New("unknown")
	})
	a := geoTestApp(t)
	_ = a.store.Update(func(st *State) error {
		st.Servers = []*Server{
			{ID: "m", Name: "manual", IPv4: "198.51.100.1", Role: "foreign", Country: "GB", CountryManual: true},
			{ID: "e", Name: "empty", IPv4: "198.51.100.2", Role: "foreign"},
			{ID: "o", Name: "old", IPv4: "198.51.100.3", Role: "foreign", Country: "us"},
			{ID: "c", Name: "moved", IPv4: "198.51.100.4", Role: "foreign", Country: "DE", CountryIP: "198.51.100.1"},
		}
		return nil
	})
	for _, s := range storeServers(a) {
		a.annotateGeo(s)
	}
	// the backfill's first pass, without its waits
	_ = a.store.Update(func(st *State) error {
		for _, s := range st.Servers {
			if s.Country != "" && s.CountryIP == "" && !s.CountryManual {
				s.Country, s.CountryIP = normCC(s.Country), serverGeoAddr(s)
			}
		}
		return nil
	})
	want := map[string]string{"m": "GB", "e": "NL", "o": "US", "c": "FI"}
	for id, cc := range want {
		if x := a.store.Server(id); x == nil || x.Country != cc {
			t.Errorf("%s: %+v, want %s", id, x, cc)
		}
	}
	if x := a.store.Server("e"); x.CountryIP != "198.51.100.2" || x.CountryManual {
		t.Errorf("an automatic country keeps the address it was found for: %+v", x)
	}
	for _, s := range storeServers(a) {
		if geoDue(s) {
			t.Errorf("%s is still due after the pass: %+v", s.ID, s)
		}
	}
}

// The server form: a new code = set by hand; "auto" = found again from the IP; the same
// code or none at all leaves it as it was.
func TestServerFormCountry(t *testing.T) {
	stubGeo(t, func(r *http.Request) (*http.Response, error) {
		return geoOK(`{"success":true,"country_code":"DE","city":"Nuremberg"}`)
	})
	a := geoTestApp(t)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = a.store.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}}
		return nil
	})
	s := &Server2{app: a, failures: map[string][]time.Time{}}
	w := httptest.NewRecorder()
	s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"boss","password":"password1"}`)))
	var ck *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == "tp_session" {
			ck = k
		}
	}
	post := func(body string) {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/servers", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(ck)
		s.servers(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	wait := func(id string, ok func(*Server) bool) *Server {
		t.Helper()
		for i := 0; i < 200; i++ {
			if x := a.store.Server(id); x != nil && ok(x) {
				return x
			}
			time.Sleep(10 * time.Millisecond)
		}
		x := a.store.Server(id)
		t.Fatalf("server %s never got there: %+v", id, x)
		return nil
	}
	post(`{"name":"de1","ipv4":"198.51.100.20","role":"foreign","sshPort":22}`)
	var id string
	for _, x := range storeServers(a) {
		id = x.ID
	}
	x := wait(id, func(x *Server) bool { return x.Country == "DE" })
	if x.CountryManual {
		t.Errorf("a detected country is not a manual one: %+v", x)
	}
	base := `"ID":"` + id + `","name":"de1","ipv4":"198.51.100.20","role":"foreign","sshPort":22`
	post(`{` + base + `,"country":"DE"}`) // the form shows the detected one: unchanged
	if x := a.store.Server(id); x.CountryManual || x.Country != "DE" {
		t.Errorf("an unchanged country became manual: %+v", x)
	}
	post(`{` + base + `,"country":"nl"}`)
	if x := a.store.Server(id); !x.CountryManual || x.Country != "NL" {
		t.Errorf("a typed country should be kept as manual: %+v", x)
	}
	post(`{` + base + `}`) // a client that sends no country
	a.annotateGeo(a.store.Server(id))
	if x := a.store.Server(id); !x.CountryManual || x.Country != "NL" {
		t.Errorf("the manual country was replaced: %+v", x)
	}
	post(`{` + base + `,"country":"auto"}`)
	wait(id, func(x *Server) bool { return !x.CountryManual && x.Country == "DE" })
	post(`{"name":"tr1","ipv4":"198.51.100.21","role":"foreign","sshPort":22,"country":"tr","countryIp":"x"}`)
	for _, x := range storeServers(a) {
		if x.Name == "tr1" && (x.Country != "TR" || !x.CountryManual || x.CountryIP != "") {
			t.Errorf("a country typed in the add form is manual: %+v", x)
		}
	}
}

// Every flag the page knows has its SVG in the build, and every bundled SVG is known.
func TestFlagSVGsBundled(t *testing.T) {
	js, err := os.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`const FLAGS = new Set\('([a-z ]+)'`).FindSubmatch(js)
	if m == nil {
		t.Fatal("no FLAGS list in app.js")
	}
	known := map[string]bool{}
	for _, c := range strings.Fields(string(m[1])) {
		known[c] = true
		if _, err := fs.Stat(webRoot(), "flags/"+c+".svg"); err != nil {
			t.Errorf("flag %s: %v", c, err)
		}
	}
	files, _ := fs.Glob(webRoot(), "flags/*.svg")
	for _, f := range files {
		if c := strings.TrimSuffix(strings.TrimPrefix(f, "flags/"), ".svg"); !known[c] {
			t.Errorf("%s is bundled but not in FLAGS", f)
		}
	}
	for _, c := range []string{"ir", "de", "nl", "us", "fi", "tr", "gb", "fr"} {
		if !known[c] {
			t.Errorf("no flag for %s", c)
		}
	}
	if len(files) < 240 {
		t.Errorf("only %d flags bundled", len(files))
	}
}

func storeServers(a *App) []*Server {
	var out []*Server
	a.store.View(func(st *State) {
		for _, s := range st.Servers {
			c := *s
			out = append(out, &c)
		}
	})
	return out
}
