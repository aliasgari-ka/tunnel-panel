package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// One "Measure" covers IPv4 and IPv6: the second family starts when the first ends, waits
// for a busy slot, and doesn't start after a cancel.
func TestBenchThen(t *testing.T) {
	old := benchThenPoll
	benchThenPoll = time.Millisecond
	defer func() { benchThenPoll = old }()

	js := newJobs()
	first, _ := js.start("bench", "bench")
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		benchThen(first, func() (*Job, error) {
			if calls.Add(1) < 3 {
				return nil, errBenchBusy // the automatic benchmark took the slot in between
			}
			return &Job{ID: "j2"}, nil
		}, time.Minute)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("the second family started while the first still ran")
	}
	first.finish("ok")
	<-done
	if calls.Load() != 3 {
		t.Fatalf("calls %d, want 3 (two busy, then started)", calls.Load())
	}

	// cancelled: nothing more
	c, _ := js.start("bench2", "bench")
	c.mu.Lock()
	c.Status = "cancelled"
	c.mu.Unlock()
	n := 0
	benchThen(c, func() (*Job, error) { n++; return nil, nil }, time.Minute)
	if n != 0 {
		t.Fatal("started after a cancel")
	}

	// another error: given up at once, said in the first job's log
	e, _ := js.start("bench3", "bench")
	e.finish("ok")
	m := 0
	benchThen(e, func() (*Job, error) { m++; return nil, errors.New("no methods match") }, time.Minute)
	if m != 1 {
		t.Fatalf("tries %d, want 1", m)
	}
}

// A stopped tunnel (or one no longer on hot standby) has no switcher view in the list: the
// last one read stayed and the pages said users were "now" on one of its paths.
func TestTunnelsHSViewOnlyWhileRunning(t *testing.T) {
	a, st := hsRemoveFixture(t)
	s := &Server2{app: a, failures: map[string][]time.Time{}}
	w := httptest.NewRecorder()
	s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"boss","password":"password1"}`)))
	var c *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == "tp_session" {
			c = k
		}
	}
	mux := a.routes()
	hasHS := func() bool {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/tunnels", nil)
		r.AddCookie(c)
		mux.ServeHTTP(w, r)
		var out []struct {
			ID string
			HS *hsView `json:"hs"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		for _, x := range out {
			if x.ID == "aaaaaaaaaaaa" {
				return x.HS != nil
			}
		}
		t.Fatal("tunnel not listed")
		return false
	}
	tn := st.Tunnel("aaaaaaaaaaaa")
	if !hasHS() {
		t.Fatal("a running hot-standby tunnel lost its switcher view")
	}
	_ = st.Update(func(*State) error { tn.Active = ""; return nil })
	if hasHS() {
		t.Fatal("a stopped tunnel still shows its last switcher view")
	}
	_ = st.Update(func(*State) error { tn.Active = "gre"; tn.HotStandby = false; return nil })
	if hasHS() {
		t.Fatal("hot standby off: the old switcher view is still shown")
	}
}
