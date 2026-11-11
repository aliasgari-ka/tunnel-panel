package main

import (
	"testing"
	"time"
)

func TestGemOneVerdict(t *testing.T) {
	for _, c := range []struct {
		code int
		body string
		want string
	}{
		{403, "<p><b>403.</b> <ins>That’s an error.</ins>", "refused"},
		{200, "Your client does not have permission to get URL /explore-plan/gemini-advanced from this server.", "refused"},
		{302, "", "ok"},
		{200, "<html>Google One</html>", "ok"},
		{502, "", ""},
		{0, "", ""},
	} {
		if g := gemOneVerdict(c.code, []byte(c.body)); g != c.want {
			t.Errorf("gemOneVerdict(%d, %q) = %q, want %q", c.code, c.body, g, c.want)
		}
	}
}

func TestGemOneStep(t *testing.T) {
	st := &gemOneState{}
	now := time.Now()
	if gemOneStep(st, "refused", now) {
		t.Fatal("one refusal reported")
	}
	if !gemOneStep(st, "refused", now) {
		t.Fatal("second refusal in a row not reported")
	}
	if gemOneStep(st, "refused", now.Add(time.Hour)) {
		t.Fatal("reported again within gemOneAlert")
	}
	if gemOneStep(st, "", now.Add(2*time.Hour)) || st.bad != 3 {
		t.Fatal("an undecided check changed the count")
	}
	gemOneStep(st, "ok", now.Add(3*time.Hour))
	if st.bad != 0 {
		t.Fatal("ok did not reset")
	}
	gemOneStep(st, "refused", now.Add(7*time.Hour))
	if !gemOneStep(st, "refused", now.Add(7*time.Hour)) {
		t.Fatal("not reported again after gemOneAlert")
	}
}
