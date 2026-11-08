package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type geoRT func(*http.Request) (*http.Response, error)

func (f geoRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A failed lookup isn't kept for good: after geoRetry the next one asks again and keeps
// the answer.
func TestGeoRetriesAfterFailure(t *testing.T) {
	calls := 0
	old, oldRetry := geo.client, geoRetry
	geo.client = &http.Client{Transport: geoRT(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("endpoint down")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{},
			Body: io.NopCloser(strings.NewReader(`{"status":"success","countryCode":"DE","city":"Nuremberg"}`))}, nil
	})}
	defer func() { geo.client, geoRetry = old, oldRetry }()
	const ip = "203.0.113.77"
	ctx := context.Background()
	geoRetry = time.Hour
	if g := lookupGeo(ctx, ip); g.Country != "" {
		t.Fatalf("first lookup should fail: %+v", g)
	}
	if g := lookupGeo(ctx, ip); g.Country != "" || calls != 1 {
		t.Fatalf("within geoRetry: %+v, %d calls", g, calls)
	}
	geo.Lock()
	geo.failed[ip] = time.Now().Add(-time.Second) // geoRetry has passed
	geo.Unlock()
	if g := lookupGeo(ctx, ip); g.Country != "DE" {
		t.Fatalf("after geoRetry: %+v", g)
	}
	if g := lookupGeo(ctx, ip); g.Country != "DE" || calls != 2 {
		t.Errorf("the answer should be cached: %+v, %d calls", g, calls)
	}
}
