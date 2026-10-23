package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// Real downloads with checksum verification (network). TP_FETCH_LIVE=1.
func TestFetchPinnedLive(t *testing.T) {
	if os.Getenv("TP_FETCH_LIVE") == "" {
		t.Skip("set TP_FETCH_LIVE=1 (downloads from github.com)")
	}
	cacheDir = t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	j := newJobs().mustStart(t)
	set := Settings{FRPVersion: "0.61.1"}
	for _, a := range []Artifact{artBackhaul(set), artFRP(set, "frpc")} {
		b, err := ensureArtifact(ctx, j, a, "amd64")
		t.Logf("%s: %d bytes, err %v", a.Name, len(b), err)
		if err != nil || len(b) < 1<<20 {
			t.Errorf("%s failed", a.Name)
		}
	}
	// a wrong pin must stop the install
	bad := artBackhaul(set)
	bad.Name = "backhaul-badpin"
	bad.Fetch = replaceOnce(bad.Fetch, backhaulSHA256amd64, "0000000000000000000000000000000000000000000000000000000000000000")
	if _, err := ensureArtifact(ctx, j, bad, "amd64"); err == nil {
		t.Error("a checksum mismatch was installed")
	}
	for _, l := range j.snapshot().Lines {
		t.Log("  " + l)
	}
}

func (js *Jobs) mustStart(t *testing.T) *Job {
	j, err := js.start("", "test")
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func replaceOnce(s, a, b string) string {
	for i := 0; i+len(a) <= len(s); i++ {
		if s[i:i+len(a)] == a {
			return s[:i] + b + s[i+len(a):]
		}
	}
	return s
}
