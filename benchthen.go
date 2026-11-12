package main

import (
	"errors"
	"time"
)

// benchThenWait: how long the follow-up benchmark waits for the slot (the automatic
// benchmark may take it between the two) before it gives up.
var benchThenWait = 20 * time.Minute

// benchThen starts next once first has finished: the second address family of one "Measure".
// A cancelled first run cancels the second; a busy slot (another benchmark started in
// between) is waited for.
func benchThen(first *Job, next func() (*Job, error), wait time.Duration) {
	for first.snapshot().Status == "running" {
		time.Sleep(benchThenPoll)
	}
	if first.cancelled() {
		return
	}
	end := time.Now().Add(wait)
	for {
		j, err := next()
		if err == nil || !errors.Is(err, errBenchBusy) {
			if err != nil {
				first.log("the next family's benchmark didn't start: %v", err)
			} else if j != nil {
				first.log("next: the other address family is being measured (job %s)", j.ID)
			}
			return
		}
		if time.Now().After(end) {
			first.log("the next family's benchmark didn't start: another benchmark kept the slot")
			return
		}
		time.Sleep(benchThenPoll * 5)
	}
}

var benchThenPoll = 2 * time.Second
