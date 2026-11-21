package main

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// heldTrail is a trail whose close waits until released, as one does while
// an append it holds waits on the disk.
type heldTrail struct{ released chan struct{} }

func (h heldTrail) Close() error {
	<-h.released
	return nil
}

// TestAStopIsBoundedByATrailAnAppendHolds: a trail whose close waits on an
// append still syncing does not hold the stop past its bound, which says so;
// a trail that closes ends it with no error.
func TestAStopIsBoundedByATrailAnAppendHolds(t *testing.T) {
	held := heldTrail{released: make(chan struct{})}
	defer close(held.released)
	c := &collector{srv: &http.Server{ReadHeaderTimeout: time.Second}, trail: held}
	done := make(chan error, 1)
	go func() { done <- c.stopWithin(50 * time.Millisecond) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "the trail was not closed within 50ms") {
			t.Errorf("a stop past its bound = %v, want it to say the trail was not closed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stop still waits on a trail an append holds, past its bound")
	}
	free := heldTrail{released: make(chan struct{})}
	close(free.released)
	c = &collector{srv: &http.Server{ReadHeaderTimeout: time.Second}, trail: free}
	if err := c.stopWithin(time.Second); err != nil {
		t.Errorf("a stop whose trail closes = %v", err)
	}
}

// errServe is a server that stopped serving on its own.
var errServe = errors.New("the listener failed")

// TestATrailAfterServeFailedIsClosedWithinTheBound: when the server stops
// on its own, a trail whose close waits on an append still syncing does not
// hold collect past the bound, and both failures are said.
func TestATrailAfterServeFailedIsClosedWithinTheBound(t *testing.T) {
	held := heldTrail{released: make(chan struct{})}
	defer close(held.released)
	c := &collector{srv: &http.Server{ReadHeaderTimeout: time.Second}, trail: held}
	done := make(chan error, 1)
	go func() { done <- c.serveFailed(errServe, 50*time.Millisecond) }()
	select {
	case err := <-done:
		if !errors.Is(err, errServe) || !strings.Contains(err.Error(), "the trail was not closed within 50ms") {
			t.Errorf("a failed serve past the bound = %v, want the failure and that the trail was not closed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collect still waits on a trail an append holds after its server failed, past the bound")
	}
}
