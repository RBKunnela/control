package gateway_test

import (
	"context"
	"errors"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// TestADispositionSaysWhenItsExecutionIsUnrecorded: only a read handed out
// after the sink refused its trail, under the risk setting, is marked; a read
// whose trail landed under the same setting is not.
func TestADispositionSaysWhenItsExecutionIsUnrecorded(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads), func(c *gateway.Config) { c.AllowReadsUnrecorded = true })
	recorded := h.admit(readEnvelope(), []byte(`{}`))
	if recorded.Action != core.Execute || recorded.Unrecorded {
		t.Fatalf("a read whose trail landed: Action = %d, Unrecorded = %v", recorded.Action, recorded.Unrecorded)
	}
	h.sink.fail(true)
	unrecorded := h.admit(requestNamed(readEnvelope(), "req-2"), []byte(`{}`))
	if unrecorded.Action != core.Execute || !unrecorded.Unrecorded {
		t.Fatalf("a read whose trail the sink refused: Action = %d, Unrecorded = %v", unrecorded.Action, unrecorded.Unrecorded)
	}
}

// TestARefusedClosingOrAbortingRecordNamesErrNotRecorded: a record the sink
// refused is ErrNotRecorded beside the sink's error, a mismatch among them;
// a mismatch whose record landed, of JSON bytes or of bytes that are not
// JSON, is the mismatch alone.
func TestARefusedClosingOrAbortingRecordNamesErrNotRecorded(t *testing.T) {
	ok := result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)
	for _, tc := range []struct {
		name         string
		sent         []byte
		failing      bool
		mismatch     bool
		notRecorded  bool
		abortInstead bool
	}{
		{name: "a landed closing", sent: []byte(`{}`)},
		{name: "a landed mismatch", sent: []byte(`{"a":1}`), mismatch: true},
		{name: "a landed mismatch of bytes that are not JSON", sent: []byte(`not json`), mismatch: true},
		{name: "a refused closing", sent: []byte(`{}`), failing: true, notRecorded: true},
		{name: "a refused mismatch", sent: []byte(`{"a":1}`), failing: true, mismatch: true, notRecorded: true},
		{name: "a refused abort", failing: true, notRecorded: true, abortInstead: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, allowWrites))
			d := h.admit(writeEnvelope(), []byte(`{}`))
			h.sink.fail(tc.failing)
			var err error
			if tc.abortInstead {
				err = h.p.Abort(context.Background(), d, gateway.AbortCancelled)
			} else {
				err = h.p.CloseReported(context.Background(), d, tc.sent, ok)
			}
			if got := errors.Is(err, gateway.ErrExecutedArgsMismatch); got != tc.mismatch {
				t.Errorf("%v: mismatch = %v, want %v", err, got, tc.mismatch)
			}
			if got := errors.Is(err, gateway.ErrNotRecorded); got != tc.notRecorded {
				t.Errorf("%v: not recorded = %v, want %v", err, got, tc.notRecorded)
			}
			if tc.failing && !errors.Is(err, errSink) {
				t.Errorf("%v does not carry the sink's error", err)
			}
		})
	}
}
