package otelgenai_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/guardana/control/internal/ingest/otelgenai"
)

// failingReader fails every read with err.
type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

// failingOnce fails its first read with err and ends at io.EOF after it.
type failingOnce struct {
	err  error
	done bool
}

func (f *failingOnce) Read([]byte) (int, error) {
	if f.done {
		return 0, io.EOF
	}
	f.done = true
	return 0, f.err
}

// TestASourceFailureWrappingEOFFailsTheImport: complete lines followed by a
// read failing with an error that wraps io.EOF fail the import, since only
// io.EOF itself ends the input; the same lines ended by io.EOF import whole.
func TestASourceFailureWrappingEOFFailsTheImport(t *testing.T) {
	in := readTestdata(t, "mixed_service.jsonl")
	failed := io.MultiReader(bytes.NewReader(in), failingReader{fmt.Errorf("source failed: %w", io.EOF)})
	if _, err := otelgenai.Import(failed, descriptor(t), descSHA, received); err == nil || !strings.Contains(err.Error(), "source failed") {
		t.Errorf("an import whose source failed: %v; want the failure", err)
	}
	b, err := otelgenai.Import(io.MultiReader(bytes.NewReader(in)), descriptor(t), descSHA, received)
	if err != nil {
		t.Fatalf("an import ended by io.EOF: %v", err)
	}
	if got := b.Report.GetCounts().GetRead(); got != 10 {
		t.Errorf("an import ended by io.EOF read %d spans, want 10", got)
	}
}

// TestASourceFailureMatchingAFullBufferFailsTheImport: a read failure that
// also matches bufio.ErrBufferFull is the source's, not the line reader's
// full buffer, so the import fails though the source ends at io.EOF after it.
func TestASourceFailureMatchingAFullBufferFailsTheImport(t *testing.T) {
	in := readTestdata(t, "mixed_service.jsonl")
	cause := errors.Join(fmt.Errorf("source failed: %w", io.EOF), bufio.ErrBufferFull)
	failed := io.MultiReader(bytes.NewReader(in), &failingOnce{err: cause})
	if _, err := otelgenai.Import(failed, descriptor(t), descSHA, received); err == nil || !strings.Contains(err.Error(), "source failed") {
		t.Errorf("an import whose source failed with an error matching a full buffer: %v; want the failure", err)
	}
}
