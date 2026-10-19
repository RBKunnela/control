package hookbridge

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// endless lists as many names as each call asks for, and ends only far past
// any bound a sweep keeps.
type endless struct{ listed int }

func (e *endless) Readdirnames(n int) ([]string, error) {
	if e.listed >= 1<<14 {
		return nil, io.EOF
	}
	if n <= 0 {
		n = 1 << 14
	}
	e.listed += n
	return make([]string, n), nil
}

// A sweep looks at no more than 256 names, so a directory full of other
// files cannot stall a hook.
func TestASweepExaminesABoundedNumberOfNames(t *testing.T) {
	d := &endless{}
	seen := 0
	err := examine(d, func(string) (bool, error) {
		seen++
		return false, nil
	})
	if err != nil || seen != sweepExamine || d.listed != sweepExamine {
		t.Fatalf("examined %d of %d names listed: %v; want %d of %d", seen, d.listed, err, sweepExamine, sweepExamine)
	}
}

func FuzzParseEntry(f *testing.F) {
	f.Add([]byte(`{"version":"1.0","handle":"h","expires_at":"2030-01-02T03:04:05Z"}`))
	f.Add([]byte(`{"version":"1.7","handle":"h-1","expires_at":"2030-01-02T03:04:05.000000006Z"}`))
	f.Add([]byte(`{"version":"2.0","handle":"h","expires_at":"2030-01-02T03:04:05Z"}`))
	f.Add([]byte(`{"version":"1.0","handle":"h","handle":"g","expires_at":"2030-01-02T03:04:05Z"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := parseEntry(raw)
		if err != nil {
			if !errors.Is(err, ErrEntry) {
				t.Fatalf("refused with %v, want ErrEntry", err)
			}
			return
		}
		var doc map[string]string
		if err := json.Unmarshal(raw, &doc); err != nil || len(doc) != 3 {
			t.Fatalf("accepted %q, which is not an object of three strings: %v", raw, err)
		}
		major, _, _ := strings.Cut(doc["version"], ".")
		at, err := time.Parse(time.RFC3339Nano, doc["expires_at"])
		if major != "1" || e.Handle == "" || e.Handle != doc["handle"] || err != nil || !at.Equal(e.ExpiresAt) {
			t.Fatalf("accepted %q as %+v", raw, e)
		}
	})
}
