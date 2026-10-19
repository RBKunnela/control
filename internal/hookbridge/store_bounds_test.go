package hookbridge_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/hookbridge"
)

// The body Publish writes for a handle h and the expiry later is this one
// with h between the quotes of handle.
const emptyHandleBody = `{"version":"1.0","handle":"","expires_at":"2030-01-02T03:04:05.000000006Z"}`

func TestAPublishIsBoundedAt4KiB(t *testing.T) {
	dir := storeDir(t)
	s := openStore(t, dir)
	handle := strings.Repeat("h", 4<<10-len(emptyHandleBody))
	if err := s.Publish("tok", "s", "at", hookbridge.Entry{Handle: handle, ExpiresAt: later}); err != nil {
		t.Fatalf("a body of exactly 4 KiB: %v", err)
	}
	if c, err := s.Claim("tok", "s", "at"); err != nil || c.Handle != handle {
		t.Fatalf("the entry of exactly 4 KiB does not read back: %v", err)
	}
	err := s.Publish("tok", "s", "over", hookbridge.Entry{Handle: handle + "h", ExpiresAt: later})
	if !errors.Is(err, hookbridge.ErrEntry) {
		t.Fatalf("a body of one byte more = %v", err)
	}
	if got := names(t, dir); len(got) != 1 {
		t.Fatalf("the refused publish left %v", got)
	}
}

// writeTemp leaves a file as a publish that crashed before it was named
// would: a temporary name holding body.
func writeTemp(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil { //nolint:gosec // G703: a name in this test's own directory
		t.Fatal(err)
	}
}

func TestASweepRemovesAnExpiredTemporaryEntry(t *testing.T) {
	dir := storeDir(t)
	s := openStore(t, dir)
	const (
		expired = ".tmp-AAAAAAAAAAAAAAAAAAAAAAAAAA"
		current = ".tmp-BBBBBBBBBBBBBBBBBBBBBBBBBB"
		torn    = ".tmp-CCCCCCCCCCCCCCCCCCCCCCCCCC"
		other   = ".tmp-short"
	)
	writeTemp(t, dir, expired, `{"version":"1.0","handle":"h-1","expires_at":"2030-01-02T03:04:05Z"}`)
	writeTemp(t, dir, current, `{"version":"1.0","handle":"h-2","expires_at":"2031-01-02T03:04:05Z"}`)
	writeTemp(t, dir, torn, `{"version":"1.0","han`)
	writeTemp(t, dir, other, `{"version":"1.0","handle":"h-3","expires_at":"2030-01-02T03:04:05Z"}`)
	n, err := s.Sweep(time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC))
	if n != 1 || err != nil {
		t.Fatalf("Sweep = %d, %v; want the one expired temporary entry", n, err)
	}
	got := names(t, dir)
	slices.Sort(got)
	if want := []string{current, torn, other}; !slices.Equal(got, want) {
		t.Fatalf("left %v, want %v", got, want)
	}
}

// A name that reads as a claimed entry up to its claimer's suffix, but whose
// suffix is not one a claim makes, is no entry: a sweep leaves it, however
// expired the body it holds.
func TestASweepLeavesANameNoClaimMakes(t *testing.T) {
	dir := storeDir(t)
	s := openStore(t, dir)
	path := publishOne(t, s, dir, "c", later)
	body, err := os.ReadFile(path) //nolint:gosec // G304: a file this test wrote
	if err != nil {
		t.Fatal(err)
	}
	odd := []string{filepath.Base(path) + ".claimed-short", filepath.Base(path) + ".claimed-" + strings.Repeat("A", 27)}
	for _, name := range odd {
		writeTemp(t, dir, name, string(body))
	}
	if n, err := s.Sweep(later.Add(time.Hour)); n != 1 || err != nil {
		t.Fatalf("Sweep = %d, %v; want the one entry", n, err)
	}
	got := names(t, dir)
	slices.Sort(got)
	slices.Sort(odd)
	if !slices.Equal(got, odd) {
		t.Fatalf("left %v, want %v", got, odd)
	}
}
