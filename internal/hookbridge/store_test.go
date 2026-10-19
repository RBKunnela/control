package hookbridge_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/hookbridge"
)

func storeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	return dir
}

func openStore(t *testing.T, dir string) *hookbridge.Store {
	t.Helper()
	s, err := hookbridge.OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

var later = time.Date(2030, 1, 2, 3, 4, 5, 6, time.UTC)

func TestAStoreDirectoryIsThisAccountsAlone(t *testing.T) {
	if _, err := hookbridge.OpenStore(""); !errors.Is(err, hookbridge.ErrNoStoreDir) {
		t.Fatalf("no directory = %v", err)
	}
	for _, mode := range []fs.FileMode{0o710, 0o701, 0o740, 0o704, 0o720, 0o702, 0o755} {
		dir := storeDir(t)
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := hookbridge.OpenStore(dir); !errors.Is(err, hookbridge.ErrStoreNotOwnerOnly) || !errors.Is(err, files.ErrMode) {
			t.Errorf("mode %04o = %v, want ErrStoreNotOwnerOnly", mode, err)
		}
	}
	file := filepath.Join(storeDir(t), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hookbridge.OpenStore(file); err == nil {
		t.Fatal("a regular file opened as a store")
	}
	openStore(t, storeDir(t))
}

// A directory opened owner-only and widened afterwards is refused at the
// next publish, before the handle is written.
func TestAPublishChecksTheDirectoryAgain(t *testing.T) {
	dir := storeDir(t)
	s := openStore(t, dir)
	if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	err := s.Publish("tok", "s-1", "c-1", hookbridge.Entry{Handle: "h-1", ExpiresAt: later})
	if !errors.Is(err, hookbridge.ErrStoreNotOwnerOnly) || len(names(t, dir)) != 0 {
		t.Fatalf("Publish = %v, names %v", err, names(t, dir))
	}
}

// The name is computed here apart from the store: SHA-256 over the domain
// tag and each part after its length as eight big-endian bytes.
func TestAnEntryIsNamedByAHashThatHidesTheToken(t *testing.T) {
	dir := storeDir(t)
	s := openStore(t, dir)
	const token = "run-secret.x1"
	if err := s.Publish(token, "s-1", "c-1", hookbridge.Entry{Handle: "h-1", ExpiresAt: later}); err != nil {
		t.Fatal(err)
	}
	pre := "hookbridge/entry/v1" +
		"\x00\x00\x00\x00\x00\x00\x00\x0d" + token +
		"\x00\x00\x00\x00\x00\x00\x00\x03" + "s-1" +
		"\x00\x00\x00\x00\x00\x00\x00\x03" + "c-1"
	sum := sha256.Sum256([]byte(pre))
	want := hex.EncodeToString(sum[:])
	got := names(t, dir)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("names %v, want [%s]", got, want)
	}
	body, err := os.ReadFile(filepath.Join(dir, want)) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"version":"1.0","handle":"h-1","expires_at":"2030-01-02T03:04:05.000000006Z"}` {
		t.Fatalf("body %s", body)
	}
	info, err := os.Stat(filepath.Join(dir, want))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", info.Mode(), err)
	}
	if strings.Contains(strings.Join(got, ""), token) || strings.Contains(string(body), token) {
		t.Fatal("the token is on disk")
	}
	if hookbridge.RequestKey("s-1", "c-1") == want || len(hookbridge.RequestKey("s-1", "c-1")) != 64 {
		t.Fatalf("request key %q", hookbridge.RequestKey("s-1", "c-1"))
	}
}

func TestTheLengthsKeepTwoKeysApart(t *testing.T) {
	dir := storeDir(t)
	s := openStore(t, dir)
	for _, k := range [][3]string{{"ab", "c", "d"}, {"a", "bc", "d"}, {"a", "b", "cd"}} {
		if err := s.Publish(k[0], k[1], k[2], hookbridge.Entry{Handle: "h", ExpiresAt: later}); err != nil {
			t.Fatalf("%v: %v", k, err)
		}
	}
	if hookbridge.RequestKey("ab", "c") == hookbridge.RequestKey("a", "bc") {
		t.Fatal("two request keys collide")
	}
}

func TestAnEntryIsCreatedOnceAndRefusesEmptyParts(t *testing.T) {
	s := openStore(t, storeDir(t))
	e := hookbridge.Entry{Handle: "h-1", ExpiresAt: later}
	if err := s.Publish("tok", "s-1", "c-1", e); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish("tok", "s-1", "c-1", hookbridge.Entry{Handle: "h-2", ExpiresAt: later}); !errors.Is(err, files.ErrExists) {
		t.Fatalf("a second publish = %v", err)
	}
	for _, tc := range []struct {
		tok, session, call string
		e                  hookbridge.Entry
	}{
		{"", "s", "c", e}, {"t", "", "c", e}, {"t", "s", "", e},
		{"t", "s", "c", hookbridge.Entry{ExpiresAt: later}}, {"t", "s", "c", hookbridge.Entry{Handle: "h"}},
	} {
		if err := s.Publish(tc.tok, tc.session, tc.call, tc.e); !errors.Is(err, hookbridge.ErrEntry) {
			t.Errorf("Publish(%q, %q, %q, %+v) = %v", tc.tok, tc.session, tc.call, tc.e, err)
		}
	}
	c, err := s.Claim("tok", "s-1", "c-1")
	if err != nil || c.Handle != "h-1" || !c.ExpiresAt.Equal(later) {
		t.Fatalf("Claim = %+v, %v", c, err)
	}
}

func TestExactlyOneOfTwoClaimersWins(t *testing.T) {
	dir := storeDir(t)
	s := openStore(t, dir)
	for i := range 50 {
		call := "c-" + string(rune('a'+i%26)) + strings.Repeat("x", i)
		if err := s.Publish("tok", "s", call, hookbridge.Entry{Handle: "h", ExpiresAt: later}); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		for j := range errs {
			wg.Go(func() {
				<-start
				var c hookbridge.Claimed
				if c, errs[j] = s.Claim("tok", "s", call); errs[j] == nil && c.Handle != "h" {
					errs[j] = errors.New("claimed another handle")
				}
			})
		}
		close(start)
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, hookbridge.ErrNoEntry):
				t.Fatalf("a claim failed: %v", err)
			}
		}
		if won != 1 {
			t.Fatalf("round %d: %d claimers won", i, won)
		}
	}
	if _, err := s.Claim("tok", "s", "never"); !errors.Is(err, hookbridge.ErrNoEntry) {
		t.Fatalf("a claim of nothing = %v", err)
	}
}

func TestAClaimedEntryIsRemoved(t *testing.T) {
	dir := storeDir(t)
	s := openStore(t, dir)
	if err := s.Publish("tok", "s", "c", hookbridge.Entry{Handle: "h", ExpiresAt: later}); err != nil {
		t.Fatal(err)
	}
	c, err := s.Claim("tok", "s", "c")
	if err != nil || len(names(t, dir)) != 1 {
		t.Fatalf("Claim = %v, names %v", err, names(t, dir))
	}
	if err := s.Remove(c); err != nil || len(names(t, dir)) != 0 {
		t.Fatalf("Remove = %v, names %v", err, names(t, dir))
	}
	if err := s.Remove(hookbridge.Claimed{}); !errors.Is(err, hookbridge.ErrEntry) {
		t.Fatalf("Remove of nothing claimed = %v", err)
	}
}
