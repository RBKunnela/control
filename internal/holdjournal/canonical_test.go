package holdjournal_test

import (
	"context"
	"encoding/base32"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/holdjournal"
)

// base32Alphabet is RFC 4648's, which the journal's entry names are written
// in.
const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// TestASecondNameForOneRequestIsForeign: a six-byte request id leaves two
// spare bits in its name's last character, so a writer of the directory can
// file a copy of the entry under a name that differs only there and decodes
// to the same id. The journal refuses the pass rather than list that request
// twice; the directory with the copy removed lists it once.
func TestASecondNameForOneRequestIsForeign(t *testing.T) {
	ctx := context.Background()
	dir := newDir(t)
	j := openJournal(t, dir)
	const id = "req-12"
	record(t, j, id)
	path := entryFileOf(t, dir, id)
	forged := secondName(t, filepath.Base(path), id)
	copied := filepath.Join(dir, forged)
	writeFile(t, copied, readFile(t, path))

	listing, err := j.List(ctx, 8)
	if !errors.Is(err, holdjournal.ErrForeignFile) || len(listing.Held) != 0 {
		t.Fatalf("a pass beside a second name for %q reported %+v, %v; want ErrForeignFile", id, listing, err)
	}
	if err := os.Remove(copied); err != nil {
		t.Fatalf("removing the copy: %v", err)
	}
	listing, err = j.List(ctx, 8)
	if err != nil || len(listing.Held) != 1 || !listing.Complete {
		t.Fatalf("a pass over the one entry reported %+v, %v", listing, err)
	}
}

// secondName is name, an entry's of id, with the lowest spare bit of its last
// character set: another spelling that decodes to id all the same.
func secondName(t *testing.T, name, id string) string {
	t.Helper()
	body, ok := strings.CutSuffix(name, ".hold")
	if !ok || len(body) != 10 {
		t.Fatalf("the entry of %q is filed as %q, not ten characters and .hold", id, name)
	}
	last := strings.IndexByte(base32Alphabet, body[len(body)-1])
	if last < 0 || last&1 != 0 {
		t.Fatalf("the name %q does not end in a character with a clear low bit", body)
	}
	forged := body[:len(body)-1] + string(base32Alphabet[last^1])
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(forged)
	if err != nil || string(raw) != id {
		t.Fatalf("%q does not decode to %q (%v); the case examines nothing", forged, id, err)
	}
	return forged + ".hold"
}
