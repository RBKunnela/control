package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policystate"
)

// TestRenewsOfOneOutLeaveTheNewestStatement: renews of serials 4, 5 and 6,
// each under its own signer floor directory, start together on one --out
// holding serial 3. In every round --out ends holding serial 6, its renew
// exits 0, a renew that exits 1 says a newer statement is there, and no
// temporary file is left.
func TestRenewsOfOneOutLeaveTheNewestStatement(t *testing.T) {
	const rounds = 20
	serials := []int{4, 5, 6}
	broken := 0
	for round := range rounds {
		r := newRenewTree(t)
		renewed(t, r, r.bundle, 3)
		start := time.Now().Truncate(time.Second).Add(-time.Minute)
		ps := make([]renewPaths, len(serials))
		for i, serial := range serials {
			ps[i] = r.paths()
			ps[i].floor = filepath.Join(r.dir, fmt.Sprintf("floors-%d", serial))
			if err := policystate.Init(context.Background(), ps[i].floor, policystate.KindSigner, "orders-policy"); err != nil {
				t.Fatal(err)
			}
			ps[i].bundle = filepath.Join(r.dir, fmt.Sprintf("b%d.bundle", serial))
			writeBundle(t, ps[i].bundle, renewDocument(serial, "allow-reads"), r.bundleSigner)
		}
		codes, stderrs := make([]int, len(ps)), make([]string, len(ps))
		var gate, wg sync.WaitGroup
		gate.Add(1)
		for i, p := range ps {
			wg.Add(1)
			go func() {
				defer wg.Done()
				gate.Wait()
				var stderr bytes.Buffer
				codes[i] = renew(p, start, &bytes.Buffer{}, &stderr)
				stderrs[i] = stderr.String()
			}()
		}
		gate.Done()
		wg.Wait()
		_, st := freshStatement(t, r.out)
		if why := newestKept(t, r.dir, st, serials, codes, stderrs); why != "" {
			broken++
			if broken <= 3 {
				t.Errorf("round %d: %s; exits %v, stderr %q", round, why, codes, stderrs)
			}
		}
	}
	if broken > 0 {
		t.Errorf("%d of %d rounds broke the renew contract", broken, rounds)
	}
}

// newestKept says what a round of renews left wrong, or "" when --out holds
// the last serial, whose renew exited 0, every renew that failed names the
// newer statement, and no temporary file is left in dir.
func newestKept(t *testing.T, dir string, st policy.Statement, serials, codes []int, stderrs []string) string {
	t.Helper()
	last := len(serials) - 1
	if int(st.Serial()) != serials[last] {
		return fmt.Sprintf("--out holds serial %d, want %d", st.Serial(), serials[last])
	}
	if codes[last] != exitOK {
		return fmt.Sprintf("the renew of %d exited %d", serials[last], codes[last])
	}
	for i, code := range codes {
		if code != exitOK && !strings.Contains(stderrs[i], errRaceLost) {
			return fmt.Sprintf("the renew of %d failed without naming a newer statement", serials[i])
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if ondisk.IsTemp(e.Name()) {
			return fmt.Sprintf("a temporary file is left: %s", e.Name())
		}
	}
	return ""
}

// TestARenewWhoseWriteLeftAFileStopsAndNamesIt: a write of --out that failed
// once it had written, here one whose name changed again while what stood
// there was put back, is not judged again: the renew exits 1 and stderr
// names the file it left. A refusal that wrote nothing is judged again.
func TestARenewWhoseWriteLeftAFileStopsAndNamesIt(t *testing.T) {
	left := ".tmp-" + strings.Repeat("A", 26)
	for _, c := range []struct {
		name    string
		refusal error
		writes  int
		code    int
	}{
		{"a write that left a file", fmt.Errorf("%w: \"out\" changed again while it was put back; %q holds what stood there then", ondisk.ErrNotJudged, left), 1, exitFail},
		{"a refusal that wrote nothing", fmt.Errorf("%w: \"out\" changed since it was judged: %w", ondisk.ErrNotJudged, ondisk.ErrNothingWritten), 2, exitOK},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRenewTree(t)
			renewed(t, r, r.bundle, 3)
			newer := r.paths()
			newer.bundle = filepath.Join(r.dir, "newer.bundle")
			writeBundle(t, newer.bundle, renewDocument(4, "allow-reads"), r.bundleSigner)
			writes := 0
			writeOutOver(t, func(ctx context.Context, path string, env policy.StatementEnvelope, judged fs.FileInfo) error {
				writes++
				if writes == 1 {
					return c.refusal
				}
				return realWriteOut(ctx, path, env, judged)
			})
			var stderr bytes.Buffer
			code := renew(newer, time.Now().Add(time.Second), &bytes.Buffer{}, &stderr)
			if code != c.code || writes != c.writes {
				t.Errorf("exit %d after %d writes, stderr %q; want exit %d after %d", code, writes, stderr.String(), c.code, c.writes)
			}
			if c.code == exitFail && !strings.Contains(stderr.String(), left) {
				t.Errorf("stderr %q does not name the file left, %s", stderr.String(), left)
			}
		})
	}
}

// realWriteOut is the write renew makes when no test replaced it.
var realWriteOut = writeOut

// writeOutOver sets the write renew makes of --out, for the test's length.
func writeOutOver(t *testing.T, f func(context.Context, string, policy.StatementEnvelope, fs.FileInfo) error) {
	t.Helper()
	writeOut = f
	t.Cleanup(func() { writeOut = realWriteOut })
}
