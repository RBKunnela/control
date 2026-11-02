package segmentlog

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
)

// TestOpenTakesOnlyAKnownKind: the default kind opens, and no other name,
// the empty one included, is read as it.
func TestOpenTakesOnlyAKnownKind(t *testing.T) {
	for _, kind := range []string{"", "Segments", "segments ", "objects"} {
		cfg := config(logDir(t), 16, 32)
		cfg.Kind = kind
		if l, err := Open(cfg); l != nil || !errors.Is(err, ErrKind) {
			t.Errorf("kind %q opened %v, %v; want ErrKind", kind, l, err)
		}
	}
	l, err := Open(config(logDir(t), 16, 32))
	if err != nil {
		t.Fatalf("the default kind: %v", err)
	}
	_ = l.Close()
}

// TestOpenHoldsTheBoundsToEachOther: a log bound below twice the segment's,
// either bound alone, a negative one and an empty or ill-formed binding are
// refused, each beside the value that opens.
func TestOpenHoldsTheBoundsToEachOther(t *testing.T) {
	for _, c := range []struct {
		segment, max int64
		tenant       string
		ok           bool
	}{
		{0, 0, "t1", true}, {16, 32, "t1", true}, {16, 31, "t1", false}, {16, 0, "t1", false}, {0, 32, "t1", false},
		{-1, 32, "t1", false}, {16, -32, "t1", false}, {16, 32, "", false}, {16, 32, "t\u200b1", false}, {16, 32, " t1", false},
	} {
		cfg := config(logDir(t), c.segment, c.max)
		cfg.Tenant = c.tenant
		l, err := Open(cfg)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrConfig)) {
			t.Errorf("segment %d, log %d, tenant %q: %v, want opened %v", c.segment, c.max, c.tenant, err, c.ok)
		}
		if l != nil {
			_ = l.Close()
		}
	}
}

// TestALiveSegmentIsSealedBeforeItWouldPassItsBound: lines that take the live
// segment exactly to its bound go in; one byte more seals it first, and the
// lines go to the next live segment whole.
func TestALiveSegmentIsSealedBeforeItWouldPassItsBound(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, config(dir, 12, 64))
	mustAppend(t, l, "aaa", "bbb")
	mustAppend(t, l, "ccc")
	if m := l.Manifest(); len(m.Segments) != 0 || m.Live.Bytes != 12 || m.Live.Lines != 3 {
		t.Fatalf("at the bound exactly: %+v", m)
	}
	mustAppend(t, l, "d")
	m := l.Manifest()
	if len(m.Segments) != 1 || m.Segments[0].Bytes != 12 || m.Segments[0].Lines != 3 || m.Live.Bytes != 2 {
		t.Fatalf("one byte past the bound: %+v", m)
	}
	holds(t, filepath.Join(dir, "segment-00000001.jsonl"), "aaa\nbbb\nccc\n")
	holds(t, filepath.Join(dir, LiveName), "d\n")
	s := m.Segments[0]
	if s.First != sum("aaa") || s.Last != sum("ccc") || s.SealedAt.Unix() != 1_800_000_000 {
		t.Errorf("the sealed segment is named %+v", s)
	}
}

func holds(t *testing.T, path, want string) {
	t.Helper()
	if got := fileText(t, path); got != want {
		t.Errorf("%s holds %q, want %q", filepath.Base(path), got, want)
	}
}

// TestTheBudgetRefusesAndPrunesNothing: an append that takes the log to its
// bound exactly is taken; one more line seals the live segment it would take
// past its own bound, is refused with ErrBudget, and writes nothing of
// itself and prunes nothing; once an operator prunes, the same append is
// taken.
func TestTheBudgetRefusesAndPrunesNothing(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, config(dir, 8, 16))
	mustAppend(t, l, "aaa", "bbb")
	mustAppend(t, l, "ccc", "ddd")
	if got := l.Manifest().Retained; got != 16 {
		t.Fatalf("retained %d, want 16", got)
	}
	err := l.Append(context.Background(), []byte("e\n"))
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("one line past the bound: %v, want ErrBudget", err)
	}
	if got := dirNames(t, dir); !slices.Equal(got, []string{"segment-00000001.jsonl", "segment-00000002.jsonl", ManifestName, LockName}) {
		t.Errorf("after the refusal the directory holds %v, want the two sealed segments and no live one", got)
	}
	holds(t, filepath.Join(dir, "segment-00000002.jsonl"), "ccc\nddd\n")
	if m := l.Manifest(); m.Retained != 16 || !slices.Equal(states(m), []State{StateSealed, StateSealed}) {
		t.Errorf("after the refusal: %+v", m)
	}
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	mustAppend(t, l, "e")
	if m := l.Manifest(); m.Retained != 10 || len(m.Segments) != 2 || m.Segments[0].State != StatePruned {
		t.Errorf("after the prune: %+v", m)
	}
}

// TestALogWithNoBoundTakesNoAppend: a log opened with both bounds zero, as a
// prune opens one, refuses every append.
func TestALogWithNoBoundTakesNoAppend(t *testing.T) {
	l := openLog(t, config(logDir(t), 0, 0))
	if err := l.Append(context.Background(), []byte("a\n")); !errors.Is(err, ErrBudget) {
		t.Errorf("Append = %v, want ErrBudget", err)
	}
}

// TestAnAppendIsWholeLines: an append with no newline at its end is refused
// and writes nothing.
func TestAnAppendIsWholeLines(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, config(dir, 16, 32))
	for _, b := range []string{"", "a", "a\nb"} {
		if err := l.Append(context.Background(), []byte(b)); !errors.Is(err, ErrLines) {
			t.Errorf("Append(%q) = %v, want ErrLines", b, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, LiveName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused append made a live segment: %v", err)
	}
}

// threeSegments is a log of two sealed segments, aaa and bbb then ccc and
// ddd, and a live one of eee.
func threeSegments(t *testing.T, dir string) *segments {
	t.Helper()
	l := openLog(t, config(dir, 8, 64))
	mustAppend(t, l, "aaa", "bbb")
	mustAppend(t, l, "ccc", "ddd")
	mustAppend(t, l, "eee")
	return l
}

// TestAPruneOfNoSealedSegmentIsRefused: nothing, the live segment, and a
// number past it are refused, and the two sealed ones beside them prune.
func TestAPruneOfNoSealedSegmentIsRefused(t *testing.T) {
	l := threeSegments(t, logDir(t))
	for _, through := range []int{0, -1, 3, 4} {
		if err := l.Prune(through); !errors.Is(err, ErrPrune) {
			t.Errorf("Prune(%d) = %v, want ErrPrune", through, err)
		}
	}
	if err := l.Prune(2); err != nil {
		t.Errorf("Prune(2) = %v", err)
	}
}

// TestPruneWritesATombstoneAndRemovesTheFile: the pruned segment's facts stay
// in the manifest and its file goes; a prefix pruned again is nothing.
func TestPruneWritesATombstoneAndRemovesTheFile(t *testing.T) {
	dir := logDir(t)
	l := threeSegments(t, dir)
	l.cfg.Now = clockAt(1_800_000_100)
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	if got := dirNames(t, dir); !slices.Equal(got, []string{LiveName, "segment-00000002.jsonl", ManifestName, LockName}) {
		t.Errorf("after the prune the directory holds %v", got)
	}
	if ans := l.Locate(key(1, "aaa")); !isTombstone(ans) {
		t.Errorf("the pruned segment is located as %v %+v", ans.State(), ans.Segment())
	}
	before := fileText(t, filepath.Join(dir, ManifestName))
	if err := l.Prune(1); err != nil || fileText(t, filepath.Join(dir, ManifestName)) != before {
		t.Errorf("pruning a pruned prefix again: %v, or the manifest changed", err)
	}
	if err := l.Prune(2); err != nil || !slices.Equal(states(l.Manifest()), []State{StatePruned, StatePruned}) {
		t.Errorf("Prune(2) = %v, states %v", err, states(l.Manifest()))
	}
}

// isTombstone reports whether ans is segment 1 of threeSegments, pruned at
// the second 1_800_000_100.
func isTombstone(ans SegmentAnswer) bool {
	s := ans.Segment()
	return ans.State() == StatePruned && s.Lines == 2 && s.Bytes == 8 && s.First == sum("aaa") && s.Last == sum("bbb") &&
		s.PrunedAt.Unix() == 1_800_000_100 && s.File == ""
}

// TestLocateAnswersForEachState: the zero answer is Unknown; a key no
// segment has, the same first line under another number among them, is
// Unknown; the live, a sealed and a pruned segment are each what they are,
// each by its own number when two begin with the same line.
func TestLocateAnswersForEachState(t *testing.T) {
	if a := (SegmentAnswer{}); a.State() != StateUnknown || a.Segment() != (Segment{}) || a.Cause() == "" {
		t.Errorf("the zero answer is %v %+v %q", a.State(), a.Segment(), a.Cause())
	}
	l := openLog(t, config(logDir(t), 8, 64))
	mustAppend(t, l, "aaa", "bbb")
	mustAppend(t, l, "ccc", "ddd")
	mustAppend(t, l, "aaa")
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[Digest]State{key(1, "aaa"): StatePruned, key(2, "ccc"): StateSealed, key(3, "aaa"): StateLive,
		key(2, "ddd"): StateUnknown, key(4, "aaa"): StateUnknown, key(1, "zzz"): StateUnknown} {
		if got := l.Locate(k).State(); got != want {
			t.Errorf("Locate(%x) = %v, want %v", k[:4], got, want)
		}
	}
	if got := l.Locate(key(3, "aaa")).Segment(); got.Seq != 3 || got.Lines != 1 {
		t.Errorf("the live segment is located as %+v", got)
	}
}

// TestASegmentKeyIsItsNumberAndFirstLine: the key is the SHA-256 the
// contract spells, computed here apart from the package.
func TestASegmentKeyIsItsNumberAndFirstLine(t *testing.T) {
	first := sha256.Sum256([]byte("aaa\n"))
	want := sha256.Sum256(append([]byte(brand.OTelNamespace+".segments/12/"), first[:]...))
	if got := SegmentKey(12, first); got != want {
		t.Errorf("SegmentKey(12, aaa) = %x, want %x", got, want)
	}
}

// TestOneWriterHoldsTheDirectory: a second open of a held directory is
// refused, and the first one closed frees it.
func TestOneWriterHoldsTheDirectory(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, config(dir, 16, 32))
	if _, err := openSegments(config(dir, 16, 32)); !errors.Is(err, ErrLocked) {
		t.Errorf("a second open = %v, want ErrLocked", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	openLog(t, config(dir, 16, 32))
}

// TestEveryLineIsVisitedOnceInOrder: an open hands the visitor every line of
// the sealed segments and then the live one, and none of a pruned segment;
// a visitor's refusal refuses the open.
func TestEveryLineIsVisitedOnceInOrder(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, config(dir, 8, 64))
	mustAppend(t, l, "aaa", "bbb")
	mustAppend(t, l, "ccc", "ddd")
	mustAppend(t, l, "eee")
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	seen, again := visited(t, config(dir, 8, 64))
	if !slices.Equal(seen, []string{"ccc", "ddd", "eee"}) {
		t.Errorf("visited %q", seen)
	}
	_ = again.Close()
	cfg := config(dir, 8, 64)
	cfg.Visit = func(line []byte) error {
		if string(line) == "eee\n" {
			return errors.New("not one of ours")
		}
		return nil
	}
	if _, err := openSegments(cfg); err == nil {
		t.Error("an open went on past a line the visitor refused")
	}
}

// openTornLive opens a live file and cuts nothing, as no consumer of this
// package should open one.
func openTornLive(root *os.Root, name string) (LiveFile, error) {
	f, err := root.OpenFile(name, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return testLive{f}, nil
}

// TestALiveSegmentItsOpenerLeftTornIsRefused: a live segment that still ends
// past its last newline once its opener had it is no segment a log appends
// to, and the open is refused; the same segment cut opens.
func TestALiveSegmentItsOpenerLeftTornIsRefused(t *testing.T) {
	cfg := config(logDir(t), 64, 256)
	l := openLog(t, cfg)
	mustAppend(t, l, "aaa")
	_ = l.Close()
	writeIn(t, cfg.Dir, LiveName, "aaa\nbb")
	cfg.OpenLive = openTornLive
	if _, err := openSegments(cfg); !errors.Is(err, ErrManifest) {
		t.Errorf("a torn live segment: %v, want ErrManifest", err)
	}
	cfg.OpenLive = openTestLive
	_ = openLog(t, cfg).Close()
}

// TestALogIsBoundToItsTenantAndProject: a log opened for another tenant or
// project than its manifest names is refused.
func TestALogIsBoundToItsTenantAndProject(t *testing.T) {
	dir := logDir(t)
	_ = openLog(t, config(dir, 16, 32)).Close()
	for _, c := range [][2]string{{"t2", "p1"}, {"t1", "p2"}} {
		cfg := config(dir, 16, 32)
		cfg.Tenant, cfg.Project = c[0], c[1]
		if _, err := openSegments(cfg); !errors.Is(err, ErrBinding) {
			t.Errorf("tenant %s project %s: %v, want ErrBinding", c[0], c[1], err)
		}
	}
	_ = openLog(t, config(dir, 16, 32)).Close()
}

// gatedLive refuses an append with what refusal holds, writing nothing, and
// otherwise appends as testLive does.
type gatedLive struct {
	LiveFile
	refusal *error
}

func (l gatedLive) AppendLines(ctx context.Context, lines []byte) error {
	if *l.refusal != nil {
		return *l.refusal
	}
	return l.LiveFile.AppendLines(ctx, lines)
}

// TestALiveFileChangedUnderTheLogFailsIt: a live file refusing an append as
// changed fails the log, which then seals and prunes nothing; any other
// refusal leaves the log taking appends.
func TestALiveFileChangedUnderTheLogFailsIt(t *testing.T) {
	errOther := errors.New("refused, the file as it was")
	for _, c := range []struct {
		refusal error
		fails   bool
	}{{fmt.Errorf("%w: cut", ErrLiveChanged), true}, {errOther, false}} {
		cfg := config(logDir(t), 8, 1<<10)
		var refusal error
		cfg.OpenLive = func(root *os.Root, name string) (LiveFile, error) {
			f, err := openTestLive(root, name)
			return gatedLive{f, &refusal}, err
		}
		l := openLog(t, cfg)
		mustAppend(t, l, "aaa")
		refusal = c.refusal
		if err := l.Append(context.Background(), []byte("b\n")); !errors.Is(err, c.refusal) {
			t.Fatalf("the refused append = %v, want %v", err, c.refusal)
		}
		refusal = nil
		err := l.Append(context.Background(), []byte("eeeee\n"))
		perr := l.Prune(1)
		if failed := errors.Is(err, ErrFailed) && errors.Is(perr, ErrFailed); failed != c.fails {
			t.Errorf("after %v: a sealing append %v, a prune %v; failed %v, want %v", c.refusal, err, perr, failed, c.fails)
		}
		if n := len(l.Manifest().Segments); c.fails && n != 0 {
			t.Errorf("the failed log sealed %d segments, want none", n)
		}
	}
}

// TestAPruneDatedBeforeASealIsRefused: a prune whose clock stands before the
// seal of a segment it would prune is refused, naming the clock, with the
// manifest and the files unchanged, so the log stays one its next open reads;
// at the second of that seal it prunes.
func TestAPruneDatedBeforeASealIsRefused(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, config(dir, 8, 64))
	mustAppend(t, l, "aaa", "bbb")
	mustAppend(t, l, "ccc", "ddd")
	l.cfg.Now = clockAt(1_800_000_010)
	mustAppend(t, l, "eee")
	l.cfg.Now = clockAt(1_800_000_009)
	if err := l.Prune(1); err != nil {
		t.Fatalf("Prune(1) after segment 1's seal = %v", err)
	}
	manifest, names := fileText(t, filepath.Join(dir, ManifestName)), dirNames(t, dir)
	if err := l.Prune(2); !errors.Is(err, ErrClock) || !strings.Contains(err.Error(), "2027-01-15T08:00:09Z") {
		t.Errorf("Prune(2) a second before segment 2's seal = %v, want ErrClock naming the clock", err)
	}
	if fileText(t, filepath.Join(dir, ManifestName)) != manifest || !slices.Equal(dirNames(t, dir), names) {
		t.Errorf("the refused prune changed the directory: %v", dirNames(t, dir))
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l = openLog(t, config(dir, 8, 64))
	l.cfg.Now = clockAt(1_800_000_010)
	if err := l.Prune(2); err != nil {
		t.Errorf("Prune(2) at segment 2's seal = %v", err)
	}
}
