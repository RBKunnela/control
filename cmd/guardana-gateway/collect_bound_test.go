package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/adapters/otel"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/segmentlog"
	"github.com/guardana/control/internal/trailfile"
)

// TestCollectTakesNothingWithoutItsCredential: a request without the
// credential, or with another, is answered 401 and writes nothing; the same
// request with it is taken.
func TestCollectTakesNothingWithoutItsCredential(t *testing.T) {
	out := filepath.Join(t.TempDir(), "trail")
	c := startCollect(t, out)
	body := otlpFixture(t, "export_logs_request.json")
	for _, auth := range []string{"", "Bearer " + collectToken[1:], "Bearer " + collectToken + "q", "Basic " + collectToken, collectToken} {
		if status := c.postAs(t, body, auth); status != http.StatusUnauthorized {
			t.Errorf("Authorization %q answered %d, want 401", auth, status)
		}
	}
	if got := liveSegment(t, out); len(got) != 0 {
		t.Errorf("a request without the credential wrote %q", got)
	}
	if status := c.post(t, body); status != http.StatusOK {
		t.Errorf("the request with the credential answered %d", status)
	}
	c.stop(t)
}

// TestCollectRefusesACredentialFileItCannotTrust: a credential file the group
// may read, one that is not there, and one too short to be a credential are
// refused before anything is listened on, and no refusal prints the file's
// content; the file beside each, narrowed or long enough, is taken.
func TestCollectRefusesACredentialFileItCannotTrust(t *testing.T) {
	short := strings.Repeat("w", 31)
	cases := map[string]struct {
		body string
		mode os.FileMode
		want string
	}{
		"readable by the group": {collectToken, 0o640, "mode"},
		"too short":             {short, 0o600, "32 to 512 bytes"},
		"a space in it":         {strings.Repeat("w", 20) + " " + strings.Repeat("w", 20), 0o600, "not printable ASCII"},
	}
	for name, c := range cases {
		path := filepath.Join(t.TempDir(), "credential")
		if err := os.WriteFile(path, []byte(c.body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, c.mode); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "trail")
		args := []string{"collect", "--listen", "unix://" + exportSocket(t), "--dir", out, "--tenant", "tenant-1", "--project", "proj-1",
			"--credential-file", path}
		// A collect that took the file would serve until this deadline and
		// end 0, which fails here rather than hanging the suite.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var stdout, stderr syncBuffer
		status := run(ctx, args, &stdout, &stderr)
		cancel()
		if status != exitFail || !strings.Contains(stderr.String(), c.want) || strings.Contains(stderr.String(), c.body) {
			t.Errorf("%s: answered %d with %q, want %d naming %q and not the content", name, status, stderr.String(), exitFail, c.want)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s: a refused collect made its trail directory", name)
		}
	}
	missing := []string{"collect", "--listen", "unix://" + exportSocket(t), "--dir", filepath.Join(t.TempDir(), "trail"), "--tenant", "tenant-1",
		"--project", "proj-1", "--credential-file", filepath.Join(t.TempDir(), "absent")}
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), missing, &stdout, &stderr); status != exitFail {
		t.Errorf("a credential file that is not there answered %d", status)
	}
	c := startCollect(t, filepath.Join(t.TempDir(), "trail"))
	c.stop(t)
}

// TestCollectRefusesAnotherProjectsEvents: a collect bound to another project
// or tenant than the fixture's answers its request 400, which the exporter
// quarantines on, and writes nothing.
func TestCollectRefusesAnotherProjectsEvents(t *testing.T) {
	for _, bind := range [][2]string{{"tenant-1", "proj-2"}, {"tenant-2", "proj-1"}} {
		out := filepath.Join(t.TempDir(), "trail")
		ctx, cancel := context.WithCancel(context.Background())
		c := &collecting{stdout: &syncBuffer{}, stderr: &syncBuffer{}, cancel: cancel, done: make(chan int, 1)}
		args := []string{"collect", "--listen", "unix://" + exportSocket(t), "--dir", out, "--tenant", bind[0], "--project", bind[1],
			"--credential-file", credentialFile(t, collectToken)}
		go func() { c.done <- run(ctx, args, c.stdout, c.stderr) }()
		_, url, _ := strings.Cut(waitFor(t, c.stdout, "listening on "), "listening on ")
		c.url = strings.TrimSpace(url)
		if status := c.post(t, otlpFixture(t, "export_logs_request.json")); status != http.StatusBadRequest {
			t.Errorf("bound to %v: the fixture answered %d, want 400", bind, status)
		}
		if got := liveSegment(t, out); len(got) != 0 {
			t.Errorf("bound to %v: the trail holds %q", bind, got)
		}
		c.stop(t)
	}
}

// TestCollectRefusesBoundsThatCouldWedgeTheLog: a segment bound below the
// largest request, a log bound below twice it and both bounds zero are
// refused before anything is opened; the bounds at those limits start.
func TestCollectRefusesBoundsThatCouldWedgeTheLog(t *testing.T) {
	least := int64(otel.MaxRequestBytes)
	for _, b := range [][2]int64{{least - 1, 4 * least}, {least, 2*least - 1}, {0, 0}} {
		out := filepath.Join(t.TempDir(), "trail")
		args := append(collectArgs(t, "unix://"+exportSocket(t), out), "--segment-bytes", strconv.FormatInt(b[0], 10),
			"--max-bytes", strconv.FormatInt(b[1], 10))
		// A collect that took the bounds would serve until this deadline and
		// end 0, which fails here rather than hanging the suite.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var stdout, stderr syncBuffer
		status := run(ctx, args, &stdout, &stderr)
		cancel()
		if status != exitUsage {
			t.Errorf("bounds %v answered %d with %q, want %d", b, status, stderr.String(), exitUsage)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("bounds %v made the trail directory", b)
		}
	}
	c := startCollect(t, filepath.Join(t.TempDir(), "trail"), "--segment-bytes", strconv.FormatInt(least, 10),
		"--max-bytes", strconv.FormatInt(2*least, 10))
	c.stop(t)
}

// sealedTrail is a log in a new directory of three segments, the first two
// sealed, one line each, closed; it returns the directory and the bytes of
// the first segment's file.
func sealedTrail(t *testing.T) (string, int64) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "trail")
	l, err := trailfile.OpenLog(trailfile.LogConfig{Dir: dir, Tenant: "t1", Project: "p1", SegmentBytes: 1, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range trailOf("req-1", kProposed, kDecided, kRequested) {
		if err := l.Append(context.Background(), []*controlv1.Event{ev}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "segment-00000001.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return dir, info.Size()
}

// pruneRefusedWhileHeld checks prune refuses the log in dir while a writer
// holds it, and removes nothing.
func pruneRefusedWhileHeld(t *testing.T, dir string) {
	t.Helper()
	held, err := trailfile.OpenLog(trailfile.LogConfig{Dir: dir, Tenant: "t1", Project: "p1"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"prune", "--through", "1", dir}, &stdout, &stderr); status != exitFail ||
		!strings.Contains(stderr.String(), "held by another writer") {
		t.Errorf("prune of a held directory answered %d with %q", status, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "segment-00000001.jsonl")); err != nil {
		t.Errorf("a refused prune removed the segment: %v", err)
	}
}

// TestPruneRemovesSealedSegmentsAndLeavesTheirTombstones: prune through 1
// says what it removed, marks the segment pruned, unlinks its file and keeps
// the next one; while a collector holds the directory it is refused and
// removes nothing.
func TestPruneRemovesSealedSegmentsAndLeavesTheirTombstones(t *testing.T) {
	dir, first := sealedTrail(t)
	pruneRefusedWhileHeld(t, dir)
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{"prune", "--through", "1", dir}, &stdout, &stderr)
	if status != exitOK || !strings.Contains(stdout.String(), "through 1 are pruned; "+strconv.FormatInt(first, 10)+" byte(s) removed") {
		t.Fatalf("prune answered %d with %q and %q", status, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "segment-00000001.jsonl")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the pruned segment's file is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "segment-00000002.jsonl")); err != nil {
		t.Errorf("the segment after the pruned one is gone: %v", err)
	}
	v, err := segmentlog.Inspect(dir, evidence.MaxLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	if m := v.Manifest(); len(m.Segments) != 2 || m.Segments[0].State != segmentlog.StatePruned ||
		m.Segments[0].Bytes != first || m.Segments[1].State != segmentlog.StateSealed {
		t.Errorf("after the prune the manifest is %+v", m)
	}
}

// droppedTrail is a log in a new directory whose first segment was pruned
// and its tombstone dropped, as a seal at the cap drops it, with segments 2
// and 3 sealed, one line each, closed.
func droppedTrail(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "trail")
	l, err := trailfile.OpenLog(trailfile.LogConfig{Dir: dir, Tenant: "t1", Project: "p1", SegmentBytes: 1, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range trailOf("req-1", kProposed, kDecided, kRequested, kStarted) {
		if err := l.Append(context.Background(), []*controlv1.Event{ev}); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(l.Prune(1), l.Close()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, segmentlog.ManifestName)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	m := string(raw)
	first, second := strings.Index(m, `{"seq":1,"state":"pruned"`), strings.Index(m, `{"seq":2,`)
	if first < 0 || second < first || !strings.Contains(m, `"dropped":0,`) {
		t.Fatalf("the manifest is not the one this test edits: %s", m)
	}
	m = strings.Replace(m[:first]+m[second:], `"dropped":0,`, `"dropped":1,`, 1)
	if err := os.WriteFile(path, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestPruneCountsSegmentsFromTheDroppedOnes: once a tombstone was dropped,
// prune through 2 prunes segment 2 and keeps segment 3 and its file.
func TestPruneCountsSegmentsFromTheDroppedOnes(t *testing.T) {
	dir := droppedTrail(t)
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"prune", "--through", "2", dir}, &stdout, &stderr); status != exitOK {
		t.Fatalf("prune answered %d with %q and %q", status, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "segment-00000002.jsonl")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("segment 2's file after prune through 2: %v, want gone", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "segment-00000003.jsonl")); err != nil {
		t.Errorf("prune through 2 removed segment 3's file: %v", err)
	}
	v, err := segmentlog.Inspect(dir, evidence.MaxLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	if m := v.Manifest(); m.Dropped != 1 || len(m.Segments) != 2 || m.Segments[0].Seq != 2 ||
		m.Segments[0].State != segmentlog.StatePruned || m.Segments[1].State != segmentlog.StateSealed {
		t.Errorf("after prune through 2 the manifest is %+v", m)
	}
}

// TestTheCollectorsDefaultsAreThePagesNumbers: the collector guide says a
// segment is sealed at 64 MiB and the log takes 1 GiB unless told, and a
// credential is 32 to 512 bytes.
func TestTheCollectorsDefaultsAreThePagesNumbers(t *testing.T) {
	if defaultSegmentBytes != 64<<20 || defaultMaxBytes != 1<<30 {
		t.Errorf("the defaults are %d and %d bytes, and the pages say 64 MiB and 1 GiB", defaultSegmentBytes, defaultMaxBytes)
	}
	if otel.MinCredentialBytes != 32 || otel.MaxCredentialBytes != 512 {
		t.Errorf("a credential is %d to %d bytes, and the pages say 32 to 512", otel.MinCredentialBytes, otel.MaxCredentialBytes)
	}
}
