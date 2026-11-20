package attempts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAReportIsANewFileWrittenLineByLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.jsonl")
	r, err := CreateReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Write(map[string]string{"line": "header"}); err != nil {
		t.Fatal(err)
	}
	// The line is on disk before the report is closed.
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own file
	if err != nil || string(raw) != "{\"line\":\"header\"}\n" {
		t.Errorf("after one line the file holds %q, %v", raw, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateReport(path); !errors.Is(err, ErrReport) || !errors.Is(err, os.ErrExist) {
		t.Errorf("a report over an existing file: %v, want %v and %v", err, ErrReport, os.ErrExist)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the report's mode: %v, %v", info, err)
	}
}

func TestTheAttemptLineRecordsWhatHappened(t *testing.T) {
	m := mustRead(t, []byte(validManifest))
	r := blockedOnEnforce(t, 1)
	r.Steps[0].Sent, r.Steps[0].Answer, r.Steps[0].NotSent = false, "", "input missing: step[0] has no output"
	r.Steps = append(r.Steps, StepRun{Step: 2, Label: LabelOperator, Kind: "approve", NotRun: "step[0] was not answered with a pending approval"})
	r.Unfinished = "closing the session: EOF"
	raw, err := json.Marshal(LineOf("../scenarios/deny.json", Evaluate(m, r)))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"line":"attempt","attempt":"deny","scenario":"../scenarios/deny.json","plane":"enforce","repetition":1,"started":true,` +
		`"policy_digest":"sha256:x","unfinished":"closing the session: EOF","steps":[` +
		`{"step":0,"label":"attack","kind":"call","tool":"refund","sent":false,"not_sent":"input missing: step[0] has no output","agreement":"not sent"},` +
		`{"step":1,"label":"legitimate","kind":"call","tool":"read_order","sent":true,"answer":{"kind":"result","codes":[]},"agreement":"agrees","outcome":"completed"},` +
		`{"step":2,"label":"operator","kind":"approve","ran":false,"not_run":"step[0] was not answered with a pending approval"}],` +
		`"effects":[{"effect":"refund","at_victim":"absent, not sent","why":"step 0 was not sent: input missing: step[0] has no output"}]}`
	if string(raw) != want {
		t.Errorf("the line is\n%s\nwant\n%s", raw, want)
	}
}

func TestTheCorpusDigestIsOfSortedLines(t *testing.T) {
	files := []FileDigest{{Path: "b.json", SHA256: "22"}, {Path: "a.json", SHA256: "11"}}
	sum := sha256.Sum256([]byte("a.json 11\nb.json 22\n"))
	if got, want := CorpusDigest(files), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("corpus digest %s, want %s", got, want)
	}
	if CorpusDigest(files) != CorpusDigest([]FileDigest{files[1], files[0]}) {
		t.Error("the digest depends on the order the files are named in")
	}
	if CorpusDigest(files) == CorpusDigest([]FileDigest{{Path: "b.json", SHA256: "22"}, {Path: "a.json", SHA256: "12"}}) {
		t.Error("a file's digest changed and the corpus digest did not")
	}
	if !strings.HasPrefix(Digest([]byte("")), "e3b0c442") {
		t.Errorf("the digest of nothing is %s", Digest(nil))
	}
}
