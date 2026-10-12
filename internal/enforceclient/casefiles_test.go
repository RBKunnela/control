package enforceclient_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/guardana/control/internal/enforceclient"
)

const casesDir = "../../testdata/enforce"

// caller is one client under test, bound to a receiver's socket and a token.
type caller func(ctx context.Context, tool string, args []byte, exec enforceclient.Exec) (enforceclient.Answer, error)

type newCaller func(t *testing.T, socket, token string) caller

type caseEntry struct {
	ID              string `json:"id"`
	Side            string `json:"side"`
	Contract        string `json:"contract"`
	Rule            string `json:"rule"`
	NegativeControl struct {
		Defect string `json:"defect"`
		Breaks string `json:"breaks"`
	} `json:"negative_control"`
}

type callFile struct {
	Tool       string   `json:"tool"`
	Arguments  string   `json:"arguments"`
	RunToken   string   `json:"run_token"`
	DeadlineMS int      `json:"deadline_ms"`
	ToolDoes   toolDoes `json:"tool_does"`
}

type toolDoes struct {
	Status                 string `json:"status"`
	StartedAt              string `json:"started_at"`
	EndedAt                string `json:"ended_at"`
	ResultHash             string `json:"result_hash"`
	SideEffectConfirmation string `json:"side_effect_confirmation"`
	Error                  string `json:"error"`
	CancelCaller           bool   `json:"cancel_caller"`
}

type scripted struct {
	For    string          `json:"for"`
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	Raw    *string         `json:"raw"`
	Then   string          `json:"then"`
}

type expectFile struct {
	ToolReached      bool            `json:"tool_reached"`
	ToolReceived     *string         `json:"tool_received"`
	Requests         []expectRequest `json:"requests"`
	AbortCause       string          `json:"abort_cause"`
	CompletionStatus string          `json:"completion_status"`
	Returns          returns         `json:"returns"`
}

type expectRequest struct {
	Path string         `json:"path"`
	Body map[string]any `json:"body"`
}

type returns struct {
	Error      string `json:"error"`
	Code       string `json:"code"`
	Ending     string `json:"ending"`
	ApprovalID string `json:"approval_id"`
	RetryAfter string `json:"retry_after"`
}

func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func readJSON(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	if err := strictJSON(data, v); err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}
}

func loadCases(t *testing.T) []caseEntry {
	t.Helper()
	var file struct {
		Cases []caseEntry `json:"cases"`
	}
	readJSON(t, filepath.Join(casesDir, "cases.json"), &file)
	var out []caseEntry
	for _, c := range file.Cases {
		switch c.Side {
		case "client":
			out = append(out, c)
		case "receiver":
		default:
			t.Fatalf("cases.json: %s has side %q, not client or receiver", c.ID, c.Side)
		}
	}
	if len(out) == 0 {
		t.Fatal("cases.json lists no client case")
	}
	return out
}

func loadAnswers(t *testing.T, dir string) []scripted {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "answers.jsonl")))
	if err != nil {
		t.Fatalf("reading answers: %v", err)
	}
	var out []scripted
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		var a scripted
		if err := strictJSON(line, &a); err != nil {
			t.Fatalf("%s answer %d: %v", dir, i+1, err)
		}
		if (a.Raw == nil) == (a.Body == nil) || a.Status == 0 || a.For == "" {
			t.Fatalf("%s answer %d: needs for, status and exactly one of body and raw", dir, i+1)
		}
		if !slices.Contains([]string{"", "cancel_caller", "await_caller"}, a.Then) {
			t.Fatalf("%s answer %d: then %q", dir, i+1, a.Then)
		}
		out = append(out, a)
	}
	return out
}
