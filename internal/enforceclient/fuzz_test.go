package enforceclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
)

// seedAnswers adds every scripted answer of the client cases.
func seedAnswers(f *testing.F) {
	names, err := filepath.Glob("../../testdata/enforce/client/*/answers.jsonl")
	if err != nil || len(names) == 0 {
		f.Fatalf("no seed answers: %v", err)
	}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			f.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			var a struct {
				Status int             `json:"status"`
				Body   json.RawMessage `json:"body"`
				Raw    string          `json:"raw"`
			}
			if err := json.Unmarshal(line, &a); err != nil {
				f.Fatal(err)
			}
			f.Add(a.Status, []byte(a.Body))
			f.Add(a.Status, []byte(a.Raw))
		}
	}
}

// FuzzDecodeAnswer holds the reading of any answer to two properties: a
// status other than 200 never reads as an answer, and nothing past the
// bound is read.
func FuzzDecodeAnswer(f *testing.F) {
	seedAnswers(f)
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		var resp enforcev1alpha1.AdmitResponse
		err := decodeAnswer(status, body, &resp)
		if err == nil && status != http.StatusOK {
			t.Fatalf("status %d read as an answer", status)
		}
		if err == nil && len(body) > MaxAnswerBytes {
			t.Fatalf("%d bytes read past the bound", len(body))
		}
		if err != nil && !errors.Is(err, ErrMalformedAnswer) && !errors.Is(err, ErrRefused) {
			t.Fatalf("an answer refused with %v", err)
		}
	})
}
