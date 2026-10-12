package enforce

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/pkg/contract"
)

// seedBodies adds every request body of the receiver cases, and a valid body
// of each operation.
func seedBodies(f *testing.F) {
	f.Add(uint8(0), []byte(`{"tool":"refund","arguments":"eyJhbW91bnQiOjV9","requestKey":"order-7","traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}`))
	f.Add(uint8(1), []byte(`{"handle":"0123456789abcdef0123456789abcdef","sentArguments":"e30=","status":"COMPLETION_STATUS_TIMEOUT","startedAt":"2026-10-11T12:00:01Z","resultHash":"sha256:9f86"}`))
	f.Add(uint8(2), []byte(`{"handle":"0123456789abcdef0123456789abcdef","cause":"ABORT_CAUSE_NOT_SENT"}`))
	names, err := filepath.Glob("../../testdata/enforce/receiver/*/exchange.jsonl")
	if err != nil || len(names) == 0 {
		f.Fatalf("no seed exchanges: %v", err)
	}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			f.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			var s struct {
				Post string          `json:"post"`
				Body json.RawMessage `json:"body"`
			}
			if json.Unmarshal(line, &s) == nil && s.Body != nil {
				for op := range uint8(3) {
					f.Add(op, []byte(s.Body))
				}
			}
		}
	}
}

// FuzzDecodeRequest holds the decoding of any body to three properties: it
// never panics; nothing over the body bound is read; and whatever is
// accepted is within every bound of its operation and decodes again, strictly,
// to the same message.
func FuzzDecodeRequest(f *testing.F) {
	seedBodies(f)
	f.Fuzz(func(t *testing.T, op uint8, body []byte) {
		if _, err := readBody(bytes.NewReader(body), MinBodyBytes); err == nil && len(body) > MinBodyBytes {
			t.Fatalf("%d bytes read past a bound of %d", len(body), MinBodyBytes)
		}
		m, err := decodeChecked(t, op, body)
		if err != nil {
			if !errors.Is(err, errMalformed) {
				t.Fatalf("refused with %v", err)
			}
			return
		}
		again := m.ProtoReflect().New().Interface()
		text, merr := protojson.Marshal(m)
		if merr != nil || unmarshal(text, again) != nil || !proto.Equal(m, again) {
			t.Fatalf("an accepted body does not decode again to itself: %s: %v", text, merr)
		}
	})
}

// decodeChecked decodes body as the operation op names and holds what it
// accepts to that operation's bounds.
func decodeChecked(t *testing.T, op uint8, body []byte) (proto.Message, error) {
	t.Helper()
	switch op % 3 {
	case 0:
		req, err := decodeAdmit(body)
		if err == nil {
			checkAdmit(t, req)
		}
		return req, err
	case 1:
		req, err := decodeComplete(body)
		if err == nil {
			checkComplete(t, req)
		}
		return req, err
	}
	req, err := decodeAbort(body)
	if err == nil && (req.GetHandle() == "" || !declared(req.GetCause()) || req.GetCause() == 0) {
		t.Fatalf("accepted %v", req)
	}
	return req, err
}

func checkAdmit(t *testing.T, req *enforcev1alpha1.AdmitRequest) {
	t.Helper()
	if req.GetTool() == "" || len(req.GetTool()) > contract.MaxStringBytes || len(req.GetArguments()) > contract.MaxArgumentsBytes ||
		len(req.GetTraceparent()) > contract.MaxStringBytes || !requestKey(req.GetRequestKey()) {
		t.Fatalf("accepted an admit out of bounds: %v", req)
	}
}

func checkComplete(t *testing.T, req *enforcev1alpha1.CompleteRequest) {
	t.Helper()
	if req.GetHandle() == "" || req.GetStatus() == 0 || !declared(req.GetStatus()) ||
		len(req.GetSentArguments()) == 0 || len(req.GetSentArguments()) > contract.MaxArgumentsBytes ||
		len(req.GetResultHash()) > contract.MaxStringBytes || len(req.GetSideEffectConfirmation()) > contract.MaxStringBytes {
		t.Fatalf("accepted a complete out of bounds: %v", req)
	}
}
