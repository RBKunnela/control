package gateway_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/reasons"
)

// minted is every code the enforcement point spells, with the verdict it
// mints it under, written here as literals. registry_test.go in the reasons
// package pins each code's number and verdict; this holds the plane's use to
// that table.
var minted = map[string]controlv1.Verdict{
	codePaused:                  verdictDeny,
	codePauseStateUnavailable:   verdictIndeterminate,
	codeRunStopped:              verdictDeny,
	codeStopStateUnavailable:    verdictIndeterminate,
	codeLockdown:                verdictDeny,
	codeEvidenceUnavailable:     verdictIndeterminate,
	codeExecutedArgsMismatch:    verdictDeny,
	codeApprovalExpired:         verdictDeny,
	codeApprovalRejected:        verdictDeny,
	codeApprovalAlreadyUsed:     verdictDeny,
	codeApprovalNotResumed:      verdictDeny,
	codeApprovalStateUnknown:    verdictIndeterminate,
	codeObligationNotUnderstood: verdictDeny,
	codeInvalidFieldValue:       verdictIndeterminate,
	codeActionUnclassified:      verdictIndeterminate,
	codeApprovalDigestMismatch:  verdictDeny,
	codeApprovalBundleMismatch:  verdictDeny,
	codeExecutionAbandoned:      verdictIndeterminate,
	codePolicyStale:             verdictIndeterminate,
}

// abortCodes is the code each abort cause is recorded as, typed from the
// registry page.
var abortCodes = map[gateway.AbortCause]string{
	gateway.AbortArgsMismatch:   codeExecutedArgsMismatch,
	gateway.AbortObligation:     codeObligationNotUnderstood,
	gateway.AbortUnroutable:     codeActionUnclassified,
	gateway.AbortUntranslatable: codeInvalidFieldValue,
	gateway.AbortCancelled:      codeEvidenceUnavailable,
}

// TestEveryAbortCauseIsRecordedAsItsRegisteredCode: each declared cause
// closes the trail with its own code in tool_protocol_status, and the code is
// in the registry. The table above is typed from the registry page, so a
// cause recorded as another cause's code fails here.
func TestEveryAbortCauseIsRecordedAsItsRegisteredCode(t *testing.T) {
	for cause, code := range abortCodes {
		if _, ok := reasons.Lookup(code); !ok {
			t.Errorf("abort cause %d is recorded as %s, which is not in the registry", cause, code)
		}
		h := build(t, modeEnforce, snapshot(t, allowWrites))
		d := h.admit(writeEnvelope(), []byte(`{}`))
		if err := h.p.Abort(context.Background(), d, cause); err != nil {
			t.Fatalf("Abort with cause %d: %v", cause, err)
		}
		events := h.events()
		closing := events[len(events)-1].GetResult()
		if closing.GetToolProtocolStatus() != code {
			t.Errorf("abort cause %d is recorded as %q, want %s", cause, closing.GetToolProtocolStatus(), code)
		}
	}
}

// TestTheAbortCausesAreExactlyTheTable: the causes this build declares are
// the ones the table above types out, one number each from one upwards, and
// nothing outside them aborts an execution. A cause added to the set without
// its entry here is the number past the table, and it is refused.
func TestTheAbortCausesAreExactlyTheTable(t *testing.T) {
	// The causes are numbered from one, so the number past the table is one
	// no build with this table declares.
	beyond := gateway.AbortArgsMismatch
	for range abortCodes {
		beyond++
	}
	for _, cause := range []gateway.AbortCause{0, beyond} {
		h := build(t, modeEnforce, snapshot(t, allowWrites))
		d := h.admit(writeEnvelope(), []byte(`{}`))
		if err := h.p.Abort(context.Background(), d, cause); !errors.Is(err, gateway.ErrAbortCause) {
			t.Errorf("Abort with cause %d = %v, want ErrAbortCause", cause, err)
		}
		// The execution is left open for a cause that is in the set.
		if err := h.p.Abort(context.Background(), d, gateway.AbortObligation); err != nil {
			t.Errorf("Abort after a refused cause: %v", err)
		}
	}
	for cause := gateway.AbortArgsMismatch; cause < beyond; cause++ {
		if _, ok := abortCodes[cause]; !ok {
			t.Errorf("cause %d is declared and the table names no code for it", cause)
		}
	}
}

// TestNoRuleMaySpellThePlaneCodes: a bundle cannot dress a denial of its own
// as an operator's pause or a run's stop, or as a pause or stop state the
// plane could not read.
func TestNoRuleMaySpellThePlaneCodes(t *testing.T) {
	for _, code := range []string{codePaused, codePauseStateUnavailable, codeRunStopped, codeStopStateUnavailable} {
		for _, effect := range []string{"DENY", "ALLOW"} {
			rule := `{"id":"r","effect":"` + effect + `","reason":"` + code + `","when":{"action":{"effect":["WRITE"]}}}`
			if _, err := policy.Sign(document(rule), key(), "k1"); err == nil {
				t.Errorf("a %s rule naming %s was signed", effect, code)
			}
		}
	}
	// The same rule naming a code a rule may use is signed, so the refusal
	// above is about the code.
	if _, err := policy.Sign(document(`{"id":"r","effect":"DENY","reason":"OUT_OF_SCOPE_ACTION","when":{"action":{"effect":["WRITE"]}}}`), key(), "k1"); err != nil {
		t.Errorf("a rule naming a code rules may use: %v", err)
	}
}

// TestSourceSpellsOnlyRegisteredCodes reads the production source for every
// string literal shaped like a reason code: each is registered, carries the
// registry's verdict in the table above, and the table names nothing the
// source does not spell.
func TestSourceSpellsOnlyRegisteredCodes(t *testing.T) {
	found := codeLiterals(t)
	var covered []string
	for code := range minted {
		covered = append(covered, code)
	}
	slices.Sort(covered)
	if !slices.Equal(found, covered) {
		t.Errorf("the source spells %q and the table covers %q", found, covered)
	}
	for code, verdict := range minted {
		registered, ok := reasons.Lookup(code)
		if !ok {
			t.Errorf("%s is not in the registry", code)
			continue
		}
		if registered.Verdict != verdict {
			t.Errorf("%s is minted with %s and registered with %s", code, verdict, registered.Verdict)
		}
	}
}

// TestTheKernelSpellsNoStopCode: the kernel's production source, which spells
// every code it emits as a literal, spells neither stop code, so only the
// plane names a stop.
func TestTheKernelSpellsNoStopCode(t *testing.T) {
	kernel := codeLiteralsIn(t, filepath.Join("..", "core"))
	if !slices.Contains(kernel, codePolicyUnavailable) {
		t.Fatalf("the kernel's source spells %q and not POLICY_UNAVAILABLE; the wrong source was examined", kernel)
	}
	for _, code := range []string{codeRunStopped, codeStopStateUnavailable} {
		if slices.Contains(kernel, code) {
			t.Errorf("the kernel's source spells %s", code)
		}
	}
}

// codeLiterals returns, sorted and once each, every string literal in the
// production files that is all capitals: the shape of a reason code.
func codeLiterals(t *testing.T) []string {
	t.Helper()
	return codeLiteralsIn(t, ".")
}

// codeLiteralsIn is codeLiterals over the production files of dir.
func codeLiteralsIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	var found []string
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files++
		found = append(found, literalsIn(t, filepath.Join(dir, name))...)
	}
	if files < 5 || len(found) == 0 {
		t.Fatalf("read %d production file(s) and found %d code literal(s); the source was not examined", files, len(found))
	}
	slices.Sort(found)
	return slices.Compact(found)
}

var codeShaped = regexp.MustCompile(`^[A-Z][A-Z0-9_]{3,}$`)

func literalsIn(t *testing.T, name string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil && codeShaped.MatchString(s) {
				found = append(found, s)
			}
		}
		return true
	})
	return found
}
