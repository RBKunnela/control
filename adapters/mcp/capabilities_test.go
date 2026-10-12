package mcp_test

import (
	"net/http"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/gateway"
)

// provenBy maps every capability and every obligation the adapter declares to
// the tests in this package that exercise it against the in-process upstream.
// ADR-0013 makes each declared capability's conformance test part of the seam:
// a capability the adapter declares with nothing exercising it is a documented
// capability that does not exist, so this table is what a new declaration has
// to be added to, and TestEveryDeclaredCapabilityIsProven refuses a
// declaration the table does not name and a table entry naming a test that is
// not here.
var provenBy = map[string][]string{
	"ObserveRequest":    {"TestAllowSendsTheAuthorizedBytes", "TestBlockNeverReachesUpstream"},
	"ObserveResult":     {"TestAllowSendsTheAuthorizedBytes", "TestUpstreamErrorPassesThrough"},
	"EnforcementInline": {"TestBlockNeverReachesUpstream", "TestZeroDispositionBlocks"},
	"Authenticates":     {"TestAuthenticatedListenerBindsTheUser", "TestAuthenticatorWithoutUserBlocks"},
	"BindEndUser":       {"TestAuthenticatedListenerBindsTheUser", "TestUnauthenticatedListenerDeclaresNoBinding"},
	"SeeResourceIDs":    {"TestResourceFromReadsTheResourceID"},
	"PresentsRuns":      {"TestRunTokenReachesTheAdmission", "TestRefusedRunTokenIsA401BeforeTheLibrary", "TestStdioResolvesEveryMessage"},

	"read_only":          {"TestReadOnlyObligation"},
	"restrict_resources": {"TestRestrictResourcesObligation"},
	"shorten_timeout":    {"TestShortenTimeoutObligation"},
	"deny_external_sink": {"TestDenyExternalSinkObligation"},
}

// TestEveryDeclaredCapabilityIsProven holds the table above to what the
// adapter declares, on a listener that authenticates, on one that does not and
// on one that resolves runs, so the capabilities only some declare are covered
// too.
func TestEveryDeclaredCapabilityIsProven(t *testing.T) {
	declared := declaredCapabilities(t)
	if len(declared) == 0 {
		t.Fatal("no capability was read from the adapter; nothing was examined")
	}
	tests := testFunctions(t)
	for _, name := range declared {
		proofs, ok := provenBy[name]
		if !ok || len(proofs) == 0 {
			t.Errorf("the adapter declares %s and no test in this package is named as its proof", name)
			continue
		}
		for _, proof := range proofs {
			if !slices.Contains(tests, proof) {
				t.Errorf("%s names %s as its proof and this package has no such test", name, proof)
			}
		}
	}
	for name := range provenBy {
		if !slices.Contains(declared, name) {
			t.Errorf("the table names %s, which the adapter does not declare", name)
		}
	}
}

// declaredCapabilities is the union of what the adapter declares on each kind
// of listener: every true flag of gateway.Capabilities by its field name, the
// enforcement it declares, plus every obligation by its type.
func declaredCapabilities(t *testing.T) []string {
	t.Helper()
	var out []string
	passThrough := func(next http.Handler) http.Handler { return next }
	for _, o := range []rigOptions{{}, {auth: passThrough}, {runs: &fakeRuns{}}} {
		caps := adapterFor(t, o).Capabilities()
		value := reflect.ValueOf(caps)
		for i := range value.NumField() {
			field := value.Type().Field(i)
			if field.Type.Kind() == reflect.Bool && value.Field(i).Bool() && !slices.Contains(out, field.Name) {
				out = append(out, field.Name)
			}
		}
		enforcement := map[gateway.Enforcement]string{
			gateway.EnforcementCooperative: "EnforcementCooperative", gateway.EnforcementInline: "EnforcementInline",
		}[caps.Enforcement]
		if enforcement != "" && !slices.Contains(out, enforcement) {
			out = append(out, enforcement)
		}
		for _, obligation := range caps.Obligations {
			if !slices.Contains(out, obligation) {
				out = append(out, obligation)
			}
		}
	}
	return out
}

// adapterFor builds an adapter that is never started: Capabilities is fixed at
// New, and what it declares is what the pipeline is refused or accepted on.
func adapterFor(t *testing.T, o rigOptions) *mcp.Adapter {
	t.Helper()
	v := newVictim()
	// Nothing is started, so the upstream transport is never connected;
	// Capabilities is fixed at New.
	upstream, _ := sdk.NewInMemoryTransports()
	a, err := mcp.New(newConfig(t, v, mcp.KindStatelessHTTP, upstream, o))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

var testName = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]*)\(`)

// testFunctions is every test this package declares, read from its own source,
// so a table entry naming a test that was renamed or deleted fails.
func testFunctions(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	var out []string
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		source, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		for _, match := range testName.FindAllSubmatch(source, -1) {
			out = append(out, string(match[1]))
		}
	}
	if len(out) == 0 {
		t.Fatal("no test function was found in this package's source; the search is broken")
	}
	return out
}
