package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
)

// The symbols the gateway's built binary must not hold, and those it must.
// It keeps no code that answers an approval, opens or closes a run, writes
// the pause file, makes or lowers a floor, or reads,
// parses or writes a private key: those are the approver's, run as another
// binary. It signs a bundle in memory for dev, so the signer is there. A name matches a symbol that is
// the name or starts with it and a dot, so a type's name covers its methods
// and a function's its closures.
var (
	gatewayRefuses = []string{
		brand.ModulePath + "/internal/approvals.(*Approver)",
		// Opening, closing and listing a run, and the record encoder with
		// them, are the operator's (ADR-0034).
		brand.ModulePath + "/internal/runs.(*Admin)",
		// OpenAdmin and InitAdmin are inlined where they are called; the
		// body they wrap is what a binary holds.
		brand.ModulePath + "/internal/runs.openAdmin",
		brand.ModulePath + "/internal/runs.(*dir).writeMarker",
		brand.ModulePath + "/internal/runs.(*dir).lockDir",
		brand.ModulePath + "/internal/pause.Init",
		brand.ModulePath + "/internal/pause.Add",
		brand.ModulePath + "/internal/pause.Remove",
		brand.ModulePath + "/internal/policykey.ReadPrivate",
		brand.ModulePath + "/internal/policykey.ParsePrivate",
		brand.ModulePath + "/internal/policykey.MarshalPrivate",
		// WriteKeyPair is inlined where it is called; the body it wraps is
		// what a binary holds.
		brand.ModulePath + "/internal/policykey.writeKeyPair",
		// Making a floor directory, giving a bundle id its floor file and
		// lowering a floor are the operator's (ADR-0038). Init and Reset are
		// the bodies that do it; writeMarker and onlyLeftovers are called by
		// Init alone.
		brand.ModulePath + "/internal/policystate.Init",
		brand.ModulePath + "/internal/policystate.Reset",
		brand.ModulePath + "/internal/policystate.(*dir).writeMarker",
		brand.ModulePath + "/internal/policystate.onlyLeftovers",
		// Making a route floor is the operator's too (ADR-0046); a plane
		// only reads and raises one.
		brand.ModulePath + "/internal/policystate.InitRoute",
		brand.ModulePath + "/internal/policystate.(*dir).claimRoute",
		brand.ModulePath + "/internal/policystate.(*dir).writeRouteMarker",
		// A route at a superseded rule version is read only as the source of
		// an operator's carry; a plane never accepts one.
		brand.ModulePath + "/internal/reaction.CheckCarrySource",
		brand.ModulePath + "/internal/reaction.VerifyCarrySource",
		brand.ModulePath + "/internal/reaction.JudgeCarrySource",
	}
	gatewayHolds = []string{
		brand.ModulePath + "/internal/approvals.(*Plane)",
		brand.ModulePath + "/internal/runs.(*Plane)",
		brand.ModulePath + "/internal/policykey.SignBundle",
		brand.ModulePath + "/internal/reaction.VerifyRoute",
		brand.ModulePath + "/internal/policystate.RaiseRoute",
		brand.ModulePath + "/internal/reaction/stoplist.(*Poller)",
	}
	// The standard library's private-key parsers, under the names a program
	// that calls them holds.
	stdlibKeyParsers = []string{
		"crypto/x509.ParsePKCS8PrivateKey",
		"crypto/x509.ParsePKCS1PrivateKey",
		// ParseECPrivateKey is inlined where it is called; the body it wraps
		// is what a binary holds.
		"crypto/x509.parseECPrivateKey",
		"crypto/tls.X509KeyPair",
		"crypto/tls.LoadX509KeyPair",
	}
)

// keyParserProbe is a program that calls every parser stdlibKeyParsers names.
const keyParserProbe = `package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func main() {
	der := []byte(os.Args[1])
	_, e1 := x509.ParsePKCS8PrivateKey(der)
	_, e2 := x509.ParsePKCS1PrivateKey(der)
	_, e3 := x509.ParseECPrivateKey(der)
	_, e4 := tls.X509KeyPair(der, der)
	_, e5 := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	fmt.Println(e1, e2, e3, e4, e5)
}
`

// TestTheGatewayBinaryHoldsNoStandardKeyParser: the gateway holds none of the
// standard library's private-key parsers, and a probe built to call each of
// them holds every one, so each name is one the listing shows.
func TestTheGatewayBinaryHoldsNoStandardKeyParser(t *testing.T) {
	t.Parallel()
	gatewayBin, _ := builtBinaries(t)
	if problems := judgeSymbols(symbolsOf(t, gatewayBin), stdlibKeyParsers, nil); len(problems) > 0 {
		t.Errorf("the gateway binary:\n%s", strings.Join(problems, "\n"))
	}
	dir := t.TempDir()
	for name, text := range map[string]string{"go.mod": "module keyparserprobe\n\ngo 1.21\n", "main.go": keyParserProbe} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	probe := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-o", probe, ".") //nolint:gosec // G204: the go tool building this test's own probe
	cmd.Dir, cmd.Env = dir, append(os.Environ(), "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the probe: %v\n%s", err, out)
	}
	if problems := judgeSymbols(symbolsOf(t, probe), nil, stdlibKeyParsers); len(problems) > 0 {
		t.Errorf("the probe that calls every parser:\n%s", strings.Join(problems, "\n"))
	}
}

// TestTheGatewayBinaryHoldsNoApproversCode reads the built binary's symbol
// table. A listing that holds none of the symbols the gateway must hold
// fails, so a table that could not be read is never a pass; and the
// approver's own binary, which holds what the gateway refuses, fails the
// same check.
func TestTheGatewayBinaryHoldsNoApproversCode(t *testing.T) {
	t.Parallel()
	gatewayBin, controlBin := builtBinaries(t)
	if problems := judgeSymbols(symbolsOf(t, gatewayBin), gatewayRefuses, gatewayHolds); len(problems) > 0 {
		t.Errorf("the gateway binary:\n%s", strings.Join(problems, "\n"))
	}
	problems := judgeSymbols(symbolsOf(t, controlBin), gatewayRefuses, gatewayHolds)
	for _, name := range gatewayRefuses {
		if !slices.Contains(problems, "holds "+name) {
			t.Errorf("the approver's binary passes the check for %s: %q", name, problems)
		}
	}
	if problems := judgeSymbols(nil, gatewayRefuses, gatewayHolds); len(problems) != len(gatewayHolds) {
		t.Errorf("an empty listing reads as %q", problems)
	}
}

// judgeSymbols names every refused name the listing holds and every held
// name it does not.
func judgeSymbols(symbols, refuses, holds []string) []string {
	matches := func(name string) bool {
		return slices.ContainsFunc(symbols, func(s string) bool { return s == name || strings.HasPrefix(s, name+".") })
	}
	var problems []string
	for _, name := range refuses {
		if matches(name) {
			problems = append(problems, "holds "+name)
		}
	}
	for _, name := range holds {
		if !matches(name) {
			problems = append(problems, "lacks "+name)
		}
	}
	return problems
}

// symbolsOf lists a binary's symbol names with the go tool's nm.
func symbolsOf(t *testing.T, bin string) []string {
	t.Helper()
	out, err := exec.Command("go", "tool", "nm", bin).Output() //nolint:gosec // G204: the go tool on a binary this test built
	if err != nil {
		t.Fatalf("go tool nm %s: %v", bin, err)
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if fields := strings.Fields(line); len(fields) >= 3 {
			names = append(names, strings.Join(fields[2:], " "))
		}
	}
	return names
}
