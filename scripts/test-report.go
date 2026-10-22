//go:build ignore

// Command test-report reads `go test -json` on standard input and writes each
// passing package's result line; for a failing one, its own lines and the
// output of each test that failed; then every skipped test and the skip count,
// so that a skip is visible in the gate's output.
//
//	go test -json ./... | go run scripts/test-report.go
//
// Run it from the root module's directory: the packages of that module under
// api/gen/, which is generated code, are the only ones that may have no test
// files, and its go.mod names them.
//
// Everything this program decides lives in internal/testreport, which the gate
// compiles, vets, lints and tests. It exits 1 on anything that does not prove a
// pass, an empty or unreadable stream among them; the go test it reads from
// keeps its own exit status, which a pipeline under pipefail does not lose.
package main

import (
	"fmt"
	"os"

	"github.com/guardana/control/internal/testreport"
)

func main() {
	if len(os.Args) > 1 {
		fail(fmt.Errorf("unexpected argument %q", os.Args[1]))
	}
	gomod, err := os.ReadFile("go.mod")
	if err != nil {
		fail(fmt.Errorf("reading the root module's go.mod: %w", err))
	}
	generated, err := testreport.GeneratedPrefix(gomod)
	if err != nil {
		fail(err)
	}
	if _, err := testreport.Summarize(os.Stdin, os.Stdout, generated); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "test-report: %v\n", err)
	os.Exit(1)
}
