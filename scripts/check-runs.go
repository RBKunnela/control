//go:build ignore

// Command check-runs reads `go test -json` events on standard input and
// fails unless every test scripts/expected-runs.txt names passed in them.
// It is the verdict of the "Two accounts" job, whose tests run only where a
// second and a third account exist (ADR-0081), so a skip, a missing test,
// a failed build, an empty stream or an empty list each fail it: the job
// can never pass by running nothing.
//
//	go run scripts/check-runs.go <stream.jsonl
//
// Run it from the root module's directory. Everything it decides lives in
// internal/testreport (SummarizeRuns), which the gate compiles, vets, lints
// and tests.
package main

import (
	"fmt"
	"os"

	"github.com/guardana/control/internal/testreport"
)

const expectedRuns = "scripts/expected-runs.txt"

func main() {
	if len(os.Args) > 1 {
		fail(fmt.Errorf("unexpected argument %q", os.Args[1]))
	}
	list, err := os.ReadFile(expectedRuns)
	if err != nil {
		fail(fmt.Errorf("reading the expected runs: %w", err))
	}
	expected, err := testreport.ParseExpectedRuns(list)
	if err != nil {
		fail(fmt.Errorf("%s: %w", expectedRuns, err))
	}
	if _, err := testreport.SummarizeRuns(os.Stdin, os.Stdout, expected); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "check-runs: %v\n", err)
	os.Exit(1)
}
