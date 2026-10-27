//go:build ignore

// Command gen-reason-codes writes the reason-code reference page to disk.
//
//	go run scripts/gen-reason-codes.go                                     # stdout
//	go run scripts/gen-reason-codes.go -o docs/reference/reason-codes.md   # file
//
// Everything this program decides lives in internal/docscheck/reasondoc,
// which the gate compiles, vets, lints and tests. What is left here is argument
// handling and a write, so that a file the gate cannot see holds no logic that
// could be wrong.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/guardana/control/internal/docscheck/reasondoc"
)

func main() {
	out := flag.String("o", "", "write the page to this file instead of standard output")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}

	page, err := reasondoc.Page()
	if err != nil {
		fail(err)
	}
	if err := write(*out, page); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "gen-reason-codes: %v\n", err)
	os.Exit(1)
}

func write(path string, page []byte) error {
	if path == "" {
		if _, err := os.Stdout.Write(page); err != nil {
			return fmt.Errorf("writing to standard output: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(path, page, 0o644); err != nil { //nolint:gosec // G306: a tracked file, world-readable as a checkout writes it
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
