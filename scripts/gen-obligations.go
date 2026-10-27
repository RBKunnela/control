//go:build ignore

// Command gen-obligations writes the obligation reference page to disk.
//
//	go run scripts/gen-obligations.go                                    # stdout
//	go run scripts/gen-obligations.go -o docs/reference/obligations.md   # file
//
// Everything this program decides lives in internal/docscheck/obligationdoc,
// which the gate compiles, vets, lints and tests. What is left here is
// argument handling and a write; the catalogue comes from rules.Obligations
// and who applies each type from obligationdoc.Appliers.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/guardana/control/internal/docscheck/obligationdoc"
	"github.com/guardana/control/internal/policy/rules"
)

func main() {
	out := flag.String("o", "", "write the page to this file instead of standard output")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}

	page, err := obligationdoc.Page(rules.Obligations(), obligationdoc.Appliers())
	if err != nil {
		fail(err)
	}
	if err := write(*out, page); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "gen-obligations: %v\n", err)
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
