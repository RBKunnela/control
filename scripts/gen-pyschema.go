//go:build ignore

// Command gen-pyschema writes the table the Python client reads the
// enforcement API's answers by.
//
//	go run scripts/gen-pyschema.go                                                            # stdout
//	go run scripts/gen-pyschema.go -o clients/python/src/guardana_control/enforce/_schema.py  # file
//
// Everything this program decides lives in internal/docscheck/pyschema, which
// the gate compiles, vets, lints and tests. What is left here is argument
// handling and a write.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/guardana/control/internal/docscheck/pyschema"
)

func main() {
	out := flag.String("o", "", "write the table to this file instead of standard output")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}
	model, err := pyschema.Build(pyschema.Roots()...)
	if err != nil {
		fail(err)
	}
	table, err := pyschema.Python(model)
	if err != nil {
		fail(err)
	}
	if err := write(*out, table); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "gen-pyschema: %v\n", err)
	os.Exit(1)
}

func write(path string, table []byte) error {
	if path == "" {
		if _, err := os.Stdout.Write(table); err != nil {
			return fmt.Errorf("writing to standard output: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(path, table, 0o644); err != nil { //nolint:gosec // G306: a tracked file, world-readable as a checkout writes it
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
