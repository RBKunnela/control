//go:build ignore

// Command gen-config writes the configuration reference page to disk.
//
//	go run scripts/gen-config.go                                       # stdout
//	go run scripts/gen-config.go -o docs/reference/configuration.md    # file
//
// Everything this program decides lives in internal/docscheck/configdoc and
// the field table in internal/gatewayconfig, which the gate compiles, vets,
// lints and tests. What is left here is argument handling and a write.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/guardana/control/internal/docscheck/configdoc"
	"github.com/guardana/control/internal/gatewayconfig"
)

func main() {
	out := flag.String("o", "", "write the page to this file instead of standard output")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}
	page, err := configdoc.Page(gatewayconfig.Fields())
	if err != nil {
		fail(err)
	}
	if err := write(*out, page); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "gen-config: %v\n", err)
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
