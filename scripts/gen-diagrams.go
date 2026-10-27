//go:build ignore

// Command gen-diagrams rewrites the generated block of one concept page.
//
//	go run scripts/gen-diagrams.go -o docs/concepts/enforcement-modes.md
//
// The page names which block it holds through internal/docscheck/diagramdoc,
// where everything this program decides lives and where the gate compiles,
// vets, lints and tests it. What is left here is argument handling, a read of
// the page and a write of the same page with its block replaced.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/guardana/control/internal/docscheck/diagramdoc"
)

func main() {
	out := flag.String("o", "", "the page whose block is rewritten in place (required)")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}
	if *out == "" {
		fail(errors.New("-o names the page; a block is not rendered on its own"))
	}
	name, ok := diagramdoc.Pages[*out]
	if !ok {
		fail(fmt.Errorf("%s holds no generated block this program knows", *out))
	}
	page, err := os.ReadFile(*out)
	if err != nil {
		fail(fmt.Errorf("reading %s: %w", *out, err))
	}
	block, err := diagramdoc.Render(name)
	if err != nil {
		fail(err)
	}
	spliced, err := diagramdoc.Splice(page, block)
	if err != nil {
		fail(fmt.Errorf("%s: %w", *out, err))
	}
	if err := os.WriteFile(*out, spliced, 0o644); err != nil { //nolint:gosec // G306: a tracked file, world-readable as a checkout writes it
		fail(fmt.Errorf("writing %s: %w", *out, err))
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "gen-diagrams: %v\n", err)
	os.Exit(1)
}
