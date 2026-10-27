//go:build ignore

// Command gen-wire writes the reference page of one file of the wire contract
// to disk.
//
//	go run scripts/gen-wire.go common.proto                                   # stdout
//	go run scripts/gen-wire.go -o docs/reference/wire/common.md common.proto  # file
//
// Everything this program decides lives in internal/docscheck/wiredoc, which
// the gate compiles, vets, lints and tests. What is left here is argument
// handling and a write. A page written with -o has to be named as the
// renderer names it, so a recipe line cannot put one file's page under
// another file's name.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/guardana/control/internal/docscheck/wiredoc"
)

func main() {
	out := flag.String("o", "", "write the page to this file instead of standard output")
	flag.Parse()
	if flag.NArg() != 1 {
		fail(fmt.Errorf("want exactly one argument, the proto file's base name, got %d", flag.NArg()))
	}
	fd, err := wiredoc.Find(flag.Arg(0))
	if err != nil {
		fail(err)
	}
	if *out != "" && filepath.Base(*out) != wiredoc.PageName(fd) {
		fail(fmt.Errorf("%s is not the page of %s, which is %s", *out, flag.Arg(0), wiredoc.PageName(fd)))
	}
	page, err := wiredoc.Page(fd)
	if err != nil {
		fail(err)
	}
	if err := write(*out, page); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "gen-wire: %v\n", err)
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
