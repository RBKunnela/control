package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"

	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/internal/policy/rules"
)

// maxReadBytes bounds what a command reads from one file. It sits above the
// parser's 1 MiB document bound, and above a case that holds such a document
// beside the largest envelope and arguments the contract accepts, so an
// over-long document meets the parser's own refusal and this program holds no
// second copy of that bound.
const maxReadBytes = 2 << 20

// lint parses, validates and compiles the document at path, the checks Load
// runs on the signed bytes minus the signature, and holds its obligation
// parameters to the catalogue as Sign does. It returns 0 when the document
// would sign and load, or 1 with the first refusal on stderr, on one line. The
// promise runs one way: Load does not check parameters, so a document lint
// refuses for one can still load from a bundle signed elsewhere. Each check
// returns its first refusal in document order, so an author fixes one per run.
func lint(path string, stderr io.Writer) int {
	raw, err := readBounded(path)
	if err != nil {
		return fail(stderr, "policy lint", err)
	}
	doc, _, err := rules.Parse(raw)
	if err != nil {
		return fail(stderr, "policy lint", err)
	}
	if err := rules.CheckObligations(doc); err != nil {
		return fail(stderr, "policy lint", err)
	}
	// Compile refuses nothing Parse accepted today; it runs because Load runs
	// it, and a document that lints has to load.
	if _, err := match.Compile(doc); err != nil {
		return fail(stderr, "policy lint", err)
	}
	return exitOK
}

// readBounded reads a regular file of at most maxReadBytes, judged from its
// opened descriptor, so a named pipe is refused rather than waited on. A
// refusal names the path once.
func readBounded(path string) ([]byte, error) {
	raw, err := ondisk.ReadRegular(path, maxReadBytes, 0)
	var pathErr *fs.PathError
	if err != nil && !errors.As(err, &pathErr) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return raw, err
}
