//go:build ignore

// Command gen-site redraws the diagram slots of the site's landing page from
// the README's Mermaid blocks, writes the release docs/docs.json names as
// published into its release slot, and renders the documentation into site/docs/ with
// the sitemap.
//
//	go run scripts/gen-site.go -o site/index.html
//
// Everything it decides lives in internal/docscheck/sitedoc and its docsite
// package, where the gate compiles, vets, lints and tests it. What is left here
// is argument handling, reads, and the writes: site/docs/ is removed and
// written again whole, so a page whose source is gone goes with it.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/guardana/control/internal/docscheck/docsconfig"
	"github.com/guardana/control/internal/docscheck/impact"
	"github.com/guardana/control/internal/docscheck/sitedoc"
	"github.com/guardana/control/internal/docscheck/sitedoc/docsite"
)

const config = "docs/docs.json"

// inputs is everything the site is rendered from.
type inputs struct {
	page, readme, notes []byte
	cfg                 docsconfig.Config
	listed              []string
}

// site is everything the program writes: the landing page and the docs pages
// by path.
type site struct {
	page  []byte
	files map[string][]byte
}

func main() {
	out := flag.String("o", "", "the page whose slots are rewritten in place (required)")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}
	if *out == "" {
		fail(errors.New("-o names the page; a figure is not rendered on its own"))
	}
	if *out != sitedoc.Page {
		fail(fmt.Errorf("%s is not %s, the one page this program rewrites", *out, sitedoc.Page))
	}
	in, err := readInputs(*out)
	if err != nil {
		fail(err)
	}
	rendered, err := render(*out, in)
	if err != nil {
		fail(err)
	}
	if err := write(*out, rendered); err != nil {
		fail(err)
	}
}

func readInputs(out string) (inputs, error) {
	var in inputs
	var err error
	if in.page, err = readFile(out); err != nil {
		return in, err
	}
	if in.readme, err = readFile(sitedoc.Source); err != nil {
		return in, err
	}
	data, err := readFile(config)
	if err != nil {
		return in, err
	}
	if in.cfg, err = docsconfig.Parse(data); err != nil {
		return in, err
	}
	if in.notes, err = readFile(sitedoc.Changelog); err != nil {
		return in, err
	}
	listed, err := impact.RepositoryFiles(".", os.Environ())
	if err != nil {
		return in, err
	}
	in.listed = listed.Paths
	return in, nil
}

func readFile(name string) ([]byte, error) {
	data, err := os.ReadFile(name) //nolint:gosec // G304: the program's own fixed inputs and the one page -o may name
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	return data, nil
}

func render(out string, in inputs) (site, error) {
	rendered, err := sitedoc.Render(in.page, in.readme)
	if err != nil {
		return site{}, fmt.Errorf("%s: %w", out, err)
	}
	if err := sitedoc.Published(in.notes, in.cfg.Released); err != nil {
		return site{}, err
	}
	if rendered, err = sitedoc.FillRelease(rendered, in.cfg.Released); err != nil {
		return site{}, fmt.Errorf("%s: %w", out, err)
	}
	files, err := docsite.Build(os.DirFS("."), impact.LeftOut(in.listed, in.cfg.Excludes), in.cfg.Released)
	if err != nil {
		return site{}, err
	}
	return site{rendered, files}, nil
}

// write replaces the landing page, then removes the docs directory and writes
// every page again, so a page whose source is gone goes with it.
func write(out string, s site) error {
	if err := os.WriteFile(out, s.page, 0o644); err != nil { //nolint:gosec // G306: a tracked file, world-readable as a checkout writes it
		return fmt.Errorf("writing %s: %w", out, err)
	}
	if err := os.RemoveAll(docsite.Dir); err != nil {
		return fmt.Errorf("removing %s: %w", docsite.Dir, err)
	}
	names := make([]string, 0, len(s.files))
	for name := range s.files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil { //nolint:gosec // G301: a tracked directory, world-readable as a checkout makes it
			return err
		}
		if err := os.WriteFile(name, s.files[name], 0o644); err != nil { //nolint:gosec // G306: a tracked file, world-readable as a checkout writes it
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}
	return nil
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "gen-site: %v\n", err)
	os.Exit(1)
}
