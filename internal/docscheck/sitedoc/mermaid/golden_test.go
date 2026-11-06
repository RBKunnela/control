package mermaid

import (
	"bytes"
	"flag"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/*.html from this package's drawing")

var testdata = os.DirFS("testdata")

// Every golden is named here, so that deleting one fails the test instead of
// shrinking it.
var requiredGoldens = []string{
	"shapes", "edges", "chains", "classes", "subgraph", "direction-td", "direction-tb",
	"breaks", "long-edge", "pulled-source", "readme-1", "readme-2", "readme-3",
	"trap-round-half-even", "trap-escape", "trap-codepoints", "trap-compensated-sum",
	"trap-stable-sort", "trap-unicode-space", "trap-insertion-order", "wide-group-title",
}

func goldenInputs(t *testing.T) []string {
	t.Helper()
	inputs, err := fs.Glob(testdata, "*.mmd")
	if err != nil {
		t.Fatalf("listing testdata: %v", err)
	}
	for _, name := range requiredGoldens {
		if _, err := fs.Stat(testdata, name+".mmd"); err != nil {
			t.Errorf("golden input %s: %v", name, err)
		}
	}
	if len(inputs) < len(requiredGoldens) {
		t.Fatalf("found %d golden inputs, want at least %d", len(inputs), len(requiredGoldens))
	}
	return inputs
}

// readSource reads a file of testdata by its name there.
func readSource(t *testing.T, name string) string {
	t.Helper()
	data, err := fs.ReadFile(testdata, name)
	if err != nil {
		t.Fatalf("reading testdata/%s: %v", name, err)
	}
	return string(data)
}

func TestFiguresEqualTheGoldensByteForByte(t *testing.T) {
	for _, input := range goldenInputs(t) {
		name := strings.TrimSuffix(input, ".mmd")
		t.Run(name, func(t *testing.T) {
			got, err := Figure(readSource(t, input), 0)
			if err != nil {
				t.Fatalf("Figure: %v", err)
			}
			golden := name + ".html"
			if *update {
				if err := os.WriteFile(filepath.Join("testdata", golden), []byte(got), 0o600); err != nil {
					t.Fatalf("writing %s: %v", golden, err)
				}
				return
			}
			want := readSource(t, golden)
			if got != want {
				at := firstDifference(got, want)
				t.Errorf("drawing differs from testdata/%s at byte %d:\n got %q\nwant %q",
					golden, at, excerpt(got, at), excerpt(want, at))
			}
		})
	}
}

func TestEveryGoldenPageHasItsInput(t *testing.T) {
	pages, err := fs.Glob(testdata, "*.html")
	if err != nil {
		t.Fatalf("listing testdata: %v", err)
	}
	if len(pages) < len(requiredGoldens) {
		t.Fatalf("found %d golden pages, want at least %d", len(pages), len(requiredGoldens))
	}
	for _, page := range pages {
		if _, err := fs.Stat(testdata, strings.TrimSuffix(page, ".html")+".mmd"); err != nil {
			t.Errorf("golden page testdata/%s has no input: %v", page, err)
		}
	}
}

func firstDifference(a, b string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

func excerpt(s string, at int) string {
	return s[max(at-40, 0):min(at+40, len(s))]
}

// The figure's id joins the digest of the source to the index it is given, so
// two figures of one source on a page keep apart.
func TestFigureIDCarriesTheIndex(t *testing.T) {
	source := readSource(t, "shapes.mmd")
	for index, want := range map[int]string{0: `id="dgcab7c80"`, 12: `id="dgcab7c812"`, -1: `id="dgcab7c8-1"`} {
		got, err := Figure(source, index)
		if err != nil {
			t.Fatalf("Figure: %v", err)
		}
		if !strings.HasPrefix(got, `<figure class="dg" `+want+`>`) {
			t.Errorf("Figure(shapes, %d) starts %q, want the figure %s", index, got[:40], want)
		}
	}
}

// drawAll draws every golden input, in order, into one byte string.
func drawAll(t *testing.T) []byte {
	t.Helper()
	var all bytes.Buffer
	for _, input := range goldenInputs(t) {
		got, err := Figure(readSource(t, input), 0)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		all.WriteString(got)
		all.WriteByte(0)
	}
	return all.Bytes()
}

// Every range over a map starts at a random element, so a drawing that read
// one would change between these draws.
func TestTheSameSourceDrawsTheSameBytes(t *testing.T) {
	first := drawAll(t)
	for range 20 {
		if again := drawAll(t); !bytes.Equal(again, first) {
			t.Fatal("drawing the goldens again gave different bytes")
		}
	}
	out := filepath.Join(t.TempDir(), "drawn")
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperDrawsTheGoldens$", "-test.count=1") //nolint:gosec // G204: the test binary's own path and its own flags
	cmd.Env = append(os.Environ(), "MERMAID_DRAW_GOLDENS="+out)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("drawing in a fresh process: %v\n%s", err, output)
	}
	drawn, err := os.ReadFile(out) //nolint:gosec // G304: a path this test composed under its own temporary directory
	if err != nil {
		t.Fatalf("reading the fresh process's drawings: %v", err)
	}
	if !bytes.Equal(drawn, first) {
		t.Fatalf("a fresh process drew %d bytes, this one %d, and they differ", len(drawn), len(first))
	}
}

func TestHelperDrawsTheGoldens(t *testing.T) {
	out := os.Getenv("MERMAID_DRAW_GOLDENS")
	if out == "" {
		t.Skip("runs only as the fresh process of TestTheSameSourceDrawsTheSameBytes")
	}
	if err := os.WriteFile(out, drawAll(t), 0o600); err != nil {
		t.Fatalf("writing the drawings: %v", err)
	}
}
