package diagramdoc_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/docscheck/diagramdoc"
	"github.com/guardana/control/internal/docscheck/frontmatter"
)

func TestRenderRefusesAnUnknownName(t *testing.T) {
	if out, err := diagramdoc.Render("spool"); !errors.Is(err, diagramdoc.ErrBlock) {
		t.Errorf("Render(spool) = %q, %v", out, err)
	}
	for _, name := range diagramdoc.Pages {
		if _, err := diagramdoc.Render(name); err != nil {
			t.Errorf("Render(%s): %v", name, err)
		}
	}
}

const (
	opening = frontmatter.GeneratedOpen + diagramdoc.Script + " -->\n"
	closing = frontmatter.GeneratedClose + "\n"
)

func TestSpliceReplacesTheOneBlock(t *testing.T) {
	page := "# T\n\nlead\n\n" + opening + "old\n" + closing + "\ntail\n"
	got, err := diagramdoc.Splice([]byte(page), []byte("new\nlines\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "# T\n\nlead\n\n" + opening + "new\nlines\n" + closing + "\ntail\n"; string(got) != want {
		t.Errorf("Splice =\n%s\nwant\n%s", got, want)
	}
	for name, page := range map[string]string{
		"no block":               "# T\n\nlead\n",
		"two blocks":             opening + "a\n" + closing + opening + "b\n" + closing,
		"unclosed":               opening + "a\n",
		"another script's block": frontmatter.GeneratedOpen + "scripts/gen-index.go -->\na\n" + closing,
	} {
		if out, err := diagramdoc.Splice([]byte(page), []byte("x\n")); !errors.Is(err, diagramdoc.ErrBlock) {
			t.Errorf("%s: Splice = %q, %v", name, out, err)
		}
	}
}

// The rows ADR-0013 and the status page state: four modes run, two are
// planned, and the zero value and an undeclared number are refused.
func TestModeTableNamesTheRecordsRows(t *testing.T) {
	out, err := diagramdoc.Render("modes")
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{
		"| `OBSERVE` | observe the request, observe the result | runs |",
		"| `SHADOW` | observe the request, observe the result, cooperative or inline enforcement | planned: refused at start |",
		"| `WARN` | observe the request, observe the result | planned: refused at start |",
		"| `APPROVE` | observe the request, observe the result, cooperative or inline enforcement | runs |",
		"| `ENFORCE` | observe the request, observe the result, cooperative or inline enforcement | runs |",
		"| `LOCKDOWN` | observe the request, observe the result, cooperative or inline enforcement | runs |",
		"| `UNSPECIFIED` | nothing: refused as configuration | refused at start |",
		"| a number no build declares | nothing: refused as configuration | refused at start |",
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("the mode table lacks the row %q:\n%s", want, text)
		}
	}
	if rows := strings.Count(text, "\n| `"); rows != 7 {
		t.Errorf("%d mode rows, want 7 (six declared modes and the zero value)", rows)
	}
}

// The table ADR-0012 states, typed here: every material or undeclared effect
// blocks under every input; a READ blocks on a cause in the request, on an
// unavailable policy, with the setting off, and with a snapshot whose
// determinate verdict is not ALLOW; it runs with the setting on and no
// snapshot, or a snapshot that allows.
func TestFailClosedTableIsTheRecordsRule(t *testing.T) {
	out, err := diagramdoc.Render("fail-closed")
	if err != nil {
		t.Fatal(err)
	}
	want := "| Effect class | a cause in the request | the policy available | fail-open reads on | a snapshot present | the determinate verdict | Action |\n" +
		"| --- | --- | --- | --- | --- | --- | --- |\n" +
		"| `UNSPECIFIED`, `WRITE`, `DELETE`, `EXECUTE`, `COMMUNICATE`, `TRANSACT`, `IDENTITY_OR_ACCESS`, `CONFIGURE`, `SPAWN_OR_DELEGATE`, a number no build declares | any | any | any | any | any | blocks |\n" +
		"| `READ` | no | no | any | any | any | blocks |\n" +
		"| `READ` | no | yes | no | any | any | blocks |\n" +
		"| `READ` | no | yes | yes | no | any | runs, recorded as a fail-open read |\n" +
		"| `READ` | no | yes | yes | yes | `UNSPECIFIED` or `DENY` or `REQUIRE_APPROVAL` or `ALLOW_WITH_OBLIGATIONS` or `INDETERMINATE` | blocks |\n" +
		"| `READ` | no | yes | yes | yes | `ALLOW` | runs, recorded as a fail-open read |\n" +
		"| `READ` | yes | any | any | any | any | blocks |\n"
	if string(out) != want {
		t.Errorf("fail-closed table =\n%s\nwant\n%s", out, want)
	}
}

// The edges ADR-0013 and the chain rest on, typed here, and nothing else
// moves the trail; the two kinds that leave it in place are stated; the
// diagram stays within the page rule's fifteen nodes.
func TestChainDiagramDrawsTheRecordsEdges(t *testing.T) {
	out, err := diagramdoc.Render("chain")
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	edges := []string{
		"[*] --> proposed: ACTION_PROPOSED",
		"proposed --> decided: POLICY_DECIDED",
		"decided --> requested: APPROVAL_REQUESTED",
		"decided --> started: ACTION_STARTED",
		"decided --> closed: ACTION_BLOCKED",
		"requested --> approved: APPROVAL_DECIDED",
		"requested --> expired: APPROVAL_EXPIRED",
		"approved --> started: ACTION_STARTED",
		"approved --> closed: ACTION_BLOCKED",
		"expired --> requested: APPROVAL_REQUESTED",
		"expired --> closed: ACTION_BLOCKED",
		"started --> closed: ACTION_COMPLETED",
		"started --> closed: ACTION_FAILED",
	}
	for _, edge := range edges {
		if !strings.Contains(text, "    "+edge+"\n") {
			t.Errorf("the diagram lacks %q", edge)
		}
	}
	if drawn := strings.Count(text, " --> "); drawn != len(edges) {
		t.Errorf("%d edges drawn, want %d:\n%s", drawn, len(edges), text)
	}
	for _, note := range []string{
		"`POLICY_RELOADED` leaves the trail where it is, from every state.",
		"`FINDING_RAISED` leaves the trail where it is, from every state but the start.",
	} {
		if !strings.Contains(text, note) {
			t.Errorf("the notes lack %q", note)
		}
	}
	if !strings.Contains(text, "```\n\nSources: `internal/trailchain/state.go`, `internal/trailchain/trailchain.go`, `internal/evidence/chainsteps.go`.\n") {
		t.Errorf("the Sources line does not follow the fence:\n%s", text)
	}
	if !strings.HasPrefix(text, "```mermaid\nstateDiagram-v2\n") {
		t.Errorf("the block is not a state diagram:\n%s", text)
	}
	nodes := drawnNodes(text)
	if len(nodes) == 0 || len(nodes) > 15 {
		t.Errorf("the diagram draws %d nodes %q, want between 1 and 15", len(nodes), nodes)
	}
}

// drawnNodes lists the distinct identifiers the rendered diagram's
// `A --> B: label` lines name, the pseudo state `[*]` aside: the page rule
// counts it as no node.
func drawnNodes(text string) []string {
	var nodes []string
	for _, line := range strings.Split(text, "\n") {
		from, rest, ok := strings.Cut(strings.TrimSpace(line), " --> ")
		if !ok {
			continue
		}
		to, _, _ := strings.Cut(rest, ":")
		for _, id := range []string{from, strings.TrimSpace(to)} {
			if id != "[*]" && !slices.Contains(nodes, id) {
				nodes = append(nodes, id)
			}
		}
	}
	return nodes
}

func TestDrawnNodesCountsEachIdentifierOnce(t *testing.T) {
	text := "```mermaid\nstateDiagram-v2\n    [*] --> a: X\n    a --> b: Y\n    b --> a: Z\n    a --> [*]\n```\n"
	if got := drawnNodes(text); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("drawnNodes = %q, want a and b once each", got)
	}
	if got := drawnNodes("```mermaid\nstateDiagram-v2\n```\n"); len(got) != 0 {
		t.Errorf("drawnNodes of no edge = %q, want nothing", got)
	}
}
