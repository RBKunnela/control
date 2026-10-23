package configdoc

import (
	"strings"
	"testing"

	"github.com/guardana/control/internal/docscheck/frontmatter"
	"github.com/guardana/control/internal/gatewayconfig"
)

// fixture is a table of three keys, one of each shape the renderer treats
// differently: a required enum, a plain key with a default, and an enum whose
// set holds the empty spelling. The variables are neutral: the page is
// rendered from whatever Env says, not from the product's prefix.
func fixture() []gatewayconfig.Field {
	return []gatewayconfig.Field{
		{Path: "mode", Env: "X_MODE", Kind: "one of", Default: "WATCH", Required: true, Values: []string{"WATCH", "STOP"}},
		{Path: "spool.max_bytes", Env: "X_SPOOL_MAX_BYTES", Kind: "bytes", Default: "1GiB"},
		{Path: "items.N.zone", Env: "X_ITEMS_N_ZONE", Kind: "one of", Values: []string{"", "INNER"}},
	}
}

// collections is a list and a map, in the order the page has to keep.
func collections() []gatewayconfig.Collection {
	return []gatewayconfig.Collection{
		{Path: "hosts.N", Env: "X_HOSTS_N", Holds: "one host"},
		{Path: "headers.<name>", Env: "X_HEADERS_<NAME>", Holds: "one header"},
	}
}

func TestPageHasOneRowPerFieldInOrder(t *testing.T) {
	page, err := render(fixture(), collections())
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	text := string(page)
	want := []string{
		"| `mode` | `X_MODE` | one of | `WATCH` | yes | `WATCH`, `STOP` |",
		"| `spool.max_bytes` | `X_SPOOL_MAX_BYTES` | bytes | `1GiB` | no |  |",
		"| `items.N.zone` | `X_ITEMS_N_ZONE` | one of |  | no | an empty value, `INNER` |",
		"| `hosts.N` | `X_HOSTS_N` | one host |",
		"| `headers.<name>` | `X_HEADERS_<NAME>` | one header |",
	}
	at := -1
	for _, row := range want {
		i := strings.Index(text, row+"\n")
		if i < 0 {
			t.Errorf("page has no row %q\n%s", row, text)
			continue
		}
		if i < at {
			t.Errorf("row %q comes before the row of the field listed before it", row)
		}
		at = i
	}
	if rows := strings.Count(text, "\n| `"); rows != len(want) {
		t.Errorf("page holds %d rows, want %d", rows, len(want))
	}
	if !strings.Contains(text, "\n# Configuration\n") {
		t.Error("page has no H1 spelling the title")
	}
}

func TestPageCarriesTheFrontmatterTheCheckReads(t *testing.T) {
	page, err := render(fixture(), collections())
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	meta, body, err := frontmatter.Parse(page)
	if err != nil {
		t.Fatalf("the page does not parse: %v", err)
	}
	if meta.Title != "Configuration" || meta.Type != "reference" || meta.Generated != Generator {
		t.Errorf("frontmatter is %+v", meta)
	}
	if len(meta.Covers) != 3 || meta.Covers[0] != "internal/gatewayconfig/**" || meta.Covers[1] != "internal/classify/**" {
		t.Errorf("covers is %q, want the loader, the classification and the command", meta.Covers)
	}
	if !strings.HasPrefix(string(body), "\n# Configuration\n") {
		t.Errorf("the body does not start with the H1: %q", body[:min(len(body), 40)])
	}
}

func TestPageRefusals(t *testing.T) {
	twice := append(fixture(), fixture()[0])
	pipe := fixture()
	pipe[1].Default = "1|2"
	backtick := fixture()
	backtick[0].Values[1] = "STOP`"
	control := fixture()
	control[0].Env = "X_\tMODE"
	noKind := fixture()
	noKind[2].Kind = ""
	for name, fields := range map[string][]gatewayconfig.Field{
		"an empty table":           nil,
		"a key listed twice":       twice,
		"a pipe in a default":      pipe,
		"a backtick in a value":    backtick,
		"a control character":      control,
		"a key with no kind":       noKind,
		"a key with an empty path": {{Env: "X", Kind: "string"}},
		"a key with no variable":   {{Path: "a", Kind: "string"}},
	} {
		t.Run(name, func(t *testing.T) {
			page, err := render(fields, collections())
			if err == nil {
				t.Fatalf("Page accepted %s:\n%s", name, page)
			}
			if page != nil {
				t.Errorf("Page returned %d bytes beside the error", len(page))
			}
		})
	}
}

func TestPageRefusesAListOrMapItCannotRender(t *testing.T) {
	scalarAgain := append(collections(), gatewayconfig.Collection{Path: "mode", Env: "X_MODE", Holds: "a mode"})
	twice := append(collections(), collections()[0])
	pipe := collections()
	pipe[0].Holds = "one host | or two"
	noHolds := collections()
	noHolds[1].Holds = ""
	noEnv := collections()
	noEnv[0].Env = ""
	for name, lists := range map[string][]gatewayconfig.Collection{
		"no list or map":                   nil,
		"a list that is also a scalar key": scalarAgain,
		"a list listed twice":              twice,
		"a pipe in what it holds":          pipe,
		"a map that says nothing it holds": noHolds,
		"a list with no variable":          noEnv,
	} {
		t.Run(name, func(t *testing.T) {
			page, err := render(fixture(), lists)
			if err == nil {
				t.Fatalf("render accepted %s:\n%s", name, page)
			}
			if page != nil {
				t.Errorf("render returned %d bytes beside the error", len(page))
			}
		})
	}
}

// TestPageListsTheLoadersListsAndMaps: the page the generator writes carries
// a row for the decision point's list and map, which the loader binds and no
// prose names.
func TestPageListsTheLoadersListsAndMaps(t *testing.T) {
	page, err := Page(fixture())
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	for _, key := range []string{"| `pdp.informational_context.N` |", "| `pdp.headers.<name>` |", "| `export.headers.<name>` |"} {
		if !strings.Contains(string(page), "\n"+key) {
			t.Errorf("the page has no row starting %s", key)
		}
	}
}

func TestPageIsDeterministic(t *testing.T) {
	first, err := Page(fixture())
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	second, err := Page(fixture())
	if err != nil {
		t.Fatalf("Page, second call: %v", err)
	}
	if string(first) != string(second) {
		t.Error("two calls to Page produced different bytes")
	}
}

// TestTheListTimeoutRowSaysWhatItBounds: the list bound also bounds an
// upstream's connection at start, and its zero is the adapter's own bound.
func TestTheListTimeoutRowSaysWhatItBounds(t *testing.T) {
	page, err := Page(gatewayconfig.Fields())
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	const note = "| bounds reading one upstream's list, and connecting to each upstream at start; `0` is the adapter's own `30s` |"
	for _, line := range strings.Split(string(page), "\n") {
		if strings.HasPrefix(line, "| `upstream.list_timeout` |") {
			if !strings.HasSuffix(line, note) {
				t.Errorf("the row is %q, want it to end %q", line, note)
			}
			return
		}
	}
	t.Error("the page has no row for upstream.list_timeout")
}

// TestThePageSaysWhatTheSocketCheckLeavesOut: the plane judges the socket's
// directory by its mode bits alone, so the page names what that leaves out.
func TestThePageSaysWhatTheSocketCheckLeavesOut(t *testing.T) {
	page, err := Page(gatewayconfig.Fields())
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	text := strings.Join(strings.Fields(string(page)), " ")
	for _, want := range []string{
		"at most 103 bytes as it resolves",
		"checks neither a macOS access control list on it nor a parent directory another account may write",
		"`listener.max_open_per_run` is positive and below `approvals.max_open`",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the page does not say %q", want)
		}
	}
}
