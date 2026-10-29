package runview_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/runview"
	"github.com/guardana/control/internal/supervise"
)

var update = flag.Bool("update", false, "rewrite testdata/*.html from this package's drawing")

type scenario struct {
	name  string
	build func(*testing.T) (*supervise.Procedure, *supervise.Result)
	opt   runview.Options
}

// Every golden is named here, so deleting one fails instead of shrinking
// the test.
var goldens = []scenario{
	{"refund-0.1", refundRun, runview.Options{}},
	{"refund-0.1-all", refundRun, runview.Options{All: true}},
	{"tree-exception-taken", exceptionRun, runview.Options{All: true}},
	{"resource-outside-and-retry", strayRun, runview.Options{}},
}

func draw(t *testing.T, s scenario) string {
	t.Helper()
	p, res := s.build(t)
	page, err := runview.Page(p, res, s.opt)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	return string(page)
}

func TestPagesEqualTheGoldensByteForByte(t *testing.T) {
	for _, s := range goldens {
		t.Run(s.name, func(t *testing.T) {
			got := draw(t, s)
			path := filepath.Join("testdata", s.name+".html")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path) //nolint:gosec // G304: a golden of this package
			if err != nil {
				t.Fatalf("reading the golden: %v", err)
			}
			if got != string(want) {
				t.Errorf("the page differs from %s; rerun with -update and read the diff", path)
			}
		})
	}
}

// TestThePageIsAFunctionOfItsInput: two drawings of one result are the same
// bytes, so nothing on the page reads a clock or a map's order.
func TestThePageIsAFunctionOfItsInput(t *testing.T) {
	for _, s := range goldens {
		if a, b := draw(t, s), draw(t, s); a != b {
			t.Fatalf("%s: two drawings differ", s.name)
		}
	}
}

var (
	callRow   = regexp.MustCompile(`(?s)<tr class="call">.*?</tr>`)
	markLabel = regexp.MustCompile(`<span class="mk-label">([^<]*)</span>`)
	gapRow    = regexp.MustCompile(`<tr class="gap"><td colspan="9">([^<]*)</td></tr>`)
)

// marks is each drawn call's id and mark label, in the page's order, and
// the gaps between them as "gap: <text>".
func marks(page string) []string {
	var out []string
	rows := regexp.MustCompile(`(?s)<tr class="(?:call|gap)">.*?</tr>`).FindAllString(page, -1)
	for _, row := range rows {
		if g := gapRow.FindStringSubmatch(row); g != nil {
			out = append(out, "gap: "+g[1])
			continue
		}
		id := regexp.MustCompile(`<td class="id"><code>([^<]*)</code>`).FindStringSubmatch(row)
		label := markLabel.FindStringSubmatch(row)
		if id == nil || label == nil {
			out = append(out, "unreadable row")
			continue
		}
		out = append(out, id[1]+" "+label[1])
	}
	return out
}

func sameMarks(t *testing.T, name string, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s: drawn\n%s\nwant\n%s", name, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestEachCallIsMarkedFromItsData: a call a plane enforced, one decided by
// a plane that enforces nothing, one denied, one the plane blocked, a report
// with its source's trust, an approved call an exception took, and a step
// with no call.
func TestEachCallIsMarkedFromItsData(t *testing.T) {
	sameMarks(t, "refund, all", marks(draw(t, goldens[1])),
		"r1 enforced", "s1 decided, not enforced", "s2 decided, not enforced", "s3 decided, not enforced",
		"d1 blocked", "r2 enforced", "p1 blocked", "s4 decided, not enforced", "s5 decided, not enforced",
		"obs-1 observed")
	sameMarks(t, "tree", marks(draw(t, goldens[2])), "r1 enforced", "r2 enforced", "m1 exception or approval")

	page := draw(t, goldens[1])
	for _, want := range []string{
		`<span class="mk-label">not seen</span> <span class="mk-detail">no call of this step</span>`,
		`<span class="mk-detail">self-reported by source <code>s1</code></span>`,
		`<span class="mk-detail">mode OBSERVE</span>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page holds no %s", want)
		}
	}
}

// TestTheDefaultViewDrawsEachFindingsNeighbourhood: the calls a finding
// cites and the calls just before and after each, with what lies between
// counted; with no finding that cites a call, no call is drawn.
func TestTheDefaultViewDrawsEachFindingsNeighbourhood(t *testing.T) {
	sameMarks(t, "refund", marks(draw(t, goldens[0])),
		"gap: 3 calls not drawn",
		"s3 decided, not enforced", "d1 blocked", "r2 enforced",
		"gap: 2 calls not drawn",
		"s5 decided, not enforced", "obs-1 observed")
	sameMarks(t, "stray", marks(draw(t, goldens[3])),
		"r1 enforced", "d1 blocked", "r3 enforced", "l2 enforced")

	p, res := judge(t, refund01, supervise.Input{Exports: []supervise.Export{export(
		call{req: "r1", tool: "get_order", upstream: "shop"},
		call{req: "r2", tool: "issue_refund", upstream: "pay", at: 10e9})}})
	page, err := runview.Page(p, res, runview.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := marks(string(page)); len(got) != 0 || !bytes.Contains(page, []byte("No finding cites a call, so no call is drawn.")) {
		t.Errorf("a run with no finding draws %v", got)
	}
}

// TestEnforcedNeedsACoherentTrailAndAModeThatActs: the same completed call
// is enforced under ENFORCE, APPROVE and LOCKDOWN only; under any other mode,
// with no mode recorded or with its trail in doubt it is decided, not
// enforced, an exception taken on it included; an approval granted or an
// exception marks it, and a report is observed whatever its mode says.
func TestEnforcedNeedsACoherentTrailAndAModeThatActs(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*supervise.Instance)
		want string
	}{
		{"enforce", func(*supervise.Instance) {}, "enforced: mode ENFORCE"},
		{"approve", func(in *supervise.Instance) { in.Mode = controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE }, "enforced: mode APPROVE"},
		{"lockdown", func(in *supervise.Instance) { in.Mode = controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN }, "enforced: mode LOCKDOWN"},
		{"warn", func(in *supervise.Instance) { in.Mode = controlv1.EnforcementMode_ENFORCEMENT_MODE_WARN }, "decided, not enforced: mode WARN"},
		{"shadow", func(in *supervise.Instance) { in.Mode = controlv1.EnforcementMode_ENFORCEMENT_MODE_SHADOW }, "decided, not enforced: mode SHADOW"},
		{"no mode", func(in *supervise.Instance) { in.Mode = 0 }, "decided, not enforced: no mode recorded"},
		{"undeclared mode", func(in *supervise.Instance) { in.Mode = 99 }, "decided, not enforced: mode 99"},
		{"doubt", func(in *supervise.Instance) { in.Doubt, in.Outcome = true, supervise.OutcomeUnknown }, "decided, not enforced: trail in doubt"},
		{"granted", func(in *supervise.Instance) { in.Approval = supervise.ApprovalGranted }, "exception or approval: approval granted"},
		{"excepted", func(in *supervise.Instance) { in.Excepted = true }, "exception or approval: an exception taken"},
		{"excepted in doubt", func(in *supervise.Instance) {
			in.Excepted, in.Doubt, in.Outcome = true, true, supervise.OutcomeUnknown
		}, "decided, not enforced: trail in doubt"},
		{"asked", func(in *supervise.Instance) { in.Approval = supervise.ApprovalAsked }, "enforced: mode ENFORCE"},
		{"report", func(in *supervise.Instance) { in.Observation, in.Source = "obs-9", "s9" }, "observed: self-reported by source <code>s9</code>"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, res := refundRun(t)
			c.edit(&res.Instances[0])
			res.Instances[0].Trust = res.Instances[len(res.Instances)-1].Trust
			page, err := runview.Page(p, res, runview.Options{All: true})
			if err != nil {
				t.Fatal(err)
			}
			first := callRow.FindString(string(page))
			got := regexp.MustCompile(`<span class="mk-label">([^<]*)</span> <span class="mk-detail">(.*?)</span></td>`).FindStringSubmatch(first)
			if got == nil || got[1]+": "+got[2] != c.want {
				t.Errorf("the first call is marked %q, want %q", got, c.want)
			}
		})
	}
}

// TestAnEnforcementAPICallIsDecidedInEveryMode: a client of the enforcement
// API runs the call itself, so its plane enforces nothing it decides, in
// ENFORCE as in LOCKDOWN; an MCP call in ENFORCE is enforced, and a call of no
// protocol, or of one this build does not know, is decided.
func TestAnEnforcementAPICallIsDecidedInEveryMode(t *testing.T) {
	lockdown := controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN
	p, res := judge(t, refund01, supervise.Input{Exports: []supervise.Export{export(
		call{req: "r1", tool: "get_order", upstream: "shop", protocol: "mcp"},
		call{req: "r2", tool: "issue_refund", upstream: "pay", at: 10 * time.Second, protocol: "enforce"},
		call{req: "r3", tool: "send_mail", upstream: "mail", at: 20 * time.Second, protocol: "enforce", mode: lockdown},
		call{req: "r4", tool: "get_order", upstream: "shop", at: 30 * time.Second, protocol: "a2a"},
		call{req: "r5", tool: "get_order", upstream: "shop", at: 40 * time.Second, protocol: "MCP"},
		call{req: "r6", tool: "get_order", upstream: "shop", at: 50 * time.Second, noProtocol: true})}})
	page, err := runview.Page(p, res, runview.Options{All: true})
	if err != nil {
		t.Fatal(err)
	}
	sameMarks(t, "protocols", marks(string(page)), "r1 enforced", "r2 decided, not enforced", "r3 decided, not enforced",
		"r4 decided, not enforced", "r5 decided, not enforced", "r6 decided, not enforced")
	for _, want := range []string{
		`<span class="mk-detail">a cooperating client enforces it</span>`,
		`<span class="mk-detail">no enforcement point holds the path</span>`,
	} {
		if !strings.Contains(string(page), want) {
			t.Errorf("the page holds no %s", want)
		}
	}
}
