// The renderer's refusals, which were unreachable while this code lived in a
// //go:build ignore script: nothing could call them and no gate compiled them.
// They are the branches that keep a broken registry from being published as a
// page that still renders.
package reasondoc

import (
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/reasons"
)

// good is a code that renders, so each test below changes exactly one thing.
func good() reasons.Code {
	return reasons.Code{
		ID:      "A_CODE",
		Num:     1,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "A sentence that says what happened.",
	}
}

func TestPageRendersOneRowPerCode(t *testing.T) {
	page, err := Page()
	if err != nil {
		t.Fatalf("Page: %v", err)
	}

	all := reasons.All()
	if len(all) == 0 {
		t.Fatal("the registry is empty; this test would then assert nothing")
	}
	rows := 0
	for _, line := range strings.Split(string(page), "\n") {
		if strings.HasPrefix(line, "| `") {
			rows++
		}
	}
	if rows != len(all) {
		t.Errorf("page holds %d code rows, want %d", rows, len(all))
	}
	for _, code := range all {
		if !strings.Contains(string(page), "| `"+code.ID+"` | ") {
			t.Errorf("page has no row for %s", code.ID)
		}
	}
}

// Same registry, same bytes. A page that differed between runs would make the
// currency check in internal/policy/reasons fail at random.
func TestPageIsDeterministic(t *testing.T) {
	first, err := Page()
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	second, err := Page()
	if err != nil {
		t.Fatalf("Page, second call: %v", err)
	}
	if string(first) != string(second) {
		t.Error("two calls to Page produced different bytes")
	}
}

func TestRenderRefusesAnEmptyRegistry(t *testing.T) {
	page, err := render(nil)
	if err == nil {
		t.Fatalf("render(nil) returned a page of %d bytes, want an error", len(page))
	}
	if page != nil {
		t.Errorf("render(nil) returned %d bytes beside the error, want none", len(page))
	}
}

// A pipe ends a cell and a newline ends a row. The rest are the invisible half:
// a carriage return renders as nothing and still travels into evidence, and a
// form feed is a line break to some readers and not to others. A summary is a
// sentence, so none of them belongs in one.
func TestRenderRefusesACellThatBreaksTheTable(t *testing.T) {
	for name, code := range map[string]reasons.Code{
		"pipe in the identifier": func() reasons.Code { c := good(); c.ID = "A|CODE"; return c }(),
		"pipe in the summary":    func() reasons.Code { c := good(); c.Summary = "One cell | two cells."; return c }(),
		"newline in the summary": func() reasons.Code { c := good(); c.Summary = "One row.\n| A_FORGED_CODE | 99 |"; return c }(),
		"return in the summary":  func() reasons.Code { c := good(); c.Summary = "A sentence,\rand what it hides."; return c }(),
		"tab in the summary":     func() reasons.Code { c := good(); c.Summary = "A sentence\twith a tab."; return c }(),
		"form feed in the summary": func() reasons.Code {
			c := good()
			c.Summary = "A sentence\fwith a form feed."
			return c
		}(),
		"delete in the identifier": func() reasons.Code { c := good(); c.ID = "A_CODE\x7f"; return c }(),
		"null in the summary":      func() reasons.Code { c := good(); c.Summary = "A sentence\x00with a null."; return c }(),
	} {
		t.Run(name, func(t *testing.T) {
			page, err := render([]reasons.Code{code})
			if err == nil {
				t.Fatalf("render returned a page, want an error:\n%s", page)
			}
			if !strings.Contains(err.Error(), code.ID) {
				t.Errorf("error %q does not name the code it refused", err)
			}
		})
	}
}

// The registry's own tests reject both verdicts below. This is the second
// mechanism: a page is never published from a table that names a verdict the
// frozen contract does not declare, or one that reads as nothing decided.
func TestRenderRefusesAVerdictThePageCannotName(t *testing.T) {
	for name, verdict := range map[string]controlv1.Verdict{
		"undeclared number": controlv1.Verdict(99),
		"unspecified":       controlv1.Verdict_VERDICT_UNSPECIFIED,
	} {
		t.Run(name, func(t *testing.T) {
			code := good()
			code.Verdict = verdict
			if page, err := render([]reasons.Code{code}); err == nil {
				t.Fatalf("render returned a page, want an error:\n%s", page)
			}
		})
	}
}

func TestVerdictNameDropsThePrefix(t *testing.T) {
	got, err := verdictName(controlv1.Verdict_VERDICT_REQUIRE_APPROVAL)
	if err != nil {
		t.Fatalf("verdictName: %v", err)
	}
	if got != "REQUIRE_APPROVAL" {
		t.Errorf("verdictName returned %q, want %q", got, "REQUIRE_APPROVAL")
	}
}
