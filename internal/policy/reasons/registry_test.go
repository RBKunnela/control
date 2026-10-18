// What the table holds, as tests, because the package declares a static table
// and checks nothing at init: a duplicate identifier, a reused number, a moved
// number or a placeholder summary has to fail the build here rather than panic
// inside a process that is deciding on a call.
//
// TestRegistryMatchesTheDocumentedTriples is the oracle. The generator renders
// whatever the table holds, so without a second copy of the identifier, number
// and verdict written out as literals, flipping NO_MATCHING_RULE to ALLOW or
// swapping two numbers publishes a page that contradicts ADR-0003 with nothing
// red. It is also what makes this table verifiable after it has been retyped.
//
// The pins on what leaves the package, its exported surface and its published
// page, are in surface_test.go.
package reasons_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/reasons"
)

const (
	// Below either bound a summary is a placeholder rather than a sentence
	// somebody can read on a decision.
	minSummaryLen   = 40
	minSummaryWords = 6
)

var (
	idPattern          = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	placeholderPattern = regexp.MustCompile(`(?i)\b(todo|tbd|fixme|xxx|placeholder|lorem)\b`)
)

// triple is an identifier, its number and the verdict it documents, written out
// independently of codes.go. The verdicts are spelled in full rather than
// through local aliases on purpose: an alias would let one edited line move
// every row at once, and the point of this table is that it is dumb.
type triple struct {
	id      string
	num     uint32
	verdict controlv1.Verdict
}

var wantTriples = []triple{
	{"NO_MATCHING_RULE", 1, controlv1.Verdict_VERDICT_DENY},
	{"RULE_ALLOW", 2, controlv1.Verdict_VERDICT_ALLOW},
	{"RULE_DENY", 3, controlv1.Verdict_VERDICT_DENY},
	{"APPROVAL_REQUIRED", 4, controlv1.Verdict_VERDICT_REQUIRE_APPROVAL},
	{"OBLIGATIONS_ATTACHED", 5, controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS},
	{"TENANT_MISMATCH", 6, controlv1.Verdict_VERDICT_DENY},
	{"ENVIRONMENT_BOUNDARY", 7, controlv1.Verdict_VERDICT_DENY},
	{"OUT_OF_SCOPE_ACTION", 8, controlv1.Verdict_VERDICT_DENY},
	{"DELEGATION_EXCEEDS_PARENT", 9, controlv1.Verdict_VERDICT_DENY},
	{"DELEGATION_CYCLE", 10, controlv1.Verdict_VERDICT_DENY},
	{"DELEGATION_EXPIRED", 11, controlv1.Verdict_VERDICT_DENY},
	{"APPROVAL_DIGEST_MISMATCH", 12, controlv1.Verdict_VERDICT_DENY},
	{"APPROVAL_EXPIRED", 13, controlv1.Verdict_VERDICT_DENY},
	{"APPROVAL_PENDING", 14, controlv1.Verdict_VERDICT_REQUIRE_APPROVAL},
	// 15 is INDETERMINATE, not DENY. A stale bundle and a missing bundle are
	// the same availability failure of the same source, so both route through
	// the fail-closed table; a terminal DENY here would mean holding more
	// information about policy produced a harsher outcome than holding none.
	{"POLICY_STALE", 15, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"POLICY_UNAVAILABLE", 16, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"PDP_TIMEOUT", 17, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"MALFORMED_INPUT", 18, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"UNSUPPORTED_SCHEMA", 19, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"EXECUTED_ARGS_MISMATCH", 20, controlv1.Verdict_VERDICT_DENY},
	{"TOXIC_FLOW_SENSITIVE_TO_EXTERNAL", 21, controlv1.Verdict_VERDICT_DENY},
	{"IDEMPOTENCY_REQUIRED", 22, controlv1.Verdict_VERDICT_DENY},
	{"SELF_ADMINISTRATION", 23, controlv1.Verdict_VERDICT_DENY},
	{"PAUSED", 24, controlv1.Verdict_VERDICT_DENY},
	// 25 is INDETERMINATE, not ALLOW. Nothing evaluated the read, and the
	// operator's fail-open setting changes what is enforced, never the verdict
	// recorded for it: ALLOW here is the collapse invariant 4 forbids, and a
	// consumer filtering on the verdict would count the read as an ordinary
	// allow (ADR-0011).
	{"FAIL_OPEN_READ_CONFIGURED", 25, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"REQUIRED_FIELD_ABSENT", 26, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"LIMIT_EXCEEDED", 27, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"INVALID_FIELD_VALUE", 28, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"OBLIGATION_NOT_UNDERSTOOD", 29, controlv1.Verdict_VERDICT_DENY},
	{"APPROVAL_REJECTED", 30, controlv1.Verdict_VERDICT_DENY},
	{"APPROVAL_ALREADY_USED", 31, controlv1.Verdict_VERDICT_DENY},
	{"APPROVAL_BUNDLE_MISMATCH", 32, controlv1.Verdict_VERDICT_DENY},
	{"RULE_UNDETERMINED", 33, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"TENANT_UNDETERMINED", 34, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"LOCKDOWN", 35, controlv1.Verdict_VERDICT_DENY},
	{"EVIDENCE_UNAVAILABLE", 36, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"ACTION_UNCLASSIFIED", 37, controlv1.Verdict_VERDICT_INDETERMINATE},
	// 38 is written by the reconciliation of a hold this plane lost, and by
	// nothing on a live call: an approval that was granted, whose request is
	// gone, is neither "nobody answered" nor evidence that could not be
	// written, and an operator acts on the difference.
	{"APPROVAL_NOT_RESUMED", 38, controlv1.Verdict_VERDICT_DENY},
	{"PDP_UNAVAILABLE", 39, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"PDP_ANSWER_REFUSED", 40, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"PDP_DENY", 41, controlv1.Verdict_VERDICT_DENY},
	{"PDP_ALLOW", 42, controlv1.Verdict_VERDICT_ALLOW},
	// 43 is INDETERMINATE and not PAUSED: a pause state the plane cannot read
	// is a fault, and a trail must not say an operator paused the call.
	{"PAUSE_STATE_UNAVAILABLE", 43, controlv1.Verdict_VERDICT_INDETERMINATE},
	// 44 is INDETERMINATE and not APPROVAL_EXPIRED: an answer the plane could
	// not read or trust says nothing about whether the approval lapsed.
	{"APPROVAL_STATE_UNKNOWN", 44, controlv1.Verdict_VERDICT_INDETERMINATE},
	{"RUN_STOPPED", 45, controlv1.Verdict_VERDICT_DENY},
	// 46 is INDETERMINATE and not RUN_STOPPED: a stop list the plane cannot
	// read or trust says nothing about which run is stopped.
	{"STOP_STATE_UNAVAILABLE", 46, controlv1.Verdict_VERDICT_INDETERMINATE},
	// 47 is INDETERMINATE: an execution nobody completed or aborted may or may
	// not have had its effect.
	{"EXECUTION_ABANDONED", 47, controlv1.Verdict_VERDICT_INDETERMINATE},
}

// wantTriples names verdicts by symbol, and a symbol is only worth pinning if
// the number behind it is fixed too: swapping VERDICT_ALLOW and VERDICT_DENY in
// the generated Go would leave every row above green while every stored
// decision changed meaning. Six literals close that, which is cheaper than
// repeating a number on every row and pins the same thing.
var wantVerdictNumbers = map[controlv1.Verdict]int32{
	controlv1.Verdict_VERDICT_UNSPECIFIED:            0,
	controlv1.Verdict_VERDICT_ALLOW:                  1,
	controlv1.Verdict_VERDICT_DENY:                   2,
	controlv1.Verdict_VERDICT_REQUIRE_APPROVAL:       3,
	controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS: 4,
	controlv1.Verdict_VERDICT_INDETERMINATE:          5,
}

// The wire numbers behind the symbols the pinned table names. `buf breaking`
// and `make proto-check` guard the contract itself; this guards the assumption
// this file makes about it, which is a different claim and belongs here.
func TestVerdictSymbolsKeepTheirWireNumbers(t *testing.T) {
	for verdict, want := range wantVerdictNumbers {
		if got := int32(verdict); got != want {
			t.Errorf("%s is wire number %d, want %d", verdict, got, want)
		}
	}
	if len(controlv1.Verdict_name) != len(wantVerdictNumbers) {
		t.Errorf("the contract declares %d verdicts, this file pins %d",
			len(controlv1.Verdict_name), len(wantVerdictNumbers))
	}
}

// registry returns every code and fails when the table is empty: a test that
// loops over nothing would report a pass having examined nothing.
func registry(t *testing.T) []reasons.Code {
	t.Helper()
	all := reasons.All()
	if len(all) == 0 {
		t.Fatal("All() returned no codes; every check below would pass over an empty set")
	}
	return all
}

// The oracle. Every identifier, number and documented verdict is compared with
// a literal written here, so no edit to codes.go can move a number under an
// identifier or change what verdict a code documents while the suite stays
// green and the reference page keeps rendering.
func TestRegistryMatchesTheDocumentedTriples(t *testing.T) {
	all := registry(t)
	if len(wantTriples) == 0 {
		t.Fatal("the pinned table is empty, so it pins nothing")
	}
	if len(all) != len(wantTriples) {
		t.Fatalf("the registry holds %d codes and the pinned table holds %d; compare them by hand before editing either",
			len(all), len(wantTriples))
	}
	for i, want := range wantTriples {
		got := all[i]
		switch {
		case got.ID != want.id:
			t.Errorf("entry %d is %q, want %q", i, got.ID, want.id)
		case got.Num != want.num:
			t.Errorf("%s has number %d, want %d; a number is never reused or moved", got.ID, got.Num, want.num)
		case got.Verdict != want.verdict:
			t.Errorf("%s documents %s, want %s", got.ID, got.Verdict, want.verdict)
		}
	}
}

// The two expiry codes describe the check and not its moment. ADR-0011
// measures expiry by the receiver's clock when deciding and again before
// execution, so a summary that named one of those moments, "decided" or
// "proposed", is wrong the day the second check exists.
func TestTheExpiryCodesDescribeTheCheckNotItsMoment(t *testing.T) {
	const ruled = "had expired, by this receiver's clock, when it was checked"
	for _, id := range []string{"DELEGATION_EXPIRED", "APPROVAL_EXPIRED"} {
		t.Run(id, func(t *testing.T) {
			var summary string
			for _, code := range registry(t) {
				if code.ID == id {
					summary = code.Summary
				}
			}
			if summary == "" {
				t.Fatalf("the registry holds no %s", id)
			}
			if !strings.Contains(summary, ruled) {
				t.Errorf("%s says %q, want it to say %q", id, summary, ruled)
			}
			for _, moment := range []string{"decided", "proposed"} {
				if strings.Contains(summary, moment) {
					t.Errorf("%s says %q, which names a moment (%q) rather than the check", id, summary, moment)
				}
			}
		})
	}
}

// POLICY_STALE is also what a decision says when the receiver's clock cannot
// be judged by, and what a call is blocked with when its bundle was replaced
// before the hand-out, so its summary names both beside the budget.
func TestPolicyStaleNamesTheClock(t *testing.T) {
	const want = "The policy bundle is not known to be current: it is past the staleness budget in force for this call, no freshness statement confirms it, another bundle replaced it before the call was handed out, or this receiver's clock reads before 1970, after 9999, or earlier than a time it verified for the bundle or already relied on for the call."
	for _, code := range registry(t) {
		if code.ID == "POLICY_STALE" {
			if code.Summary != want {
				t.Errorf("POLICY_STALE says %q, want %q", code.Summary, want)
			}
			return
		}
	}
	t.Fatal("the registry holds no POLICY_STALE")
}

// The two pause codes say who blocked the call: an operator's pause, or a
// pause state nobody could read. Neither may read as the other.
func TestThePauseCodesTellAnOperatorFromAFault(t *testing.T) {
	want := map[string]string{
		"PAUSED":                  "An operator paused calls in a scope this call falls in, so the enforcement point blocked it whatever the policy decided.",
		"PAUSE_STATE_UNAVAILABLE": "The enforcement point could not read the operator's pause state, so it blocked the call rather than assume that nothing is paused.",
	}
	found := 0
	for _, code := range registry(t) {
		summary, ok := want[code.ID]
		if !ok {
			continue
		}
		found++
		if code.Summary != summary {
			t.Errorf("%s says %q, want %q", code.ID, code.Summary, summary)
		}
	}
	if found != len(want) {
		t.Errorf("the registry holds %d of the %d pause codes", found, len(want))
	}
}

// The two stop codes say who blocked the call: a stop of its run, or a stop
// list nobody could read or trust. Neither may read as the other.
func TestTheStopCodesTellAStopFromAFault(t *testing.T) {
	want := map[string]string{
		"RUN_STOPPED":            "A stop the operator's route allows names the opened run this call belongs to, so the enforcement point blocked it whatever the policy decided.",
		"STOP_STATE_UNAVAILABLE": "The enforcement point could not read or trust the stop list, so it blocked the call rather than assume that no run is stopped.",
	}
	found := 0
	for _, code := range registry(t) {
		summary, ok := want[code.ID]
		if !ok {
			continue
		}
		found++
		if code.Summary != summary {
			t.Errorf("%s says %q, want %q", code.ID, code.Summary, summary)
		}
	}
	if found != len(want) {
		t.Errorf("the registry holds %d of the %d stop codes", found, len(want))
	}
}

// A lost hold's close says what the approver answered only when the plane
// could read and check it; the code for the rest says that, and never that the
// approval expired.
func TestTheUnknownApprovalStateSaysTheAnswerWasNotRead(t *testing.T) {
	const want = "The enforcement point could not read or trust the approver's answer for a lost hold, so the call was never run."
	code, ok := reasons.Lookup("APPROVAL_STATE_UNKNOWN")
	if !ok {
		t.Fatal("the registry holds no APPROVAL_STATE_UNKNOWN")
	}
	if code.Summary != want {
		t.Errorf("APPROVAL_STATE_UNKNOWN says %q, want %q", code.Summary, want)
	}
}

// An abandoned execution closes with an outcome nobody knows, so its code
// says the call may have run and never that it failed or was blocked.
func TestTheAbandonedCodeSaysTheOutcomeIsUnknown(t *testing.T) {
	const want = "An execution the enforcement point handed out was neither completed nor aborted before it expired, so it was closed without knowing whether the call ran."
	code, ok := reasons.Lookup("EXECUTION_ABANDONED")
	if !ok {
		t.Fatal("the registry holds no EXECUTION_ABANDONED")
	}
	if code.Summary != want {
		t.Errorf("EXECUTION_ABANDONED says %q, want %q", code.Summary, want)
	}
}

func TestAllHoldsEveryCodeSortedByNum(t *testing.T) {
	all := registry(t)
	if len(all) != len(wantTriples) {
		t.Errorf("All() returned %d codes, want %d", len(all), len(wantTriples))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Num >= all[i].Num {
			t.Errorf("All() is not sorted by Num: %s has %d, %s has %d",
				all[i-1].ID, all[i-1].Num, all[i].ID, all[i].Num)
		}
	}
}

func TestCodeIDsAndNumsAreUnique(t *testing.T) {
	all := registry(t)
	byID := make(map[string]reasons.Code, len(all))
	byNum := make(map[uint32]reasons.Code, len(all))
	for _, code := range all {
		if first, seen := byID[code.ID]; seen {
			t.Errorf("identifier %q is used by number %d and by number %d", code.ID, first.Num, code.Num)
		}
		if first, seen := byNum[code.Num]; seen {
			t.Errorf("number %d is used by %q and by %q", code.Num, first.ID, code.ID)
		}
		// Zero is the value a struct nobody filled in carries, so it can never
		// be a real code: Lookup's miss returns exactly that.
		if code.Num == 0 {
			t.Errorf("%s has number 0, which is the zero Code a lookup miss returns", code.ID)
		}
		byID[code.ID] = code
		byNum[code.Num] = code
	}
}

// retiredCode is an identifier and a number a code held before it was
// retired. codes.go promises that a retired code leaves a gap; this table is
// what keeps the promise. Without it, removing a code from codes.go and from
// wantTriples and later giving its number or its identifier to a new code
// leaves every test green, and a stored decision starts to mean something it
// did not mean when it was written.
type retiredCode struct {
	id  string
	num uint32
}

// retired is every code ever removed from the registry. None has been retired
// yet. A code leaves codes.go and wantTriples and arrives here in one change.
var retired = []retiredCode{}

// reuse is a registered code holding a retired identifier or number.
type reuse struct {
	retired retiredCode
	by      reasons.Code
}

// reusesOfRetired reports every registered code that holds a retired
// identifier or a retired number.
func reusesOfRetired(all []reasons.Code, retired []retiredCode) []reuse {
	var found []reuse
	for _, gone := range retired {
		for _, code := range all {
			if code.ID == gone.id || code.Num == gone.num {
				found = append(found, reuse{retired: gone, by: code})
			}
		}
	}
	return found
}

func TestRetiredCodesStayRetired(t *testing.T) {
	for _, r := range reusesOfRetired(registry(t), retired) {
		t.Errorf("%s was retired as number %d, and %s (number %d) holds its identifier or its number; a retired code is never reused",
			r.retired.id, r.retired.num, r.by.ID, r.by.Num)
	}
}

// The check above runs over an empty table today, so this is what shows it can
// fail: a retired identifier registered again and a retired number reused are
// each reported, and a retirement nothing reuses is not.
func TestRetiredCheckCatchesReuse(t *testing.T) {
	all := registry(t)
	first := all[0]
	for _, tc := range []struct {
		name    string
		retired []retiredCode
		want    int
	}{
		{"an identifier registered again", []retiredCode{{id: first.ID, num: 999}}, 1},
		{"a number reused", []retiredCode{{id: "A_RETIRED_CODE", num: first.Num}}, 1},
		{"a retirement nothing reuses", []retiredCode{{id: "A_RETIRED_CODE", num: 999}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reusesOfRetired(all, tc.retired); len(got) != tc.want {
				t.Errorf("reported %d reuse(s), want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestCodeIDsAreUpperSnake(t *testing.T) {
	for _, code := range registry(t) {
		if !idPattern.MatchString(code.ID) {
			t.Errorf("identifier %q does not match %s", code.ID, idPattern)
		}
	}
}

// A summary is what somebody reads on a decision, so it has to be a sentence:
// one full stop, at the end, and enough of it to say what happened.
func TestSummariesAreSentences(t *testing.T) {
	for _, code := range registry(t) {
		summary := code.Summary
		first, _ := utf8.DecodeRuneInString(summary)
		switch {
		case summary == "":
			t.Errorf("%s has no summary", code.ID)
		case strings.TrimSpace(summary) != summary:
			t.Errorf("%s: summary has leading or trailing space: %q", code.ID, summary)
		case !strings.HasSuffix(summary, "."):
			t.Errorf("%s: summary does not end in a full stop: %q", code.ID, summary)
		case strings.Count(summary, ".") != 1:
			t.Errorf("%s: summary holds %d full stops, want one sentence: %q",
				code.ID, strings.Count(summary, "."), summary)
		case len(summary) < minSummaryLen:
			t.Errorf("%s: summary is %d bytes, want at least %d: %q",
				code.ID, len(summary), minSummaryLen, summary)
		case len(strings.Fields(summary)) < minSummaryWords:
			t.Errorf("%s: summary holds %d words, want at least %d: %q",
				code.ID, len(strings.Fields(summary)), minSummaryWords, summary)
		case !unicode.IsUpper(first):
			t.Errorf("%s: summary does not start with a capital: %q", code.ID, summary)
		case strings.Contains(summary, "  "):
			t.Errorf("%s: summary holds a double space: %q", code.ID, summary)
		case placeholderPattern.MatchString(summary):
			t.Errorf("%s: summary reads as a placeholder: %q", code.ID, summary)
		}
	}
}

// Two codes with the same sentence means one of them was copied and never
// finished, and a reader cannot tell the two decisions apart.
func TestSummariesAreDistinct(t *testing.T) {
	seen := make(map[string]string, len(wantTriples))
	for _, code := range registry(t) {
		if first, ok := seen[code.Summary]; ok {
			t.Errorf("%s and %s carry the same summary: %q", first, code.ID, code.Summary)
		}
		seen[code.Summary] = code.ID
	}
}

// The documented verdict is checked against the frozen contract as well as
// against the pinned table: a verdict number the contract does not declare
// would otherwise sit in the table and reach the reference page.
func TestDocumentedVerdictsAreDeclared(t *testing.T) {
	for _, code := range registry(t) {
		name, declared := controlv1.Verdict_name[int32(code.Verdict)]
		switch {
		case !declared:
			t.Errorf("%s documents verdict %d, which the v1 contract does not declare",
				code.ID, int32(code.Verdict))
		case code.Verdict == controlv1.Verdict_VERDICT_UNSPECIFIED:
			t.Errorf("%s documents %s, which reads as nothing decided", code.ID, name)
		}
	}
}

func TestLookupFindsEveryRegisteredCode(t *testing.T) {
	for _, want := range registry(t) {
		got, ok := reasons.Lookup(want.ID)
		if !ok {
			t.Errorf("Lookup(%q) missed a registered code", want.ID)
			continue
		}
		if got != want {
			t.Errorf("Lookup(%q) returned %+v, want %+v", want.ID, got, want)
		}
	}
}

// The negative half. A near miss must not resolve: an identifier is compared
// exactly, never trimmed, folded or matched as a prefix.
func TestLookupMissesUnregisteredIDs(t *testing.T) {
	registered := registry(t)[0].ID
	for _, id := range []string{
		"",
		" ",
		"NOT_A_REASON_CODE",
		strings.ToLower(registered),
		registered + " ",
		" " + registered,
		registered + "\n",
		registered + "\x00",
		registered[:len(registered)-1],
		registered + "_EXTRA",
		"*",
		strings.Repeat("A", 4096),
	} {
		if got, ok := reasons.Lookup(id); ok {
			t.Errorf("Lookup(%q) returned %+v, want a miss", id, got)
		} else if got != (reasons.Code{}) {
			t.Errorf("Lookup(%q) missed but returned %+v, want the zero Code", id, got)
		}
	}
}

// A registry that hands out its own backing array lets one caller rewrite what
// every later caller reads.
//
// The snapshot is cloned so that the entry-by-entry comparison below can fail:
// taken as the slice All returned, it would alias that same backing array under
// exactly the bug this test hunts, leaving the Lookup assertion to catch it and
// the failure to name no entry at all.
func TestAllReturnsACopy(t *testing.T) {
	before := slices.Clone(registry(t))

	mutated := reasons.All()
	for i := range mutated {
		mutated[i] = reasons.Code{ID: "OVERWRITTEN", Num: 999, Summary: "overwritten"}
	}
	mutated = append(mutated, reasons.Code{ID: "APPENDED", Num: 1000})

	after := reasons.All()
	if len(after) != len(before) {
		t.Fatalf("All() returned %d codes after a caller rewrote its result, want %d", len(after), len(before))
	}
	// Reported one entry at a time: printing both tables in full buries the
	// difference the failure is about.
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("All() entry %d changed after a caller rewrote its result: %+v became %+v",
				i, before[i], after[i])
			break
		}
	}
	if _, ok := reasons.Lookup("OVERWRITTEN"); ok {
		t.Error("Lookup found an identifier that only ever existed in a caller's copy")
	}
	if len(mutated) != len(after)+1 {
		t.Errorf("the caller's slice holds %d codes, want %d; the copy was not independent",
			len(mutated), len(after)+1)
	}
}

// Code carries only value fields, so a returned code is a copy too. Written as
// a test because adding a slice or a map field would break it silently.
func TestLookupReturnsACopy(t *testing.T) {
	want := registry(t)[0]

	got, ok := reasons.Lookup(want.ID)
	if !ok {
		t.Fatalf("Lookup(%q) missed a registered code", want.ID)
	}
	got.Summary = "rewritten by a caller"
	got.Verdict = controlv1.Verdict_VERDICT_ALLOW

	again, ok := reasons.Lookup(want.ID)
	if !ok {
		t.Fatalf("Lookup(%q) missed a registered code on the second call", want.ID)
	}
	if again != want {
		t.Errorf("Lookup(%q) returned %+v after a caller rewrote an earlier result, want %+v",
			want.ID, again, want)
	}
}

// FuzzLookupMatchesOnlyRegisteredIDs states the lookup contract over arbitrary
// input: a hit is a code from the table whose identifier is exactly what was
// asked for, and a miss is the zero Code and never a registered identifier.
func FuzzLookupMatchesOnlyRegisteredIDs(f *testing.F) {
	all := reasons.All()
	if len(all) == 0 {
		f.Fatal("All() returned no codes; the corpus and the assertions would be empty")
	}
	for _, code := range all {
		f.Add(code.ID)
	}
	for _, seed := range []string{"", " ", "no_matching_rule", "RULE_ALLOW ", "RULE\x00ALLOW", "Ø"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, id string) {
		got, ok := reasons.Lookup(id)
		if !ok {
			if got != (reasons.Code{}) {
				t.Errorf("Lookup(%q) missed but returned %+v, want the zero Code", id, got)
			}
			if i := slices.IndexFunc(all, func(c reasons.Code) bool { return c.ID == id }); i >= 0 {
				t.Errorf("Lookup(%q) missed code number %d, which is registered", id, all[i].Num)
			}
			return
		}
		if got.ID != id {
			t.Errorf("Lookup(%q) returned the code named %q", id, got.ID)
		}
		if !slices.Contains(all, got) {
			t.Errorf("Lookup(%q) returned %+v, which is not in the table", id, got)
		}
	})
}
