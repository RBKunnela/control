package pyschema

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
)

const (
	enforcePackage = brand.OTelNamespace + ".enforce.v1alpha1."
	v1Package      = brand.ProtoPackage + "."
)

func realModel(t *testing.T) Model {
	t.Helper()
	m, err := Build(Roots()...)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return m
}

func realTable(t *testing.T) []byte {
	t.Helper()
	table, err := Python(realModel(t))
	if err != nil {
		t.Fatalf("Python: %v", err)
	}
	return table
}

// membersOf returns the lines of one message's members as the table writes
// them, without their indentation.
func membersOf(t *testing.T, table []byte, message string) []string {
	t.Helper()
	_, rest, found := strings.Cut(string(table), "\n    \""+message+"\": {\n")
	if !found {
		t.Fatalf("the table holds no message %s", message)
	}
	block, _, closed := strings.Cut(rest, "\n    },\n")
	if !closed {
		t.Fatalf("message %s is never closed", message)
	}
	var lines []string
	for line := range strings.SplitSeq(block, "\n") {
		lines = append(lines, strings.TrimSpace(line))
	}
	return lines
}

func TestTheTableHoldsTheEnforcementMessagesAsTheContractDeclaresThem(t *testing.T) {
	table := realTable(t)
	for _, c := range []struct{ message, line string }{
		{enforcePackage + "AdmitResponse", `"outcome": ("enum", "one", "` + enforcePackage + `Outcome"),`},
		{enforcePackage + "AdmitResponse", `"decision": ("message", "one", "` + v1Package + `Decision"),`},
		{enforcePackage + "AdmitRequest", `"requestKey": ("string", "one", ""),`},
		{enforcePackage + "Execution", `"authorizedArguments": ("bytes", "one", ""),`},
		{enforcePackage + "Execution", `"expiresAt": ("timestamp", "one", ""),`},
		{enforcePackage + "Execution", `"obligations": ("message", "list", "` + v1Package + `Obligation"),`},
		{enforcePackage + "Pending", `"retryAfter": ("duration", "one", ""),`},
		{v1Package + "Decision", `"decisionLatencyUs": ("int64", "one", ""),`},
		{v1Package + "Decision", `"policyRuleIds": ("string", "list", ""),`},
		{v1Package + "Decision", `"verdict": ("enum", "one", "` + v1Package + `Verdict"),`},
		{v1Package + "Obligation", `"params": ("string", "map", ""),`},
		{v1Package + "Obligation", `"advisory": ("bool", "one", ""),`},
	} {
		if !slices.Contains(membersOf(t, table, c.message), c.line) {
			t.Errorf("%s has no member written %s", c.message, c.line)
		}
	}
	for _, line := range []string{
		`    "` + enforcePackage + `Outcome": {"OUTCOME_UNSPECIFIED": 0, "OUTCOME_EXECUTE": 1, "OUTCOME_BLOCK": 2, "OUTCOME_PENDING": 3},`,
		`    "` + v1Package + `PolicyFreshness": {"POLICY_FRESHNESS_UNSPECIFIED": 0, "POLICY_FRESHNESS_FRESH": 1, "POLICY_FRESHNESS_STALE": 2},`,
	} {
		if !bytes.Contains(table, []byte("\n"+line+"\n")) {
			t.Errorf("the table has no line %s", line)
		}
	}
}

// Decision declares schema_version, number 13, before decision_id, number 1.
func TestTheTableListsMembersByNumber(t *testing.T) {
	members := membersOf(t, realTable(t), v1Package+"Decision")
	if first := `"decisionId": ("string", "one", ""),`; members[0] != first {
		t.Errorf("Decision starts with %s, want %s", members[0], first)
	}
	before := slices.Index(members, `"pdpVersion": ("string", "one", ""),`)
	at := slices.Index(members, `"schemaVersion": ("string", "one", ""),`)
	after := slices.Index(members, `"enforcementMode": ("enum", "one", "`+v1Package+`EnforcementMode"),`)
	if before < 0 || at != before+1 || after != at+1 {
		t.Errorf("pdpVersion, schemaVersion and enforcementMode sit at %d, %d and %d, want one after the other", before, at, after)
	}
}

// The closure is the seven bodies of the enforcement API and what they
// reach. Timestamp and Duration are kinds, so neither is a message here, and
// the enums of the contract no body reaches stay out.
func TestTheModelIsTheClosureOfTheEnforcementBodies(t *testing.T) {
	m := realModel(t)
	wantMessages := []string{
		enforcePackage + "AbortRequest",
		enforcePackage + "AbortResponse",
		enforcePackage + "AdmitRequest",
		enforcePackage + "AdmitResponse",
		enforcePackage + "CompleteRequest",
		enforcePackage + "CompleteResponse",
		enforcePackage + "Error",
		enforcePackage + "Execution",
		enforcePackage + "Pending",
		v1Package + "Decision",
		v1Package + "Obligation",
	}
	wantEnums := []string{
		enforcePackage + "AbortCause",
		enforcePackage + "CompletionStatus",
		enforcePackage + "Ending",
		enforcePackage + "ErrorCode",
		enforcePackage + "Outcome",
		v1Package + "EnforcementMode",
		v1Package + "PolicyFreshness",
		v1Package + "Verdict",
	}
	var messages, enums []string
	for _, msg := range m.Messages {
		messages = append(messages, msg.Name)
	}
	for _, e := range m.Enums {
		enums = append(enums, e.Name)
	}
	if !slices.Equal(messages, wantMessages) {
		t.Errorf("messages:\n got %q\nwant %q", messages, wantMessages)
	}
	if !slices.Equal(enums, wantEnums) {
		t.Errorf("enums:\n got %q\nwant %q", enums, wantEnums)
	}
}

// zeroProblem says what is wrong with the value a reader takes for an enum
// nobody set: there is none, or its name does not say unspecified.
func zeroProblem(e Enum) string {
	i := slices.IndexFunc(e.Values, func(v Value) bool { return v.Number == 0 })
	switch {
	case i < 0:
		return e.Name + " declares no zero value"
	case !strings.HasSuffix(e.Values[i].Name, "_UNSPECIFIED"):
		return e.Name + " names its zero value " + e.Values[i].Name
	}
	return ""
}

func TestEveryEnumOfTheClosureNamesItsZeroValueUnspecified(t *testing.T) {
	m := realModel(t)
	if len(m.Enums) == 0 {
		t.Fatal("the model holds no enum; nothing was examined")
	}
	for _, e := range m.Enums {
		if problem := zeroProblem(e); problem != "" {
			t.Error(problem)
		}
	}
}

func TestZeroProblemNamesAnEnumWithNoUnspecifiedZero(t *testing.T) {
	for _, c := range []struct {
		enum Enum
		want string
	}{
		{Enum{Name: "wire.test.Good", Values: []Value{{"GOOD_UNSPECIFIED", 0}, {"GOOD_ON", 1}}}, ""},
		{Enum{Name: "wire.test.Named", Values: []Value{{"NAMED_OFF", 0}, {"NAMED_UNSPECIFIED", 1}}}, "wire.test.Named names its zero value NAMED_OFF"},
		{Enum{Name: "wire.test.Bare", Values: []Value{{"UNSPECIFIED", 0}}}, "wire.test.Bare names its zero value UNSPECIFIED"},
		{Enum{Name: "wire.test.Shifted", Values: []Value{{"SHIFTED_UNSPECIFIED", 1}}}, "wire.test.Shifted declares no zero value"},
	} {
		if got := zeroProblem(c.enum); got != c.want {
			t.Errorf("zeroProblem(%s): got %q, want %q", c.enum.Name, got, c.want)
		}
	}
}

func TestRenderingIsDeterministic(t *testing.T) {
	first := realTable(t)
	if len(first) == 0 {
		t.Fatal("the table is empty; two empty runs are equal and prove nothing")
	}
	for run := range 20 {
		if again := realTable(t); !bytes.Equal(first, again) {
			t.Fatalf("run %d wrote another table than the first:\n%s", run+2, firstDifference(again, first))
		}
	}
}
