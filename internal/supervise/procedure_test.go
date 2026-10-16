package supervise_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/guardana/control/internal/supervise"
)

// docWith is procJSON with each pair of old and new text replaced once.
func docWith(t *testing.T, pairs ...string) string {
	t.Helper()
	doc := procJSON
	for i := 0; i+1 < len(pairs); i += 2 {
		if !strings.Contains(doc, pairs[i]) {
			t.Fatalf("procedure fixture holds no %q", pairs[i])
		}
		doc = strings.Replace(doc, pairs[i], pairs[i+1], 1)
	}
	return doc
}

func TestAProcedureIsReadWithItsSteps(t *testing.T) {
	p, err := supervise.ReadProcedure([]byte(procJSON))
	if err != nil {
		t.Fatalf("ReadProcedure: %v", err)
	}
	want := []supervise.Step{
		{ID: "lookup", Tool: "get_order", Upstream: "shop", ObservedAs: []string{"get_order"}, Required: true},
		{ID: "refund", Tool: "issue_refund", Upstream: "pay", ObservedAs: []string{"issue_refund"}, Required: true},
		{ID: "notify", Tool: "send_mail", Upstream: "mail", ObservedAs: []string{"send_mail"}},
	}
	if p.ID() != "refund" || p.Version() != "1" || !reflect.DeepEqual(p.Steps(), want) {
		t.Fatalf("read %q %q %+v", p.ID(), p.Version(), p.Steps())
	}
}

// canonicalProc is procJSON in RFC 8785's form, written out by hand.
const canonicalProc = `{"allow":[{"observed_as":["search_docs"],"tool":"search_docs","upstream":"docs"}],` +
	`"deadline_seconds":600,"max_denials":4,"order":{"notify":["refund"],"refund":["lookup"]},` +
	`"procedure_id":"refund","rules":{` +
	`"CONTINUED_AFTER_FAILURE":{"escalation":"alert","severity":"critical"},` +
	`"DEADLINE_EXCEEDED":{"escalation":"inform","severity":"low"},` +
	`"REPEATED_DENIAL":{"escalation":"alert","severity":"high"},` +
	`"REQUIRED_STEP_SKIPPED":{"escalation":"alert","severity":"high"},` +
	`"STEP_OUTSIDE_PROCEDURE":{"escalation":"alert","severity":"medium"},` +
	`"STEP_OUT_OF_ORDER":{"escalation":"inform","severity":"medium"}},` +
	`"schema_version":"0.1","steps":[` +
	`{"id":"lookup","observed_as":["get_order"],"required":true,"tool":"get_order","upstream":"shop"},` +
	`{"id":"refund","observed_as":["issue_refund"],"required":true,"tool":"issue_refund","upstream":"pay"},` +
	`{"id":"notify","observed_as":["send_mail"],"required":false,"tool":"send_mail","upstream":"mail"}],` +
	`"version":"1"}`

func TestTheDigestIsOfTheCanonicalFormAndAnEditChangesIt(t *testing.T) {
	sum := sha256.Sum256([]byte(canonicalProc))
	wantDigest := hex.EncodeToString(sum[:])
	reordered := "{\n  \"version\": \"1\",\t\"procedure_id\" : \"refund\"," +
		strings.TrimPrefix(strings.Replace(procJSON, `"procedure_id":"refund","version":"1",`, "", 1), "{")
	for name, doc := range map[string]string{"as written": procJSON, "reordered": reordered, "canonical": canonicalProc} {
		p, err := supervise.ReadProcedure([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.Digest() != wantDigest {
			t.Fatalf("%s: digest %s, want %s", name, p.Digest(), wantDigest)
		}
	}
	edited := procWith(t, `"DEADLINE_EXCEEDED":{"severity":"low"`, `"DEADLINE_EXCEEDED":{"severity":"info"`)
	if edited.Version() != "1" || edited.Digest() == wantDigest {
		t.Fatalf("an edited body under the same version kept digest %s", edited.Digest())
	}
}

func TestAProcedureIsRefused(t *testing.T) {
	long := strings.Repeat("a", 1025)
	for name, doc := range map[string]string{
		"not JSON":                   "{",
		"two values":                 procJSON + "{}",
		"an array":                   "[" + procJSON + "]",
		"a repeated member":          docWith(t, `"version":"1",`, `"version":"1","version":"1",`),
		"an unknown member":          docWith(t, `"version":"1",`, `"version":"1","owner":"x",`),
		"another schema version":     docWith(t, `"schema_version":"0.1"`, `"schema_version":"0.3"`),
		"a 0.1 body under 0.2":       docWith(t, `"schema_version":"0.1"`, `"schema_version":"0.2"`),
		"no schema version":          docWith(t, `"schema_version":"0.1",`, ``),
		"no procedure id":            docWith(t, `"procedure_id":"refund",`, ``),
		"an empty version":           docWith(t, `"version":"1"`, `"version":""`),
		"a null version":             docWith(t, `"version":"1"`, `"version":null`),
		"no steps member":            docWith(t, `"steps":[`, `"stops":[`),
		"no step":                    `{"schema_version":"0.1","procedure_id":"x","version":"1","steps":[],"order":{},"allow":[],"rules":` + rulesJSON + `}`,
		"no order":                   docWith(t, `"order":{"refund":["lookup"],"notify":["refund"]},`, ``),
		"no allow":                   docWith(t, `"allow":[{"tool":"search_docs","upstream":"docs","observed_as":["search_docs"]}],`, ``),
		"no rules":                   docWith(t, `,"rules":`+rulesJSON, ``),
		"max_denials 0":              docWith(t, `"max_denials":4`, `"max_denials":0`),
		"max_denials negative":       docWith(t, `"max_denials":4`, `"max_denials":-4`),
		"max_denials a fraction":     docWith(t, `"max_denials":4`, `"max_denials":4.5`),
		"max_denials 4.0":            docWith(t, `"max_denials":4`, `"max_denials":4.0`),
		"max_denials a string":       docWith(t, `"max_denials":4`, `"max_denials":"4"`),
		"max_denials null":           docWith(t, `"max_denials":4`, `"max_denials":null`),
		"max_denials over 32 bits":   docWith(t, `"max_denials":4`, `"max_denials":4294967296`),
		"max_denials leading zero":   docWith(t, `"max_denials":4`, `"max_denials":04`),
		"deadline 0":                 docWith(t, `"deadline_seconds":600`, `"deadline_seconds":0`),
		"a step without observed_as": docWith(t, `"upstream":"shop","observed_as":["get_order"],`, `"upstream":"shop",`),
		"a step member unknown":      docWith(t, `"required":true}`, `"required":true,"retries":1}`),
		"required not a bool":        docWith(t, `"required":true}`, `"required":"yes"}`),
		"a repeated step id":         docWith(t, `{"id":"refund"`, `{"id":"lookup"`),
		"a step tool twice":          docWith(t, `"tool":"send_mail","upstream":"mail"`, `"tool":"get_order","upstream":"shop"`),
		"an allowed step tool":       docWith(t, `"tool":"search_docs","upstream":"docs"`, `"tool":"get_order","upstream":"shop"`),
		"a name of two steps":        docWith(t, `"observed_as":["send_mail"]`, `"observed_as":["get_order"]`),
		"a name of a step allowed":   docWith(t, `"observed_as":["search_docs"]`, `"observed_as":["get_order"]`),
		"a name twice in a step":     docWith(t, `"observed_as":["get_order"]`, `"observed_as":["get_order","get_order"]`),
		"a cycle":                    docWith(t, `"order":{"refund":["lookup"]`, `"order":{"lookup":["notify"],"refund":["lookup"]`),
		"a step after itself":        docWith(t, `"notify":["refund"]`, `"notify":["notify"]`),
		"an unknown step ordered":    docWith(t, `"notify":["refund"]`, `"ghost":["refund"]`),
		"an unknown step followed":   docWith(t, `"notify":["refund"]`, `"notify":["ghost"]`),
		"an empty order entry":       docWith(t, `"notify":["refund"]`, `"notify":[]`),
		"a repeated order entry":     docWith(t, `"notify":["refund"]`, `"notify":["refund","refund"]`),
		"a rule missing":             docWith(t, `"DEADLINE_EXCEEDED":{"severity":"low","escalation":"inform"},`, ``),
		"an unknown rule":            docWith(t, `"DEADLINE_EXCEEDED"`, `"DEADLINE_MISSED"`),
		"an unknown severity":        docWith(t, `"severity":"low"`, `"severity":"urgent"`),
		"an unknown escalation":      docWith(t, `"escalation":"inform"}`, `"escalation":"page"}`),
		"a rule without escalation":  docWith(t, `"severity":"low","escalation":"inform"`, `"severity":"low"`),
		"a control character":        docWith(t, `"procedure_id":"refund"`, `"procedure_id":"ref\u0007und"`),
		"white space at the start":   docWith(t, `"procedure_id":"refund"`, `"procedure_id":" refund"`),
		"a string over the bound":    docWith(t, `"procedure_id":"refund"`, `"procedure_id":"`+long+`"`),
		"over the size bound":        procJSON + strings.Repeat(" ", supervise.MaxProcedureBytes-len(procJSON)+1),
	} {
		p, err := supervise.ReadProcedure([]byte(doc))
		if !errors.Is(err, supervise.ErrProcedure) || p != nil {
			t.Errorf("%s: ReadProcedure = %v, %v; want ErrProcedure", name, p, err)
		}
	}
}

// TestTheBoundsAdmitTheirLimit is each refusal's counterpart at its limit.
func TestTheBoundsAdmitTheirLimit(t *testing.T) {
	for name, doc := range map[string]string{
		"max_denials 1":          docWith(t, `"max_denials":4`, `"max_denials":1`),
		"max_denials at 32 bits": docWith(t, `"max_denials":4`, `"max_denials":4294967295`),
		"deadline 1":             docWith(t, `"deadline_seconds":600`, `"deadline_seconds":1`),
		"both rules left out":    docWith(t, `"max_denials":4,"deadline_seconds":600,`, ``),
		"a string at the bound":  docWith(t, `"procedure_id":"refund"`, `"procedure_id":"`+strings.Repeat("a", 1024)+`"`),
		"at the size bound":      procJSON + strings.Repeat(" ", supervise.MaxProcedureBytes-len(procJSON)),
		"no observed_as names":   docWith(t, `"observed_as":["send_mail"]`, `"observed_as":[]`),
		"no order and no allow": docWith(t, `"order":{"refund":["lookup"],"notify":["refund"]},`, `"order":{},`,
			`"allow":[{"tool":"search_docs","upstream":"docs","observed_as":["search_docs"]}]`, `"allow":[]`),
	} {
		if _, err := supervise.ReadProcedure([]byte(doc)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestStepsCannotChangeAProcedure: what Steps returns is a copy, its
// slices too, so changing it leaves the procedure, a later Steps and an
// evaluation under the procedure's digest as they were.
func TestStepsCannotChangeAProcedure(t *testing.T) {
	p := procWith(t)
	steps := p.Steps()
	steps[0].ObservedAs[0] = "wipe_disk"
	steps[1].Required = false
	steps[2].Tool = "wipe_disk"
	read := []supervise.Step{
		{ID: "lookup", Tool: "get_order", Upstream: "shop", ObservedAs: []string{"get_order"}, Required: true},
		{ID: "refund", Tool: "issue_refund", Upstream: "pay", ObservedAs: []string{"issue_refund"}, Required: true},
		{ID: "notify", Tool: "send_mail", Upstream: "mail", ObservedAs: []string{"send_mail"}},
	}
	if got := p.Steps(); !reflect.DeepEqual(got, read) {
		t.Fatalf("Steps after a change to its copy = %+v", got)
	}
	res := closedRun(t, p, export(call{req: "r1", tool: "get_order", upstream: "shop"}))
	sameFindings(t, res.Findings,
		want(p, "REQUIRED_STEP_SKIPPED", high, alert, suspected, id("REQUIRED_STEP_SKIPPED", "refund")))
}
