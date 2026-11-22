package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/canon"
)

const casesDir = "testdata/cases"

// caseDir writes each file into a directory of the test's own and returns it.
func caseDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

// policyTestOf runs `policy test` over files and returns the exit status and
// stdout's lines. stderr has to be empty: a case's failure is a stdout line.
func policyTestOf(t *testing.T, files map[string]string) (int, []string) {
	t.Helper()
	code, stdout, stderr := invoke(t, "policy", "test", caseDir(t, files))
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}
	if !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("stdout does not end in a newline: %q", stdout)
	}
	return code, strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
}

func TestPolicyTestPassesTheFiveVerdicts(t *testing.T) {
	code, stdout, stderr := invoke(t, "policy", "test", casesDir)
	if code != 0 {
		t.Errorf("exit %d, want 0", code)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}
	want := "ok   allow-read.json: ALLOW Execute [RULE_ALLOW]\n" +
		"ok   approve-refund.json: REQUIRE_APPROVAL AwaitApproval [APPROVAL_REQUIRED]\n" +
		"ok   deny-unmatched-write.json: DENY Block [NO_MATCHING_RULE]\n" +
		"ok   obligated-read.json: ALLOW_WITH_OBLIGATIONS ExecuteWithObligations [OBLIGATIONS_ATTACHED]\n" +
		"ok   stale-read.json: INDETERMINATE Block [POLICY_STALE RULE_ALLOW]\n"
	if stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", stdout, want)
	}
}

func TestPolicyTestReportsAMismatchAndKeepsGoing(t *testing.T) {
	wrong := base()
	wrong.expect = `{"verdict":"DENY","action":"Block","reason_codes":["RULE_DENY"]}`
	code, lines := policyTestOf(t, map[string]string{
		"a-right.json": base().json(),
		"b-wrong.json": wrong.json(),
		"c-right.json": base().json(),
	})
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	want := []string{
		"ok   a-right.json: ALLOW Execute [RULE_ALLOW]",
		"FAIL b-wrong.json: got ALLOW Execute [RULE_ALLOW], want DENY Block [RULE_DENY]",
		"ok   c-right.json: ALLOW Execute [RULE_ALLOW]",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// The codes are compared exactly and in order: the same set in another order
// is a mismatch, and so is a subset.
func TestPolicyTestHoldsTheCodesToTheirOrder(t *testing.T) {
	stale := base()
	stale.loadedAt = `"2026-09-11T11:00:00Z"`
	for name, tc := range map[string]struct{ expect, line string }{
		"in order": {
			`{"verdict":"INDETERMINATE","action":"Block","reason_codes":["POLICY_STALE","RULE_ALLOW"]}`,
			"ok   case.json: INDETERMINATE Block [POLICY_STALE RULE_ALLOW]",
		},
		"reversed": {
			`{"verdict":"INDETERMINATE","action":"Block","reason_codes":["RULE_ALLOW","POLICY_STALE"]}`,
			"FAIL case.json: got INDETERMINATE Block [POLICY_STALE RULE_ALLOW], want INDETERMINATE Block [RULE_ALLOW POLICY_STALE]",
		},
		"a subset": {
			`{"verdict":"INDETERMINATE","action":"Block","reason_codes":["POLICY_STALE"]}`,
			"FAIL case.json: got INDETERMINATE Block [POLICY_STALE RULE_ALLOW], want INDETERMINATE Block [POLICY_STALE]",
		},
		"the action alone wrong": {
			`{"verdict":"INDETERMINATE","action":"Execute","reason_codes":["POLICY_STALE","RULE_ALLOW"]}`,
			"FAIL case.json: got INDETERMINATE Block [POLICY_STALE RULE_ALLOW], want INDETERMINATE Execute [POLICY_STALE RULE_ALLOW]",
		},
		"the verdict alone wrong": {
			`{"verdict":"DENY","action":"Block","reason_codes":["POLICY_STALE","RULE_ALLOW"]}`,
			"FAIL case.json: got INDETERMINATE Block [POLICY_STALE RULE_ALLOW], want DENY Block [POLICY_STALE RULE_ALLOW]",
		},
		// The case's own text cannot break the one-line-per-case rule.
		"a control character in an expected code": {
			`{"verdict":"INDETERMINATE","action":"Block","reason_codes":["POLICY_STALE","RULE_ALLOW\nok   injected.json: DENY Block [X]"]}`,
			`FAIL case.json: "got INDETERMINATE Block [POLICY_STALE RULE_ALLOW], want INDETERMINATE Block [POLICY_STALE RULE_ALLOW\nok   injected.json: DENY Block [X]]"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := stale
			p.expect = tc.expect
			code, lines := policyTestOf(t, map[string]string{"case.json": p.json()})
			if wantCode := map[bool]int{true: 0, false: 1}[strings.HasPrefix(tc.line, "ok")]; code != wantCode {
				t.Errorf("exit %d, want %d", code, wantCode)
			}
			if len(lines) != 1 || lines[0] != tc.line {
				t.Errorf("lines = %q, want [%q]", lines, tc.line)
			}
		})
	}
}

// A case that cannot run is a mismatch with the reason on its line, never a
// skipped case: the exit status says the directory did not pass.
func TestPolicyTestCountsACaseItCannotReadAsAMismatch(t *testing.T) {
	badDocument := base()
	badDocument.document = `{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"orders","version":"1","serial":0,"maxStaleSeconds":300},"rules":[` + allowReads + `]}`
	badOptions := base()
	badOptions.options = `{"fail_open_read":false,"max_stale_seconds":0,"applicable":[]}`
	unknownObligation := base()
	unknownObligation.options = `{"fail_open_read":false,"max_stale_seconds":600,"applicable":["cap_amounts"]}`
	for name, tc := range map[string]struct{ content, want string }{
		"not a case":                 {`{"document":{}}`, "FAIL case.json: envelope: missing"},
		"not json":                   {`{`, "FAIL case.json: the case: "},
		"a document that fails":      {badDocument.json(), `FAIL case.json: policy: canonical is not a valid policy document: "bundle.serial": "rules: not above zero`},
		"a budget New refuses":       {badOptions.json(), "FAIL case.json: core: the staleness budget is not positive: 0s"},
		"an applicable type unknown": {unknownObligation.json(), "FAIL case.json: core: an applicable obligation type is not in the catalogue: Applicable[0]"},
	} {
		t.Run(name, func(t *testing.T) {
			code, lines := policyTestOf(t, map[string]string{"case.json": tc.content})
			if code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
			if len(lines) != 1 || !strings.HasPrefix(lines[0], tc.want) {
				t.Errorf("lines = %q, want one starting %q", lines, tc.want)
			}
		})
	}
}

// An envelope the receiver's own JSON decoder refuses is handed to the kernel
// as its refusal, which is what a receiver would do with it.
func TestPolicyTestHandsARefusedEnvelopeToTheKernel(t *testing.T) {
	p := base()
	p.envelope = strings.Replace(readEnvelope, `"requestId":"req-1",`, "", 1)
	p.expect = `{"verdict":"INDETERMINATE","action":"Block","reason_codes":["REQUIRED_FIELD_ABSENT"]}`
	code, lines := policyTestOf(t, map[string]string{"case.json": p.json()})
	if code != 0 || len(lines) != 1 || lines[0] != "ok   case.json: INDETERMINATE Block [REQUIRED_FIELD_ABSENT]" {
		t.Errorf("exit %d, lines %q", code, lines)
	}
}

// The five verdicts through `policy test`, over the fixtures the kernel's own
// tests run: every case passes, and each verdict is the answer of at least
// one of them.
func TestPolicyTestPassesTheFixtures(t *testing.T) {
	code, stdout, stderr := invoke(t, "policy", "test", "../../testdata/policy/fixtures")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "ok   ") {
			t.Errorf("line %q is not a pass", line)
		}
	}
	for _, verdict := range []string{"ALLOW", "ALLOW_WITH_OBLIGATIONS", "DENY", "REQUIRE_APPROVAL", "INDETERMINATE"} {
		if !slices.ContainsFunc(lines, func(line string) bool { return strings.Contains(line, ": "+verdict+" ") }) {
			t.Errorf("no fixture decides %s", verdict)
		}
	}
}

// NewKeyFromSeed panics on any other length, and every case would go with it.
func TestSigningSeedIsASeed(t *testing.T) {
	if len(signingSeed) != ed25519.SeedSize {
		t.Errorf("signingSeed is %d bytes, want %d", len(signingSeed), ed25519.SeedSize)
	}
}

func TestPolicyTestRefusesADirectoryWithNoCase(t *testing.T) {
	dir := caseDir(t, map[string]string{"README.md": "notes"})
	for name, path := range map[string]string{
		"empty":        t.TempDir(),
		"no case file": dir,
		"missing":      filepath.Join(dir, "missing"),
		"a file":       filepath.Join(dir, "README.md"),
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := invoke(t, "policy", "test", path)
			if code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
			if line := oneStderrLine(t, stderr); !strings.HasPrefix(line, brand.CLI+": policy test: ") {
				t.Errorf("stderr = %q, want the prefix", line)
			}
		})
	}
}

// Only files named *.json are cases; a README beside them is not read, a
// subdirectory is not entered, and a link to a case file is followed.
func TestPolicyTestReadsOnlyJSONFilesOfTheDirectory(t *testing.T) {
	dir := caseDir(t, map[string]string{"case.json": base().json(), "README.md": "not a case", "case.json.bak": "{"})
	if err := os.Mkdir(filepath.Join(dir, "nested.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := caseDir(t, map[string]string{"target.json": base().json()})
	if err := os.Symlink(filepath.Join(elsewhere, "target.json"), filepath.Join(dir, "linked.json")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := invoke(t, "policy", "test", dir)
	if code != 0 || stderr != "" {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	if want := "ok   case.json: ALLOW Execute [RULE_ALLOW]\nok   linked.json: ALLOW Execute [RULE_ALLOW]\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// Each member of a case reaches the kernel: for every one, two cases that
// differ in that member alone get different decisions.
func TestPolicyTestWiresEveryMember(t *testing.T) {
	const (
		approveToxic  = `{"id":"approve-toxic","effect":"REQUIRE_APPROVAL","when":{"flow":{"toxicAtLeast":"CONFIDENTIAL"}}}`
		sandboxReads  = `{"id":"sandbox-reads","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"require_sandbox"}],"when":{"action":{"effect":["READ"]}}}`
		externalRead  = `"destination":{"trustZone":"TRUST_ZONE_UNTRUSTED_EXTERNAL","host":"example.com"},"resource"`
		hashedRefund  = `"arguments":{"canonicalHash":"%s"},"action":{"name":"orders.read","effect":"EFFECT_CLASS_READ","provider":"orders"}`
		vetoReads     = `{"id":"veto-reads","effect":"DENY","when":{"action":{"effect":["READ"]},"external":{"denies":true}}}`
		delegatedRead = `"delegation":[{"from":"user-1","to":"agent-1","scopes":["orders:read"],"issuedAt":"2026-09-11T11:00:00Z","expiresAt":"2026-09-11T12:30:00Z"}],"action"`
	)
	flowRules := func(p *parts) {
		p.document = strings.Replace(p.document, allowReads, approveToxic+","+allowReads, 1)
		p.envelope = strings.Replace(readEnvelope, `"resource"`, externalRead, 1)
	}
	for name, tc := range map[string]struct {
		change       func(p *parts)
		a, b         func(p *parts)
		lineA, lineB string
	}{
		"fail_open_read": {
			change: func(p *parts) { p.loadedAt = `"2026-09-11T11:00:00Z"` },
			a:      func(p *parts) { p.options = `{"fail_open_read":false,"max_stale_seconds":600,"applicable":[]}` },
			b:      func(p *parts) { p.options = `{"fail_open_read":true,"max_stale_seconds":600,"applicable":[]}` },
			lineA:  "INDETERMINATE Block [POLICY_STALE RULE_ALLOW]",
			lineB:  "INDETERMINATE Execute [POLICY_STALE RULE_ALLOW FAIL_OPEN_READ_CONFIGURED]",
		},
		"max_stale_seconds": {
			change: func(p *parts) { p.loadedAt = `"2026-09-11T11:59:00Z"` },
			a:      func(p *parts) { p.options = `{"fail_open_read":false,"max_stale_seconds":60,"applicable":[]}` },
			b:      func(p *parts) { p.options = `{"fail_open_read":false,"max_stale_seconds":59,"applicable":[]}` },
			lineA:  "ALLOW Execute [RULE_ALLOW]",
			lineB:  "INDETERMINATE Block [POLICY_STALE RULE_ALLOW]",
		},
		"applicable": {
			change: func(p *parts) { p.document = strings.Replace(p.document, allowReads, sandboxReads, 1) },
			a: func(p *parts) {
				p.options = `{"fail_open_read":false,"max_stale_seconds":600,"applicable":["require_sandbox"]}`
			},
			b:     func(p *parts) { p.options = `{"fail_open_read":false,"max_stale_seconds":600,"applicable":[]}` },
			lineA: "ALLOW_WITH_OBLIGATIONS ExecuteWithObligations [OBLIGATIONS_ATTACHED]",
			lineB: "DENY Block [OBLIGATIONS_ATTACHED OBLIGATION_NOT_UNDERSTOOD]",
		},
		"flow.untrusted": {
			change: flowRules,
			a:      func(p *parts) { p.flow = `{"untrusted":true,"floor":"SECRET"}` },
			b:      func(p *parts) { p.flow = `{"untrusted":false,"floor":"SECRET"}` },
			lineA:  "REQUIRE_APPROVAL AwaitApproval [APPROVAL_REQUIRED RULE_ALLOW]",
			lineB:  "ALLOW Execute [RULE_ALLOW]",
		},
		"flow.floor": {
			change: flowRules,
			a:      func(p *parts) { p.flow = `{"untrusted":true,"floor":"SECRET"}` },
			b:      func(p *parts) { p.flow = `{"untrusted":true,"floor":"PUBLIC"}` },
			lineA:  "REQUIRE_APPROVAL AwaitApproval [APPROVAL_REQUIRED RULE_ALLOW]",
			lineB:  "INDETERMINATE Block [RULE_ALLOW RULE_UNDETERMINED]",
		},
		"authorized_args": {
			change: func(p *parts) {
				p.envelope = strings.Replace(readEnvelope, `"action":{"name":"orders.read","effect":"EFFECT_CLASS_READ","provider":"orders"}`,
					strings.Replace(hashedRefund, "%s", argumentsHash(t, `{"amount": 1}`), 1), 1)
			},
			a:     func(p *parts) { p.authorizedArgs = `"{\"amount\": 1}"` },
			b:     func(p *parts) { p.authorizedArgs = `"{\"amount\": 2}"` },
			lineA: "ALLOW Execute [RULE_ALLOW]",
			lineB: "INDETERMINATE Block [INVALID_FIELD_VALUE]",
		},
		"loaded_at": {
			a:     func(p *parts) { p.loadedAt = `"2026-09-11T11:55:00Z"` },
			b:     func(p *parts) { p.loadedAt = `"2026-09-11T11:54:59Z"` },
			lineA: "ALLOW Execute [RULE_ALLOW]",
			lineB: "INDETERMINATE Block [POLICY_STALE RULE_ALLOW]",
		},
		"external": {
			change: func(p *parts) { p.document = strings.Replace(p.document, allowReads, allowReads+","+vetoReads, 1) },
			a:      func(p *parts) { p.external = `"allowed"` },
			b:      func(p *parts) { p.external = `"timeout"` },
			lineA:  "ALLOW Execute [RULE_ALLOW PDP_ALLOW]",
			lineB:  "INDETERMINATE Block [RULE_ALLOW RULE_UNDETERMINED PDP_TIMEOUT]",
		},
		"decided_at": {
			change: func(p *parts) { p.envelope = strings.Replace(readEnvelope, `"action"`, delegatedRead, 1) },
			a:      func(p *parts) { p.decidedAt = `"2026-09-11T12:29:59Z"`; p.loadedAt = p.decidedAt },
			b:      func(p *parts) { p.decidedAt = `"2026-09-11T12:30:00Z"`; p.loadedAt = p.decidedAt },
			lineA:  "ALLOW Execute [RULE_ALLOW]",
			lineB:  "DENY Block [DELEGATION_EXPIRED RULE_ALLOW]",
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, b := base(), base()
			if tc.change != nil {
				tc.change(&a)
				tc.change(&b)
			}
			tc.a(&a)
			tc.b(&b)
			a.expect = expectOf(tc.lineA)
			b.expect = expectOf(tc.lineB)
			code, lines := policyTestOf(t, map[string]string{"a.json": a.json(), "b.json": b.json()})
			want := []string{"ok   a.json: " + tc.lineA, "ok   b.json: " + tc.lineB}
			if code != 0 || strings.Join(lines, "\n") != strings.Join(want, "\n") {
				t.Errorf("exit %d, lines:\n%s\nwant:\n%s", code, strings.Join(lines, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

// argumentsHash is the hash the envelope carries for args, from the same
// function the kernel compares it with.
func argumentsHash(t *testing.T, args string) string {
	t.Helper()
	h, err := canon.ArgumentsHashV1([]byte(args))
	if err != nil {
		t.Fatalf("ArgumentsHashV1: %v", err)
	}
	return h
}

// expectOf turns a line's "VERDICT Action [CODE ...]" into the expect member.
// The line is the literal the test states; the tool's own line is what the
// test then compares it with.
func expectOf(line string) string {
	fields := strings.Fields(line)
	codes := strings.Trim(strings.Join(fields[2:], " "), "[]")
	var quoted []string
	for _, c := range strings.Fields(codes) {
		quoted = append(quoted, `"`+c+`"`)
	}
	return `{"verdict":"` + fields[0] + `","action":"` + fields[1] + `","reason_codes":[` + strings.Join(quoted, ",") + `]}`
}

// Arguments a JSON string cannot carry byte for byte are refused, by both
// commands that read a case: the decoder would hand the kernel U+FFFD in their
// place, and the kernel refuses the bytes the case wrote.
func TestACaseIsRefusedArgumentsItCannotCarryExactly(t *testing.T) {
	c, err := readCase([]byte(base().json()))
	if err != nil {
		t.Fatalf("readCase: %v", err)
	}
	c.authorizedArgs = []byte("{\"note\":\"\xff\"}")
	if got, err := decide(c); err != nil || got.String() != "INDETERMINATE Block [INVALID_FIELD_VALUE]" {
		t.Fatalf("the kernel on the written bytes: %v, %v", got, err)
	}
	for name, args := range map[string]string{
		"an invalid UTF-8 byte":                  "\"{\\\"note\\\":\\\"\xff\\\"}\"",
		"a lone high surrogate":                  `"{\"note\":\"\ud800\"}"`,
		"a lone low surrogate":                   `"{\"note\":\"\udfff\"}"`,
		"a high surrogate unpaired":              `"{\"note\":\"\ud800A\"}"`,
		"a high surrogate before another escape": `"{\"note\":\"\ud800` + `\` + `u0041\"}"`,
		"a low surrogate before another low":     `"{\"note\":\"\udc00` + `\` + `udc00\"}"`,
		"two high surrogates":                    `"{\"note\":\"\ud800` + `\` + `ud800\"}"`,
	} {
		t.Run(name, func(t *testing.T) {
			p := base()
			p.authorizedArgs = args
			p.expect = `{"verdict":"ALLOW","action":"Execute","reason_codes":["RULE_ALLOW"]}`
			code, lines := policyTestOf(t, map[string]string{"case.json": p.json()})
			if code != 1 || len(lines) != 1 || !strings.HasPrefix(lines[0], "FAIL case.json: authorized_args: ") {
				t.Errorf("policy test: exit %d, lines %q", code, lines)
			}
			path := filepath.Join(caseDir(t, map[string]string{"case.json": withoutExpect(p)}), "case.json")
			code, stdout, stderr := invoke(t, "policy", "explain", path)
			if code != 1 || stdout != "" || !strings.HasPrefix(oneStderrLine(t, stderr), brand.CLI+": policy explain: authorized_args: ") {
				t.Errorf("policy explain: exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
		})
	}
}

// What a JSON string carries exactly is still read, escapes resolved: a
// surrogate pair, U+FFFD written as such, and a backslash before a "u".
func TestACaseReadsArgumentsItCarriesExactly(t *testing.T) {
	for name, tc := range map[string]struct{ args, want string }{
		"a surrogate pair":       {`"{\"note\":\"\ud83d\ude00\"}"`, "{\"note\":\"\U0001F600\"}"},
		"U+FFFD escaped":         {`"{\"note\":\"\ufffd\"}"`, "{\"note\":\"\uFFFD\"}"},
		"U+FFFD as its bytes":    {"\"{\\\"note\\\":\\\"\xef\xbf\xbd\\\"}\"", "{\"note\":\"\uFFFD\"}"},
		"a backslash before a u": {`"{\"note\":\"\\ud800\"}"`, `{"note":"\ud800"}`},
	} {
		t.Run(name, func(t *testing.T) {
			p := base()
			p.authorizedArgs = tc.args
			c, err := readCase([]byte(p.json()))
			if err != nil {
				t.Fatalf("readCase: %v", err)
			}
			if string(c.authorizedArgs) != tc.want {
				t.Errorf("authorized_args = %q, want %q", c.authorizedArgs, tc.want)
			}
		})
	}
}
