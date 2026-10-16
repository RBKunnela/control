package gatewayconfig

import (
	"strings"
	"testing"
)

// TestTheReaderFlattensWhatItReads pins the paths the loader binds against,
// written out as literals: a key that lands one level off would bind nothing
// and be refused as unknown, and a sequence read as a mapping would bind the
// wrong entry.
func TestTheReaderFlattensWhatItReads(t *testing.T) {
	document := `# a comment on its own line
mode: ENFORCE
listener:
  kind: stateless_http     # a comment after a value
  origins:
    - http://localhost:5173
    - "https://studio.example"
  principal:
    id: agent-runner
upstreams:
  - name: orders
    endpoint: http://127.0.0.1:9000/mcp
  - name: mail
    command: /usr/bin/mail-mcp
    args:
      - --stdio
      - "--profile=work"
quoted: "a value with a # in it and an \"escape\""
`
	want := []entry{
		{path: "mode", value: "ENFORCE"},
		{path: "listener.kind", value: "stateless_http"},
		{path: "listener.origins.0", value: "http://localhost:5173"},
		{path: "listener.origins.1", value: "https://studio.example"},
		{path: "listener.principal.id", value: "agent-runner"},
		{path: "upstreams.0.name", value: "orders"},
		{path: "upstreams.0.endpoint", value: "http://127.0.0.1:9000/mcp"},
		{path: "upstreams.1.name", value: "mail"},
		{path: "upstreams.1.command", value: "/usr/bin/mail-mcp"},
		{path: "upstreams.1.args.0", value: "--stdio"},
		{path: "upstreams.1.args.1", value: "--profile=work"},
		{path: "quoted", value: `a value with a # in it and an "escape"`},
	}
	got, err := parseYAML(document)
	if err != nil {
		t.Fatalf("the reader refused a document this test builds as valid: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("read %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].path != w.path || got[i].value != w.value {
			t.Errorf("entry %d is %s=%q, want %s=%q", i, got[i].path, got[i].value, w.path, w.value)
		}
	}
}

// TestTheReaderRefusesWhatItDoesNotUnderstand: every shape of YAML this subset
// leaves out is refused with its line, because a file the program half
// understands is a configuration nobody has read.
func TestTheReaderRefusesWhatItDoesNotUnderstand(t *testing.T) {
	for _, c := range []struct {
		name     string
		document string
		wants    string
	}{
		{"a tab in the indentation", "policy:\n\tkey_id: k1\n", "tab"},
		{"an anchor", "policy: &base\n  key_id: k1\n", "not read here"},
		{"an alias", "policy: *base\n", "not read here"},
		{"a flow mapping", "policy: {key_id: k1}\n", "not read here"},
		{"a flow sequence", "origins: [a, b]\n", "not read here"},
		{"a block scalar", "note: |\n  two\n  lines\n", "not read here"},
		{"a key with no value", "policy:\n", "no value and no block under it"},
		{"a line that is not a key", "mode\n", "expected a key followed by a colon"},
		{"a value after the closing quote", `mode: "OBSERVE" and more` + "\n", "text after the closing quote"},
		{"an escape this reader does not know", `mode: "a\qb"` + "\n", "not an escape"},
		{"a value that never closes its quote", `mode: "OBSERVE` + "\n", "without a closing quote"},
		{"a sequence item indented past its siblings", "origins:\n  - a\n      - b\n", "expected a sequence item under origins"},
		{"a tag", "tenant_id: !!str acme\n", "tags and single quotes"},
		{"a single-quoted value", "tenant_id: 'acme'\n", "tags and single quotes"},
		{"a single-quoted sequence item", "origins:\n  - 'http://localhost:5173'\n", "tags and single quotes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseYAML(c.document)
			if err == nil {
				t.Fatalf("the reader accepted %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Errorf("the refusal is %q, which does not name %q", err.Error(), c.wants)
			}
			if !strings.HasPrefix(err.Error(), "line ") {
				t.Errorf("the refusal does not start with the line it is about: %q", err.Error())
			}
		})
	}
}

// TestAHeaderValueIsNeverInARefusal: a header's value is a credential, so a
// refusal of it names the key and the reason and never the value, under
// either map, for every refusal the reader makes of a value.
func TestAHeaderValueIsNeverInARefusal(t *testing.T) {
	const secret = "s3cr3t-T0KEN"
	for _, prefix := range []string{"export:\n  headers:\n    Authorization: ", "pdp:\n  headers:\n    Authorization: "} {
		for name, value := range map[string]string{
			"flow characters":      "Bearer " + secret + "&more",
			"text after the quote": `"Bearer ` + secret + `" and more`,
			"an unknown escape":    `"Bearer ` + secret + `\q"`,
			"an unclosed quote":    `"Bearer ` + secret,
			"a single quote":       "'Bearer " + secret + "'",
		} {
			_, err := parseYAML(prefix + value + "\n")
			if err == nil {
				t.Fatalf("%s: the reader accepted %q", name, value)
			}
			if strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), NotPrinted) {
				t.Errorf("%s: the refusal is %q", name, err.Error())
			}
		}
	}
	_, err := parseYAML("project_id: \"orders\" and " + secret + "\n")
	if err == nil || !strings.Contains(err.Error(), secret) {
		t.Errorf("a value under another key is named in its refusal: %v", err)
	}
}

// TestACredentialIsNeverInARefusal: a refused value under a credential key,
// an address carrying userinfo, or text a header value left on a line of its
// own is named without the secret it holds.
func TestACredentialIsNeverInARefusal(t *testing.T) {
	const secret = "hunter2"
	for name, document := range map[string]string{
		"a single-quoted proxy":          "pdp:\n  proxy: 'http://user:" + secret + "@proxy:3128'\n",
		"an endpoint with userinfo":      "export:\n  endpoint: 'http://user:" + secret + "@collector:4318'\n",
		"an upstream endpoint":           "upstreams:\n  - name: a\n    endpoint: 'https://user:" + secret + "@up/mcp'\n",
		"a header value on its own line": "export:\n  headers:\n    Authorization:\n      'Bearer " + secret + ":x'\n",
	} {
		_, err := parseYAML(document)
		if err == nil {
			t.Fatalf("%s: the reader accepted it", name)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the refusal is %q", name, err.Error())
		}
	}
}

// TestACommentCannotHideInAValue: a '#' inside a quoted value is part of the
// value, and a '#' after a space is a comment. Getting this wrong would cut an
// endpoint or a token in half without saying so.
func TestACommentCannotHideInAValue(t *testing.T) {
	got, err := parseYAML("a: \"x #y\"\nb: x #y\nc: x#y\n")
	if err != nil {
		t.Fatalf("the reader refused a document this test builds as valid: %v", err)
	}
	want := []string{"x #y", "x", "x#y"}
	for i, w := range want {
		if got[i].value != w {
			t.Errorf("%s is %q, want %q", got[i].path, got[i].value, w)
		}
	}
}

// TestAnEscapedQuoteKeepsTheValueQuoted: inside a double-quoted scalar a
// backslash escapes the next byte, so an escaped quote does not end the value
// and a '#' after it is the value's own; an escaped backslash before the
// closing quote does end it, and a comment after a closed value is still cut.
func TestAnEscapedQuoteKeepsTheValueQuoted(t *testing.T) {
	got, err := parseYAML("list:\n  - \"a\\\" #b\"\nb: \"x\\\"y\" # a comment\nc: \"x\\\\\" # a comment\n")
	if err != nil {
		t.Fatalf("the reader refused a document this test builds as valid: %v", err)
	}
	want := []entry{{path: "list.0", value: `a" #b`}, {path: "b", value: `x"y`}, {path: "c", value: `x\`}}
	if len(got) != len(want) {
		t.Fatalf("read %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].path != w.path || got[i].value != w.value {
			t.Errorf("entry %d is %s=%q, want %s=%q", i, got[i].path, got[i].value, w.path, w.value)
		}
	}
}

// TestBytesAreReadAtTheirSuffix is the bound helper's own table: a suffix
// silently ignored would set a budget a thousand times smaller than the
// operator wrote.
func TestBytesAreReadAtTheirSuffix(t *testing.T) {
	for _, c := range []struct {
		text string
		want int64
	}{{"0", 0}, {"512", 512}, {"64KiB", 65536}, {"2MiB", 2097152}, {"1GiB", 1073741824}} {
		got, err := parseBytes(c.text)
		if err != nil {
			t.Fatalf("%q: %v", c.text, err)
		}
		if got != c.want {
			t.Errorf("%q is %d, want %d", c.text, got, c.want)
		}
	}
	for _, text := range []string{"", "-1", "1TiB", "1 GiB", "1kb", "0x10", "9223372036854775807GiB"} {
		if got, err := parseBytes(text); err == nil {
			t.Errorf("%q was read as %d, want a refusal", text, got)
		}
	}
}

// FuzzParseYAML holds the reader to what a refusal and an acceptance each
// promise: a refusal names its line, and an accepted document yields entries
// that each have a path and the line they came from. Whether a path is a
// key is the binder's question, not the reader's.
func FuzzParseYAML(f *testing.F) {
	f.Add("mode: ENFORCE\nlistener:\n  origins:\n    - a\n    - \"b\"\nupstreams:\n  - name: x\n    args:\n      - --stdio\n")
	f.Add("a: \"x #y\"\nb: x #y\nc: x#y\n")
	f.Add("policy:\n\tkey_id: k1\n")
	f.Add("origins: [a, b]\n")
	f.Add("- a\n")
	f.Add("base: &a x\n")
	f.Add("mode: *a\n")
	f.Add("mode: !!str x\n")
	f.Add("mode: 'x'\n")
	f.Add("mode: a\nmode: b\n")
	f.Fuzz(func(t *testing.T, document string) {
		entries, err := parseYAML(document)
		if err != nil {
			if !strings.HasPrefix(err.Error(), "line ") {
				t.Errorf("the refusal does not start with the line it is about: %q", err.Error())
			}
			if entries != nil {
				t.Errorf("entries %v beside the error", entries)
			}
			return
		}
		lines := strings.Count(document, "\n") + 1
		for _, e := range entries {
			if e.path == "" {
				t.Error("an entry with no path")
			}
			if e.line < 1 || e.line > lines {
				t.Errorf("%s comes from line %d of a %d-line document", e.path, e.line, lines)
			}
		}
	})
}
