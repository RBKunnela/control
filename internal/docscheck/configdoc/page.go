// Package configdoc renders the configuration reference page from the
// gateway's tables, so the page lists exactly the keys the loader binds: a
// scalar key, a list or a map added to a table appears here at the next
// `make docs-gen`, and the pin test in internal/docscheck fails until it does.
//
// Rendering is a pure function of the tables. No clock, no filesystem:
// scripts/gen-config.go is the thin writer that puts the result on disk, and
// the pin test calls Page directly.
package configdoc

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/docscheck/frontmatter"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/pkg/contract"
)

// Generator is the script that writes the page, as the frontmatter names it.
const Generator = "scripts/gen-config.go"

// Path is where the page lives, relative to the repository root.
const Path = "docs/reference/configuration.md"

const (
	title            = "Configuration"
	summary          = "Every key the gateway reads, with its environment variable, kind, default, whether it is required and the spellings it takes."
	header           = "| Key | Variable | Kind | Default | Required | Values |\n| --- | --- | --- | --- | --- | --- |\n"
	collectionHeader = "| Key | Variable | One element |\n| --- | --- | --- |\n"
)

// Page renders the reference page for fields, which are the loader's own
// listing in its order, and for the lists and maps the loader binds. It
// refuses an empty listing, a key listed twice and a value a table row
// cannot carry.
func Page(fields []gatewayconfig.Field) ([]byte, error) {
	return render(fields, gatewayconfig.Collections())
}

func render(fields []gatewayconfig.Field, collections []gatewayconfig.Collection) ([]byte, error) {
	if len(fields) == 0 || len(collections) == 0 {
		return nil, errors.New("a table is empty; refusing to render a page listing no keys")
	}
	head, err := frontmatter.Render(frontmatter.Meta{
		Title:     title,
		Summary:   summary,
		Type:      "reference",
		Covers:    []string{"internal/gatewayconfig/**", "internal/classify/**", "cmd/" + brand.Gateway + "/**"},
		Generated: Generator,
	})
	if err != nil {
		return nil, err
	}
	listDefault, err := defaultOf(listTimeoutKey)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(head)
	buf.WriteString("\n")
	rule, err := classificationRule()
	if err != nil {
		return nil, err
	}
	buf.WriteString(lead(listDefault, rule))
	buf.WriteString(header)
	seen := map[string]bool{}
	for _, f := range fields {
		if seen[f.Path] {
			return nil, fmt.Errorf("%s is listed twice", f.Path)
		}
		seen[f.Path] = true
		row, err := renderRow(f)
		if err != nil {
			return nil, err
		}
		buf.WriteString(row)
	}
	buf.WriteString(between())
	buf.WriteString(collectionHeader)
	for _, c := range collections {
		if seen[c.Path] {
			return nil, fmt.Errorf("%s is listed twice", c.Path)
		}
		seen[c.Path] = true
		row, err := collectionRow(c)
		if err != nil {
			return nil, err
		}
		buf.WriteString(row)
	}
	buf.WriteString(tail())
	return buf.Bytes(), nil
}

// listTimeoutKey is the key whose zero is not the key's own default but the
// adapter's bound, which is longer.
const listTimeoutKey = "upstream.list_timeout"

// defaultOf is the default the loader's table gives path.
func defaultOf(path string) (string, error) {
	for _, f := range gatewayconfig.Fields() {
		if f.Path == path {
			return f.Default, nil
		}
	}
	return "", fmt.Errorf("%s is not a key of the loader's table", path)
}

// classificationRule is what an override or a tool is refused for beyond its
// table: a classification whose every call the contract would refuse.
func classificationRule() (string, error) {
	var needsID, needsZone, needsEnv, needsTenant []string
	for _, name := range classify.EffectNames() {
		effect, err := contract.ParseEffect(name)
		if err != nil {
			return "", fmt.Errorf("classify lists the effect class %s, which the contract does not parse: %w", name, err)
		}
		requires := contract.EffectRequires(effect)
		if slices.Contains(requires, "resource.id") {
			needsID = append(needsID, "`"+name+"`")
		}
		if slices.Contains(requires, "destination.trust_zone") {
			needsZone = append(needsZone, "`"+name+"`")
		}
		env, resourceEnv := slices.Contains(requires, "environment"), slices.Contains(requires, "resource.environment")
		if env != resourceEnv {
			return "", fmt.Errorf("configdoc: %s needs one of environment and resource.environment; the sentence names both", name)
		}
		if env {
			needsEnv = append(needsEnv, "`"+name+"`")
		}
		if slices.Contains(requires, "resource.tenant_id") {
			needsTenant = append(needsTenant, "`"+name+"`")
		}
	}
	return "An entry of `overrides` or `tools` is refused when no call to its tool could carry\n" +
		"an envelope the contract takes: `resource_type` is an identifier of at most " + strconv.Itoa(contract.MaxStringBytes) + " bytes,\n" +
		"`resource_from` an RFC 6901 pointer of at most " + strconv.Itoa(classify.MaxPointerTokens) + " tokens of " + strconv.Itoa(classify.MaxPointerTokenSize) + " bytes, an effect whose\n" +
		"envelope needs a resource id (" + joinAnd(needsID) + ") needs `resource_from`, and\n" +
		joinAnd(needsZone) + " needs `trust_zone`; " + joinAnd(needsEnv) + " need `environment` set, and in\n" +
		"an override its upstream's `environment` too, and in an override " + joinAnd(needsTenant) + "\n" +
		"need the upstream's `tenant_id`; a tool's `name` and `provider`, and an upstream's\n" +
		"`name`, which is every call's `action.provider`, are identifiers of at most " + strconv.Itoa(contract.MaxStringBytes) + " bytes too. An identifier is held to the contract's rule\n" +
		"([contracts](../contracts.md#decoding-and-validation)): invalid UTF-8 is refused, and so\n" +
		"are White_Space at either end and, anywhere, a space other than U+0020, a code point in\n" +
		"Cc, Cf, Zl or Zp, or a Default_Ignorable_Code_Point.", nil
}

// joinAnd joins names as a sentence lists them.
func joinAnd(names []string) string {
	switch len(names) {
	case 0:
		return "none"
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func lead(listDefault, classificationRule string) string {
	return "# " + title + "\n\n" +
		"The gateway reads one file, named by `--config`, and then the environment: a variable\n" +
		"named `" + brand.EnvPrefix + "` followed by a key's path in upper case, with each dot an\n" +
		"underscore, sets that key and wins over the file. A key the table does not declare is\n" +
		"refused rather than ignored, and a required key with no default has to be set by the\n" +
		"file or by a variable. A key with a default is never without a value, so `yes` under\n" +
		"Required matters only where the default is empty. Some requirements depend on another\n" +
		"key and are not in the table: an MCP HTTP listener needs `listener.address`, and only a\n" +
		"`stateful_http` listener takes `listener.session_idle`, from one minute to a day, and\n" +
		"`listener.max_sessions`, from 1 to 16384; an upstream\n" +
		"needs exactly one of `endpoint` and `command`; `evidence.fsync_interval` is needed\n" +
		"under the `interval` policy and refused under `every_record`; the `file` approval\n" +
		"provider needs `approvals.dir` and `approvals.hold_journal_dir`, and that journal\n" +
		"directory may be neither the spool's nor the approvals directory, nor inside either;\n" +
		"and `APPROVE` needs the `file` provider, since nothing outside the process answers a\n" +
		"request held in memory. " + classificationRule + " An `enforce_api` listener serves the enforcement API on the Unix\n" +
		"socket `listener.socket` names, at most 103 bytes as it resolves; the plane checks that\n" +
		"the socket's directory is its own with no permission for group or others, and checks\n" +
		"neither a macOS access control list on it nor a parent directory another account may\n" +
		"write. It needs `runs.dir`, `listener.execution_lifetime`, from one\n" +
		"second to an hour with no default, and at least one entry of `tools`, each name once;\n" +
		"`listener.max_body_bytes` takes 1KiB to 256KiB, `listener.max_open_per_run` is\n" +
		"positive and below `approvals.max_open`, and a tool's resource has the plane's\n" +
		"`tenant_id` and `environment`. It refuses `listener.address`, `listener.origins`,\n" +
		"`upstreams`, `overrides` and the `upstream.` and `list.` keys, and every other kind refuses\n" +
		"`listener.socket`, `listener.execution_lifetime`, `listener.max_body_bytes`,\n" +
		"`listener.max_open_per_run` and `tools`.\n" +
		"`upstream.call_timeout`, `pdp.timeout` and `export.timeout` have\n" +
		"to be positive, so nothing waits on an upstream's call, the decision point or the\n" +
		"collector without a bound; `" + listTimeoutKey + "` may be zero, which is the adapter's\n" +
		"own bound of `" + adaptermcp.DefaultListTimeout.String() + "`, longer than the key's `" + listDefault + "` default, and no duration\n" +
		"may be negative. `runs.dir` may not be, hold or sit inside the spool, the\n" +
		"approvals directory, the hold journal or the pause file's directory, needs a\n" +
		"`listener.principal.type`, and refuses `flow.max_runs`, which bounds only the runs a\n" +
		"plane keeps in memory. `reaction.route`, `reaction.public_key`, `reaction.floor_dir` and\n" +
		"`reaction.stops` are set together or not at all; a route needs `runs.dir`,\n" +
		"`reaction.poll_interval` takes 100ms to a minute, and the stops directory may not be,\n" +
		"hold or sit inside the runs directory, the spool, the approvals directory, the hold\n" +
		"journal, either floor directory or the pause file's directory, compared through\n" +
		"symbolic links too. Every `pdp.` key is refused while `pdp.identifier` is empty,\n" +
		"since it would apply to no decision point, and the identifier is written into every\n" +
		"decision that consulted the decision point, so a credential goes in `pdp.headers`,\n" +
		"never in it. Other directories are compared as paths and not as what they\n" +
		"reach: two paths that are one directory through a symbolic link are not refused, and\n" +
		"a pair this build cannot compare, such as one across volumes, is refused rather than\n" +
		"allowed.\n\n" +
		"Rendered from the field table in `internal/gatewayconfig`. Rebuild it with\n" +
		"`make docs-gen`; an edit made here does not survive the next run.\n\n"
}

func between() string {
	return "\nThese keys hold a list or a map, one element per key:\n\n"
}

func tail() string {
	n := gatewayconfig.IndexPlaceholder
	return "\n`" + n + "` in a key is an entry's index, from 0, and `" + gatewayconfig.NamePlaceholder + "` a name the operator\n" +
		"chooses. A variable for a key under `" + n + "` sets an entry the file declares; it never adds\n" +
		"one. In the variable of a header each `_` stands for a `-` in the header's name.\n" +
		"Header names are compared without case, so a variable wins over the file however\n" +
		"either spells the name. A name the file or the environment spells twice is refused,\n" +
		"and so is a `_` in a header's name in the file, since no variable could replace it.\n" +
		"A relative path resolves against the directory of the file.\n"
}

func collectionRow(c gatewayconfig.Collection) (string, error) {
	for _, cell := range []string{c.Path, c.Env, c.Holds} {
		if cell == "" {
			return "", fmt.Errorf("%q: a list or map key needs a path, a variable and what it holds", c.Path)
		}
		if err := checkCell(cell); err != nil {
			return "", fmt.Errorf("%s: %w", c.Path, err)
		}
	}
	return fmt.Sprintf("| `%s` | `%s` | %s |\n", c.Path, c.Env, c.Holds), nil
}

func renderRow(f gatewayconfig.Field) (string, error) {
	for _, cell := range append([]string{f.Path, f.Env, f.Kind, f.Default}, f.Values...) {
		if err := checkCell(cell); err != nil {
			return "", fmt.Errorf("%s: %w", f.Path, err)
		}
	}
	if f.Path == "" || f.Env == "" || f.Kind == "" {
		return "", fmt.Errorf("%q: a key needs a path, a variable and a kind", f.Path)
	}
	required := "no"
	if f.Required {
		required = "yes"
	}
	note := values(f.Values)
	if f.Path == listTimeoutKey {
		note = "bounds reading one upstream's list, and connecting to each upstream at start; `0` is the adapter's own `" + adaptermcp.DefaultListTimeout.String() + "`"
	}
	return fmt.Sprintf("| `%s` | `%s` | %s | %s | %s | %s |\n",
		f.Path, f.Env, f.Kind, code(f.Default), required, note), nil
}

// code spells a value in code font, and nothing for an empty one.
func code(v string) string {
	if v == "" {
		return ""
	}
	return "`" + v + "`"
}

// values spells the admitted set. An empty spelling is a value the loader
// takes, so it is named rather than dropped.
func values(list []string) string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v == "" {
			out = append(out, "an empty value")
			continue
		}
		out = append(out, code(v))
	}
	return strings.Join(out, ", ")
}

// checkCell refuses text a table cell in code font cannot carry as it is:
// the pipe that ends the cell, the backtick that ends the code span, and
// every control, format or separator character.
func checkCell(s string) error {
	if i := strings.IndexFunc(s, breaksTheRow); i >= 0 {
		return fmt.Errorf("%q holds %U at byte %d, which a table row cannot carry", s, []rune(s[i:])[0], i)
	}
	return nil
}

func breaksTheRow(r rune) bool {
	return r == '|' || r == '`' || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029
}
