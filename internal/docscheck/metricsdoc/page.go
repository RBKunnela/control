// Package metricsdoc renders the metrics reference page from the table
// /metrics writes, so the page lists exactly the metrics a plane answers: a
// row added to the table appears here at the next `make docs-gen`, and the
// pin test fails until it does.
//
// Rendering is a pure function of the table. scripts/gen-metrics.go is the
// thin writer that puts the result on disk, and the pin test calls Page
// directly.
package metricsdoc

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/guardana/control/internal/docscheck/frontmatter"
	"github.com/guardana/control/internal/metrics"
)

// Generator is the script that writes the page, as the frontmatter names it.
const Generator = "scripts/gen-metrics.go"

// Path is where the page lives, relative to the repository root.
const Path = "docs/reference/metrics.md"

const (
	title   = "Metrics"
	summary = "Every metric a plane answers on /metrics, with its type, its label, the statistic it reads and what it counts."
	header  = "| Metric | Type | Label | Reads | Meaning |\n| --- | --- | --- | --- | --- |\n"
)

// Page renders the reference page for table, which is the renderer's own
// table in its order. It refuses an empty table, a name listed twice, a
// name outside the prefix and a cell a table row cannot carry.
func Page(table []metrics.Metric) ([]byte, error) {
	if len(table) == 0 {
		return nil, errors.New("the table is empty; refusing to render a page listing no metric")
	}
	head, err := frontmatter.Render(frontmatter.Meta{
		Title:     title,
		Summary:   summary,
		Type:      "reference",
		Covers:    []string{"internal/metrics/**"},
		Generated: Generator,
	})
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(head)
	buf.WriteString("\n")
	buf.WriteString(lead())
	buf.WriteString(header)
	seen := map[string]bool{}
	for _, m := range table {
		if seen[m.Name] {
			return nil, fmt.Errorf("%s is listed twice", m.Name)
		}
		seen[m.Name] = true
		line, err := row(m)
		if err != nil {
			return nil, err
		}
		buf.WriteString(line)
	}
	return buf.Bytes(), nil
}

func row(m metrics.Metric) (string, error) {
	if !strings.HasPrefix(m.Name, metrics.Prefix()) {
		return "", fmt.Errorf("%s does not begin with %s", m.Name, metrics.Prefix())
	}
	for _, cell := range []string{m.Name, string(m.Type), m.Label, m.Reads, m.Help} {
		if i := strings.IndexFunc(cell, breaksTheRow); i >= 0 {
			return "", fmt.Errorf("%s: %q holds %U, which a table row cannot carry", m.Name, cell, []rune(cell[i:])[0])
		}
	}
	if m.Type == "" || m.Reads == "" || m.Help == "" {
		return "", fmt.Errorf("%s: a metric needs a type, a statistic and a meaning", m.Name)
	}
	label := ""
	if m.Label != "" {
		label = "`" + m.Label + "`"
	}
	return fmt.Sprintf("| `%s` | %s | %s | `%s` | %s |\n", m.Name, m.Type, label, m.Reads, m.Help), nil
}

func lead() string {
	return "# " + title + "\n\n" +
		"The health listener answers `GET /metrics` in the Prometheus text exposition format,\n" +
		"version 0.0.4, with the content type `" + metrics.ContentType + "`.\n" +
		"Every name begins with `" + metrics.Prefix() + "`. A counter ends in `_total` and counts\n" +
		"from the plane's start; a gauge is a value now. The flags are the gauges whose meaning\n" +
		"begins \"1 when\", and read 1 or 0. Times are in seconds and sizes in bytes.\n\n" +
		"A spool that cannot answer sets `" + metrics.Prefix() + "spool_broken` to 1, and every other\n" +
		"metric reading the spool is left out of the text rather than written as zero; the rest\n" +
		"is still answered. A reading the text cannot carry truthfully answers 503 with no body:\n" +
		"a counter below zero, a pause state outside the four, a freshness state outside the\n" +
		"three, or counts outside a label's closed set that sum past a counter's range.\n\n" +
		"A plane whose listener serves the enforcement API writes the `" + metrics.Prefix() + "enforce_`\n" +
		"metrics and leaves out the MCP adapter's `" + metrics.Prefix() + "adapter_` ones; any other\n" +
		"plane does the reverse, and `" + metrics.Prefix() + "listener_enforce_api` says which.\n\n" +
		"`" + metrics.Prefix() + "pipeline_halted` is not the only thing that stops calls. While it\n" +
		"reads 0, an unknown pause state takes no call at all, which `" + metrics.Prefix() + "pause_state`\n" +
		"reports under `state=\"unknown\"`; in every mode but OBSERVE a policy that is not\n" +
		"confirmed blocks every call but a read under `policy.fail_open_read`, which\n" +
		"`" + metrics.Prefix() + "policy_freshness`\n" +
		"reports; and a refused evidence append\n" +
		"blocks the call it records, which `" + metrics.Prefix() + "pipeline_sink_failures_before_effect_total`\n" +
		"counts.\n\n" +
		"No label carries an identifier, a digest or a reason: `code` is a code of the reason\n" +
		"registry, or an error code of the enforcement API contract in lower case without its\n" +
		"`ERROR_CODE_` prefix; `cause` is why a read of the pause file was unknown, why a run token did not\n" +
		"resolve, or why a poll of the policy moved nothing; and `state` is one of the four pause\n" +
		"states or the three freshness states. A code or a cause outside its set is counted under\n" +
		"`" + metrics.Other + "`, so no count is dropped. Reads names the statistic: `Pipeline` is the\n" +
		"pipeline's, `Adapter` the MCP adapter's, `Enforce` the enforcement API adapter's,\n" +
		"`Pause` the pause file reader's, `Policy` the\n" +
		"policy refresher's, `Spool` the evidence spool's and `Exporter` the exporter's.\n\n" +
		"Rendered from the table in `internal/metrics`. Rebuild it with `make docs-gen`; an\n" +
		"edit made here does not survive the next run.\n\n"
}

func breaksTheRow(r rune) bool {
	return r == '|' || r == '`' || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029
}
