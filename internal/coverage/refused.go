package coverage

import (
	"fmt"
	"maps"
	"math/bits"
	"slices"
	"strings"

	"github.com/guardana/control/internal/observe"
)

// maxReasonsPrinted bounds the reasons one refused row names.
const maxReasonsPrinted = 16

// unnamedReason is how a row counts the refusals a report gives no reason
// for.
const unnamedReason = "no reason given"

// RefusedSource is an egress source whose own import reports count lines the
// importer refused: connections that happened and whose destination nobody
// read, so no path can be said to cover them.
type RefusedSource struct {
	SourceID string
	// Refused is the lines refused over every report of the source, live or
	// not, since a past refusal is still a connection nobody read.
	Refused uint64
	// By counts them by the reason the reports name, a reason no report
	// names under unnamedReason.
	By map[string]uint64
}

// refused is a row for every egress source given whose import reports count
// a refused line, in the order the sources were given.
func (in Input) refused() []RefusedSource {
	var out []RefusedSource
	for i := range in.Sources {
		d := in.Sources[i].Descriptor
		if d.GetKind() != observe.KindEgressAccessLog {
			continue
		}
		row := RefusedSource{SourceID: d.GetSourceId(), By: map[string]uint64{}}
		for _, r := range in.Sources[i].Records {
			rep := r.GetImportReport()
			if !observe.Reports(d, rep) || rep.GetCounts().GetRefused() == 0 {
				continue
			}
			c := rep.GetCounts()
			row.Refused = addCount(row.Refused, c.GetRefused())
			var named uint64
			for reason, n := range c.GetRefusedBy() {
				row.By[reason] = addCount(row.By[reason], n)
				named = addCount(named, n)
			}
			if named < c.GetRefused() {
				row.By[unnamedReason] = addCount(row.By[unnamedReason], c.GetRefused()-named)
			}
		}
		if row.Refused > 0 {
			out = append(out, row)
		}
	}
	return out
}

// addCount adds two counts, holding at the largest a count can be rather
// than wrapping to a small one.
func addCount(a, b uint64) uint64 {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return ^uint64(0)
	}
	return sum
}

// refusedLines prints a row per refused source.
func refusedLines(rows []RefusedSource) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		reasons := slices.Sorted(maps.Keys(r.By))
		shown := reasons[:min(len(reasons), maxReasonsPrinted)]
		parts := make([]string, 0, len(shown))
		for _, reason := range shown {
			parts = append(parts, fmt.Sprintf("%s %d", printable(reason), r.By[reason]))
		}
		list := strings.Join(parts, ", ")
		if more := len(reasons) - len(shown); more > 0 {
			list += fmt.Sprintf(" and %d more reasons", more)
		}
		noun := "lines"
		if r.Refused == 1 {
			noun = "line"
		}
		out = append(out, fmt.Sprintf("refused egress by %s: %d %s refused, so their connections are unknown: %s; %s",
			printable(r.SourceID), r.Refused, noun, list, NoPlaneDecidesEgress))
	}
	return out
}
