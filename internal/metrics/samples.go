package metrics

import (
	"errors"
	"fmt"
	"maps"
	"math/bits"
	"slices"
	"strconv"
	"strings"

	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy/reasons"
)

// pauseStates is every state a pause state gauge has a sample for.
var pauseStates = []pause.State{pause.Unknown, pause.Disabled, pause.Clear, pause.Paused}

func count(name, reads, help string, v func(Reading) uint64) Metric {
	return Metric{Name: Prefix() + name, Type: Counter, Help: help, Reads: reads,
		read: func(r Reading) ([]sample, error) { return one(strconv.FormatUint(v(r), 10)), nil }}
}

func level(name, reads, help string, v func(Reading) int64) Metric {
	return Metric{Name: Prefix() + name, Type: Gauge, Help: help, Reads: reads,
		read: func(r Reading) ([]sample, error) { return one(strconv.FormatInt(v(r), 10)), nil }}
}

func flag(name, reads, help string, v func(Reading) bool) Metric {
	return level(name, reads, help, func(r Reading) int64 {
		if v(r) {
			return 1
		}
		return 0
	})
}

func labelled(t Type, name, label, reads, help string, read func(Reading) ([]sample, error)) Metric {
	return Metric{Name: Prefix() + name, Type: t, Help: help, Label: label, Reads: reads, read: read}
}

// signed is a counter its seam keeps as a signed number; Render refuses one
// below zero.
func signed(name, reads, help string, v func(Reading) int64) Metric {
	m := level(name, reads, help, v)
	m.Type = Counter
	return m
}

func one(value string) []sample { return []sample{{value: value}} }

// blockSamples is one sample per code the reason registry holds, in order,
// and one labelled Other for the rest, so a label carries a documented code
// and never an identifier or a reason, and no block goes uncounted.
func blockSamples(blocks map[string]uint64) ([]sample, error) {
	return closedSamples(blocks, func(code string) bool {
		_, ok := reasons.Lookup(code)
		return ok
	})
}

// runSamples writes the count of every run refusal cause counted at least
// once, in their order, and the sum of any other key last, labelled Other.
func runSamples(counts map[gateway.RunCause]uint64) ([]sample, error) {
	causes := gateway.RunCauses()
	out := make([]sample, 0, len(causes)+1)
	for _, cause := range causes {
		if n := counts[cause]; n > 0 {
			out = append(out, sample{string(cause), strconv.FormatUint(n, 10)})
		}
	}
	others := maps.Clone(counts)
	maps.DeleteFunc(others, func(c gateway.RunCause, _ uint64) bool { return slices.Contains(causes, c) })
	rest, err := closedSamples(others, func(gateway.RunCause) bool { return false })
	if err != nil {
		return nil, err
	}
	return append(out, rest...), nil
}

func causeSamples(failed map[pause.Cause]uint64) ([]sample, error) {
	return closedSamples(failed, func(c pause.Cause) bool { return slices.Contains(pause.Causes(), c) })
}

// closedSamples writes the counts of the keys known holds under their own
// label, in order, and the sum of the others last, labelled Other. A sum past
// a counter's range is refused rather than written wrapped.
func closedSamples[K ~string](counts map[K]uint64, known func(K) bool) ([]sample, error) {
	out := make([]sample, 0, len(counts))
	var other uint64
	var outside bool
	for _, k := range sortedKeys(counts) {
		if known(k) {
			out = append(out, sample{string(k), strconv.FormatUint(counts[k], 10)})
			continue
		}
		sum, carry := bits.Add64(other, counts[k], 0)
		if carry != 0 {
			return nil, fmt.Errorf("the counts labelled %s pass a counter's range", Other)
		}
		other, outside = sum, true
	}
	if outside {
		out = append(out, sample{Other, strconv.FormatUint(other, 10)})
	}
	return out, nil
}

func stateSamples(state pause.State) ([]sample, error) {
	if !slices.Contains(pauseStates, state) {
		return nil, errors.New("a pause state outside the four")
	}
	out := make([]sample, 0, len(pauseStates))
	for _, s := range pauseStates {
		v := "0"
		if s == state {
			v = "1"
		}
		out = append(out, sample{s.String(), v})
	}
	return out, nil
}

// seconds spells a count of microseconds in seconds, exactly: a float would
// round a large count.
func seconds(micros uint64) string {
	s := strconv.FormatUint(micros/1_000_000, 10)
	if frac := micros % 1_000_000; frac != 0 {
		s += "." + strings.TrimRight(fmt.Sprintf("%06d", frac), "0")
	}
	return s
}

func sortedKeys[K ~string, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
