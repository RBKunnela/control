package metrics

import (
	"maps"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/metrics/metricstest"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy/reasons"
	"github.com/guardana/control/internal/policywatch"
)

// leaf is one statistic of a Reading: a number, a flag or a map of counts,
// named by its dotted path.
type leaf struct {
	path  string
	index []int
	kind  reflect.Kind
}

// leaves walks every field of t, into nested structs, and fails on a field
// of a shape no metric could carry, so a new field is never skipped.
func leaves(t *testing.T, typ reflect.Type, prefix string, index []int) []leaf {
	t.Helper()
	var out []leaf
	for i := range typ.NumField() {
		f := typ.Field(i)
		path := prefix + f.Name
		at := append(append([]int(nil), index...), i)
		if !f.IsExported() {
			t.Errorf("%s is unexported; no metric can read it", path)
			continue
		}
		switch k := f.Type.Kind(); k {
		case reflect.Struct:
			out = append(out, leaves(t, f.Type, path+".", at)...)
		case reflect.Bool, reflect.Int, reflect.Int64, reflect.Uint8, reflect.Uint64:
			out = append(out, leaf{path, at, k})
		case reflect.Map:
			if f.Type.Key().Kind() != reflect.String || f.Type.Elem().Kind() != reflect.Uint64 {
				t.Errorf("%s is a map of %v to %v, which no labelled counter reads", path, f.Type.Key(), f.Type.Elem())
				continue
			}
			out = append(out, leaf{path, at, k})
		default:
			t.Errorf("%s is a %v, which no metric reads", path, f.Type)
		}
	}
	return out
}

func readingLeaves(t *testing.T) []leaf {
	t.Helper()
	all := leaves(t, reflect.TypeFor[Reading](), "", nil)
	if len(all) < 50 {
		t.Fatalf("the walk found %d statistics; the seams hold more than 50", len(all))
	}
	return all
}

// TestEveryStatisticHasOneMetric walks the structs the seams return: a field
// added to any of them without a row fails here, and so does a row naming a
// field that does not exist.
func TestEveryStatisticHasOneMetric(t *testing.T) {
	readers := map[string][]string{}
	for _, m := range Table() {
		readers[m.Reads] = append(readers[m.Reads], m.Name)
	}
	known := map[string]bool{}
	for _, l := range readingLeaves(t) {
		known[l.path] = true
		if len(readers[l.path]) != 1 {
			t.Errorf("%s is read by %v, want exactly one metric", l.path, readers[l.path])
		}
	}
	for path, names := range readers {
		if !known[path] {
			t.Errorf("%v read %q, which is no statistic of a Reading", names, path)
		}
	}
}

// TestEachMetricReadsItsOwnStatistic sets one statistic at a time to a value
// no other has and reads the text back under the strict reader: the metric
// that claims the statistic carries it, and every other metric is what it is
// for a zero reading. A row reading a neighbour's field fails here.
func TestEachMetricReadsItsOwnStatistic(t *testing.T) {
	base := map[bool][]metricstest.Family{false: parse(t, Reading{}), true: parse(t, Reading{EnforceAPI: true})}
	code := reasons.All()[0].ID
	for i, l := range readingLeaves(t) {
		if l.path == "PauseState" || l.path == "PolicyFreshness" {
			continue
		}
		r, key, raw := readingWith(t, l, uint64(1_000_003+7919*i), code)
		got := parse(t, r)
		for _, m := range Table() {
			fam, found := metricstest.Find(got, m.Name)
			if leftOut(r, m) {
				if found {
					t.Errorf("setting %s left %s in: %+v", l.path, m.Name, fam.Samples)
				}
				continue
			}
			if m.Reads != l.path {
				if !reflect.DeepEqual(fam, family(t, base[r.EnforceAPI], m.Name)) {
					t.Errorf("setting %s changed %s: %+v", l.path, m.Name, fam.Samples)
				}
				continue
			}
			carries(t, m, fam, l, key, raw)
		}
	}
}

// carries checks that fam, the family of m, is one sample of raw, under key
// where l is a map.
func carries(t *testing.T, m Metric, fam metricstest.Family, l leaf, key, raw string) {
	t.Helper()
	labels := map[string]string{}
	if l.kind == reflect.Map {
		labels = map[string]string{m.Label: key}
	}
	s, ok := fam.One(labels)
	switch {
	case !ok || len(fam.Samples) != 1:
		t.Errorf("%s: no single sample %v for %s: %+v", m.Name, labels, l.path, fam.Samples)
	case l.path == "Pipeline.Asks.Micros":
		if microsOf(s.Raw) != raw {
			t.Errorf("%s is %s for %s microseconds, want seconds", m.Name, s.Raw, raw)
		}
	case s.Raw != raw:
		t.Errorf("%s is %s, want %s from %s", m.Name, s.Raw, raw, l.path)
	}
}

// readingWith is a zero Reading but for the statistic l, set to v: a flag
// is set, and a map holds v under one key, code for the blocks. A statistic of
// the enforcement API adapter is read on a plane that serves it. It returns
// the key and the value as the text has to spell it.
func readingWith(t *testing.T, l leaf, v uint64, code string) (r Reading, key, raw string) {
	t.Helper()
	r.EnforceAPI = strings.HasPrefix(l.path, "Enforce.")
	field := reflect.ValueOf(&r).Elem().FieldByIndex(l.index)
	raw = strconv.FormatUint(v, 10)
	switch l.kind {
	case reflect.Bool:
		field.SetBool(true)
		raw = "1"
	case reflect.Int, reflect.Int64, reflect.Uint64:
		field.Set(reflect.ValueOf(v).Convert(field.Type()))
	case reflect.Map:
		key = string(pause.CauseStale)
		switch l.path {
		case "Pipeline.Blocks":
			key = code
		case "Adapter.RunsRefusedAtRequest", "Adapter.RunsRefusedAtMessage", "Enforce.RunsRefused":
			key = string(gateway.RunClosed)
		case "Enforce.Refused":
			key = "handle_spent"
		case "Policy.Refused":
			key = string(policywatch.CauseStatementFuture)
		}
		m := reflect.MakeMap(field.Type())
		m.SetMapIndex(reflect.ValueOf(key).Convert(field.Type().Key()), reflect.ValueOf(v))
		field.Set(m)
	default:
		t.Fatalf("%s: no value for a %v", l.path, l.kind)
	}
	return r, key, raw
}

// TestABrokenSpoolLeavesOutOnlyItsOwn: a spool that reports an error leaves
// out every metric that reads the spool and sets spool_broken; every other
// metric is still written, and the same reading with a sound spool writes the
// spool's metrics with their values.
func TestABrokenSpoolLeavesOutOnlyItsOwn(t *testing.T) {
	var r Reading
	r.Spool.Bytes, r.Spool.Segments, r.Pipeline.Executed = 4096, 3, 7
	sound := parse(t, r)
	r.SpoolBroken = true
	broken := parse(t, r)
	left := 0
	for _, m := range Table() {
		if !readsSpool(m) {
			continue
		}
		left++
		if _, ok := metricstest.Find(broken, m.Name); ok {
			t.Errorf("a broken spool still writes %s", m.Name)
		}
		if _, ok := metricstest.Find(sound, m.Name); !ok {
			t.Errorf("a sound spool does not write %s", m.Name)
		}
	}
	if left < 10 {
		t.Errorf("%d metrics read the spool; the spool's statistics hold more", left)
	}
	for name, want := range map[string][2]string{
		"spool_broken": {"0", "1"}, "spool_bytes": {"4096", ""}, "pipeline_executed_total": {"7", "7"},
	} {
		for i, families := range [][]metricstest.Family{sound, broken} {
			got := ""
			if f, ok := metricstest.Find(families, Prefix()+name); ok {
				s, _ := f.One(map[string]string{})
				got = s.Raw
			}
			if got != want[i] {
				t.Errorf("%s reads %q with the spool broken %v, want %q", name, got, i == 1, want[i])
			}
		}
	}
}

// TestAValueOutsideItsSetIsCountedUnderOther: a block code the registry does
// not hold, and a cause the pause reader does not declare, are never written
// as a label and never dropped: each is added to the sample labelled other,
// which is last. other is itself in neither set.
func TestAValueOutsideItsSetIsCountedUnderOther(t *testing.T) {
	code := reasons.All()[0].ID
	if _, ok := reasons.Lookup(Other); ok || slices.Contains(pause.Causes(), pause.Cause(Other)) {
		t.Fatalf("%q is a code or a cause, so it cannot stand for neither", Other)
	}
	var r Reading
	r.Pipeline.Blocks = map[string]uint64{code: 1, code + "_X": 2, "": 3, Other: 4, "a \"quoted\" \\ code\n": 5}
	r.Pause.Failed = map[pause.Cause]uint64{pause.CauseStale: 1, "\xff": 2, "made up": 3}
	families := parse(t, r)
	for name, want := range map[string][]metricstest.Sample{
		"pipeline_blocks_total":     {{Labels: map[string]string{"code": code}, Raw: "1"}, {Labels: map[string]string{"code": Other}, Raw: "14"}},
		"pause_poll_failures_total": {{Labels: map[string]string{"cause": string(pause.CauseStale)}, Raw: "1"}, {Labels: map[string]string{"cause": Other}, Raw: "5"}},
	} {
		f := family(t, families, Prefix()+name)
		if len(f.Samples) != len(want) {
			t.Errorf("%s: %+v, want %+v", name, f.Samples, want)
			continue
		}
		for i, s := range f.Samples {
			if !maps.Equal(s.Labels, want[i].Labels) || s.Raw != want[i].Raw {
				t.Errorf("%s: sample %d is %v %s, want %v %s", name, i, s.Labels, s.Raw, want[i].Labels, want[i].Raw)
			}
		}
	}
}

// TestFlagsAreTheMetricsWhoseHelpSaysOneWhen: the page tells a flag by its
// help, so a metric reading a yes or no begins its help "1 when", and no
// other metric does.
func TestFlagsAreTheMetricsWhoseHelpSaysOneWhen(t *testing.T) {
	flags := map[string]bool{}
	for _, l := range readingLeaves(t) {
		flags[l.path] = l.kind == reflect.Bool
	}
	for _, m := range Table() {
		if says := strings.HasPrefix(m.Help, "1 when "); says != flags[m.Reads] {
			t.Errorf("%s reads %s, a flag %v, and its help %q", m.Name, m.Reads, flags[m.Reads], m.Help)
		}
	}
}

// zeroStates is the state a zero reading is in, by the statistic that holds it.
var zeroStates = map[string]string{"PauseState": "unknown", "PolicyFreshness": "unconfirmed"}

// TestAZeroReadingIsZero: before anything is counted every metric without a
// label is 0, a labelled counter has no sample, the pause state is unknown and
// the policy unconfirmed, which are the zero states.
func TestAZeroReadingIsZero(t *testing.T) {
	for _, f := range slices.Concat(parse(t, Reading{}), parse(t, Reading{EnforceAPI: true})) {
		m := metric(t, f.Name)
		switch {
		case zeroStates[m.Reads] != "":
			if s, ok := f.One(map[string]string{"state": zeroStates[m.Reads]}); !ok || s.Raw != "1" {
				t.Errorf("the zero %s is not %s: %+v", m.Reads, zeroStates[m.Reads], f.Samples)
			}
		case m.Label != "":
			if len(f.Samples) != 0 {
				t.Errorf("%s has samples before anything was counted: %+v", f.Name, f.Samples)
			}
		default:
			if s, ok := f.One(map[string]string{}); !ok || len(f.Samples) != 1 || (s.Raw != "0" && m.Reads != "EnforceAPI") {
				t.Errorf("%s is not one 0: %+v", f.Name, f.Samples)
			}
		}
	}
}

func TestTheFreshnessStateIsOneOfThree(t *testing.T) {
	for state, name := range map[policywatch.State]string{
		policywatch.Unconfirmed: "unconfirmed", policywatch.Confirmed: "confirmed", policywatch.Expired: "expired",
	} {
		f := family(t, parse(t, Reading{PolicyFreshness: state}), Prefix()+"policy_freshness")
		if len(f.Samples) != 3 {
			t.Errorf("%s: %d samples, want one per state", name, len(f.Samples))
		}
		for _, s := range f.Samples {
			want := "0"
			if s.Labels["state"] == name {
				want = "1"
			}
			if s.Raw != want {
				t.Errorf("under %s the sample %v is %s, want %s", name, s.Labels, s.Raw, want)
			}
		}
	}
}

// TestARefreshCauseOutsideTheSetIsCountedUnderOther: the refresher's causes
// are a closed set like the pause reader's.
func TestARefreshCauseOutsideTheSetIsCountedUnderOther(t *testing.T) {
	var r Reading
	r.Policy.Refused = map[policywatch.Cause]uint64{policywatch.CauseFloor: 2, "made up": 3}
	f := family(t, parse(t, r), Prefix()+"policy_refresh_refused_total")
	want := []metricstest.Sample{{Labels: map[string]string{"cause": "floor"}, Raw: "2"}, {Labels: map[string]string{"cause": Other}, Raw: "3"}}
	if len(f.Samples) != len(want) {
		t.Fatalf("%+v, want %+v", f.Samples, want)
	}
	for i, s := range f.Samples {
		if !maps.Equal(s.Labels, want[i].Labels) || s.Raw != want[i].Raw {
			t.Errorf("sample %d is %v %s, want %v %s", i, s.Labels, s.Raw, want[i].Labels, want[i].Raw)
		}
	}
	if slices.Contains(policywatch.Causes(), policywatch.Cause(Other)) {
		t.Fatalf("%q is a refresh cause, so it cannot stand for none", Other)
	}
}

func TestThePauseStateIsOneOfFour(t *testing.T) {
	for state, name := range map[pause.State]string{
		pause.Unknown: "unknown", pause.Disabled: "disabled", pause.Clear: "clear", pause.Paused: "paused",
	} {
		f := family(t, parse(t, Reading{PauseState: state}), Prefix()+"pause_state")
		if len(f.Samples) != 4 {
			t.Errorf("%s: %d samples, want one per state", name, len(f.Samples))
		}
		for _, s := range f.Samples {
			want := "0"
			if s.Labels["state"] == name {
				want = "1"
			}
			if s.Raw != want {
				t.Errorf("under %s the sample %v is %s, want %s", name, s.Labels, s.Raw, want)
			}
		}
	}
}

var nameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// TestNamesFollowTheConventions: one prefix, `_total` on counters and only
// there, base units, a label only where a statistic is a map or a state, and
// no label that could carry an identifier, a digest or a reason.
func TestNamesFollowTheConventions(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Table() {
		if seen[m.Name] {
			t.Errorf("%s is in the table twice", m.Name)
		}
		seen[m.Name] = true
		if !strings.HasPrefix(m.Name, Prefix()) || !nameRE.MatchString(m.Name) {
			t.Errorf("%s is not a lower-case name under %s", m.Name, Prefix())
		}
		if strings.HasSuffix(m.Name, "_total") != (m.Type == Counter) {
			t.Errorf("%s is a %s: `_total` belongs on counters and only there", m.Name, m.Type)
		}
		for _, word := range strings.Split(m.Name, "_") {
			if slices.Contains([]string{"us", "ms", "microseconds", "milliseconds", "minutes", "kib", "mib", "kb", "mb"}, word) {
				t.Errorf("%s is not in a base unit", m.Name)
			}
		}
		if m.Help == "" || strings.ContainsAny(m.Help, "\n\\|`") {
			t.Errorf("%s: help %q is empty or not one plain line", m.Name, m.Help)
		}
		wantLabel := map[string]string{
			"Pipeline.Blocks": "code", "Pause.Failed": "cause", "PauseState": "state",
			"Adapter.RunsRefusedAtRequest": "cause", "Adapter.RunsRefusedAtMessage": "cause",
			"Policy.Refused": "cause", "PolicyFreshness": "state", "Stops.Failed": "cause",
			"Enforce.Refused": "code", "Enforce.RunsRefused": "cause",
		}[m.Reads]
		if m.Label != wantLabel {
			t.Errorf("%s reads %s and has label %q, want %q", m.Name, m.Reads, m.Label, wantLabel)
		}
	}
}

// TestThePrefixIsTheProductsName derives the prefix from the name shown to a
// person, which is another road than the one the code takes.
func TestThePrefixIsTheProductsName(t *testing.T) {
	want := strings.ToLower(strings.ReplaceAll(brand.Name, " ", "_")) + "_"
	if Prefix() != want {
		t.Errorf("Prefix is %q, want %q", Prefix(), want)
	}
}

// Each refusal is paired with the nearest reading that renders.
func TestRenderRefuses(t *testing.T) {
	code := reasons.All()[0].ID
	for _, c := range []struct {
		name    string
		refused Reading
		taken   Reading
	}{
		{"a counter below zero", Reading{Adapter: statsSent(-1)}, Reading{Adapter: statsSent(0)}},
		{"a pause state outside the four", Reading{PauseState: pause.Paused + 1}, Reading{PauseState: pause.Paused}},
		{"a freshness state outside the three", Reading{PolicyFreshness: policywatch.Expired + 1}, Reading{PolicyFreshness: policywatch.Expired}},
		{"codes outside the registry past a counter's range",
			Reading{Pipeline: blocks(map[string]uint64{code + "_X": math.MaxUint64, code + "_Y": 1})},
			Reading{Pipeline: blocks(map[string]uint64{code + "_X": math.MaxUint64 - 1, code + "_Y": 1, code: math.MaxUint64})}},
		{"causes outside the set past a counter's range",
			Reading{Pause: pause.PollStats{Failed: map[pause.Cause]uint64{"x": math.MaxUint64, "y": 1}}},
			Reading{Pause: pause.PollStats{Failed: map[pause.Cause]uint64{"x": math.MaxUint64 - 1, "y": 1}}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Render(c.refused); err == nil {
				t.Error("Render wrote the reading")
			}
			parse(t, c.taken)
		})
	}
}

// TestTheCausesAreInOrder: every declared cause is its own sample, sorted.
func TestTheCausesAreInOrder(t *testing.T) {
	failed := map[pause.Cause]uint64{}
	for i, c := range pause.Causes() {
		failed[c] = uint64(i + 1)
	}
	f := family(t, parse(t, Reading{Pause: pause.PollStats{Failed: failed}}), Prefix()+"pause_poll_failures_total")
	var order []string
	for _, s := range f.Samples {
		if want := strconv.FormatUint(failed[pause.Cause(s.Labels["cause"])], 10); s.Raw != want {
			t.Errorf("cause %q reads %s, want %s", s.Labels["cause"], s.Raw, want)
		}
		order = append(order, s.Labels["cause"])
	}
	want := make([]string, 0, len(failed))
	for _, c := range pause.Causes() {
		want = append(want, string(c))
	}
	slices.Sort(want)
	if !slices.Equal(order, want) {
		t.Errorf("the causes read %q, want one sample each in the order %q", order, want)
	}
}

// TestALabelValueIsEscaped: the format's three escapes, the one place a label
// value could break a line or a label set.
func TestALabelValueIsEscaped(t *testing.T) {
	if got, want := escapeLabel("a \"q\" \\ b\nc"), `a \"q\" \\ b\nc`; got != want {
		t.Errorf("escapeLabel = %s, want %s", got, want)
	}
	if got, want := escapeHelp("a \"q\" \\ b\nc"), `a "q" \\ b\nc`; got != want {
		t.Errorf("escapeHelp = %s, want %s", got, want)
	}
}

// TestTheWaitIsInSecondsExactly: a count of microseconds a float cannot hold
// is spelled to its last digit.
func TestTheWaitIsInSecondsExactly(t *testing.T) {
	for micros, want := range map[uint64]string{
		0: "0", 2_000_000: "2", 1_500: "0.0015", 1<<62 + 1: "4611686018427.387905",
	} {
		var r Reading
		r.Pipeline.Asks.Micros = micros
		s, _ := family(t, parse(t, r), Prefix()+"pdp_ask_wait_seconds_total").One(map[string]string{})
		if s.Raw != want {
			t.Errorf("%d microseconds read %s, want %s", micros, s.Raw, want)
		}
	}
}

func statsSent(n int64) (s adaptermcp.Stats) { s.Sent = n; return s }

func blocks(m map[string]uint64) (s gateway.Stats) { s.Blocks = maps.Clone(m); return s }

func parse(t *testing.T, r Reading) []metricstest.Family {
	t.Helper()
	text, err := Render(r)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	families, err := metricstest.Parse(text)
	if err != nil {
		t.Fatalf("the strict reader refused the text: %v\n%s", err, text)
	}
	want := 0
	for _, m := range Table() {
		if !leftOut(r, m) {
			want++
		}
	}
	if len(families) != want {
		t.Fatalf("%d families, want %d of the table's %d rows", len(families), want, len(Table()))
	}
	return families
}

// readsSpool is a metric a broken spool leaves out.
func readsSpool(m Metric) bool { return strings.HasPrefix(m.Reads, "Spool.") }

// leftOut is whether r leaves m out of the text: the MCP adapter's metrics on
// a plane serving the enforcement API, that adapter's on any other, and a
// broken spool's.
func leftOut(r Reading, m Metric) bool {
	switch {
	case strings.HasPrefix(m.Reads, "Adapter."):
		return r.EnforceAPI
	case strings.HasPrefix(m.Reads, "Enforce."):
		return !r.EnforceAPI
	}
	return r.SpoolBroken && readsSpool(m)
}

func family(t *testing.T, families []metricstest.Family, name string) metricstest.Family {
	t.Helper()
	f, ok := metricstest.Find(families, name)
	if !ok {
		t.Fatalf("no family %s", name)
	}
	return f
}

func metric(t *testing.T, name string) Metric {
	t.Helper()
	for _, m := range Table() {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("no row %s", name)
	return Metric{}
}

// TestTheFreshnessHelpSaysWhichModesBlock: an unconfirmed policy blocks
// material calls only where the mode enforces, so the help names the one mode
// that does not.
func TestTheFreshnessHelpSaysWhichModesBlock(t *testing.T) {
	if help := metric(t, Prefix()+"policy_freshness").Help; !strings.Contains(help, "every mode but OBSERVE blocks") {
		t.Errorf("policy_freshness says %q, which does not name the mode that runs every call", help)
	}
}
