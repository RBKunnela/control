package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strconv"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/coverage"
	ondisk "github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/observe"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/internal/supervise"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// casesSchema is the one version of the cases document this build reads.
const casesSchema = "0.1"

// casesDoc is a cases document as read: its procedure and its cases.
type casesDoc struct {
	procedure *supervise.Procedure
	cases     []procedureCase
}

// procedureCase is one case: the input supervise judges, less the
// procedure, and what the case expects of it.
type procedureCase struct {
	name   string
	input  supervise.Input
	expect caseExpect
}

// readCasesFile reads the cases document at path strictly: every member of
// the format present but sources and sources_not_read, each spelled
// exactly, none the format does not have, none twice. Paths in it are read
// relative to its own directory. A refusal names the member it is about.
func readCasesFile(path string) (*casesDoc, error) {
	raw, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	c := &casesReader{dir: filepath.Dir(path)}
	doc := c.document(raw)
	if c.err != nil {
		return nil, fmt.Errorf("%s: %w", path, c.err)
	}
	return doc, nil
}

// casesReader keeps the first refusal, as reader does, and resolves the
// document's paths against dir.
type casesReader struct {
	reader
	dir string
}

func (c *casesReader) fail(where string, err error) {
	if c.err == nil {
		c.err = fmt.Errorf("%s: %w", where, err)
	}
}

// object reads raw as an object holding every one of required and nothing
// but required and optional.
func (c *casesReader) object(raw json.RawMessage, at string, required, optional []string) map[string]json.RawMessage {
	if c.err != nil {
		return nil
	}
	o, err := strictjson.ReadObject(raw)
	if err != nil {
		c.fail(orDocument(at), err)
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(o)) {
		if !slices.Contains(required, name) && !slices.Contains(optional, name) {
			c.refuse(at, name, errors.New("a member the cases format does not have"))
			return nil
		}
	}
	for _, name := range required {
		if _, ok := o[name]; !ok {
			c.refuse(at, name, errors.New("missing"))
			return nil
		}
	}
	return o
}

func orDocument(at string) string {
	if at == "" {
		return "the cases document"
	}
	return at
}

// list reads a JSON array, never null.
func (c *casesReader) list(raw json.RawMessage, where string) []json.RawMessage {
	var items []json.RawMessage
	if isNull(raw) || json.Unmarshal(raw, &items) != nil {
		c.fail(where, errors.New("want a list"))
		return nil
	}
	return items
}

func at(where string, i int) string { return where + "." + strconv.Itoa(i+1) }

func (c *casesReader) document(raw []byte) *casesDoc {
	m := c.object(raw, "", []string{"schema_version", "procedure", "cases"}, nil)
	if c.err != nil {
		return nil
	}
	if v := c.string(m, "", "schema_version"); c.err == nil && v != casesSchema {
		c.refuse("", "schema_version", errors.New("not "+casesSchema+", the one version this build reads"))
	}
	doc := &casesDoc{procedure: c.procedure(c.string(m, "", "procedure"))}
	items := c.list(m["cases"], "cases")
	if c.err == nil && len(items) == 0 {
		c.fail("cases", errors.New("no case"))
	}
	named := map[string]bool{}
	for i, item := range items {
		pc := c.procedureCase(item, at("cases", i))
		if c.err == nil && named[pc.name] {
			c.refuse(at("cases", i), "name", errors.New("given to two cases"))
		}
		named[pc.name] = true
		doc.cases = append(doc.cases, pc)
	}
	return doc
}

// resolve is path as the document names it, relative to its directory.
func (c *casesReader) resolve(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(c.dir, path)
}

func (c *casesReader) procedure(path string) *supervise.Procedure {
	if c.err != nil {
		return nil
	}
	raw, err := readBounded(c.resolve(path))
	if err != nil {
		c.fail("procedure", err)
		return nil
	}
	p, err := supervise.ReadProcedure(raw)
	if err != nil {
		c.fail("procedure", fmt.Errorf("%s: %w", path, err))
	}
	return p
}

func (c *casesReader) procedureCase(raw json.RawMessage, where string) procedureCase {
	m := c.object(raw, where, []string{"name", "run", "tree", "evidence", "expect"}, []string{"sources", "sources_not_read"})
	if c.err != nil {
		return procedureCase{}
	}
	pc := procedureCase{name: c.string(m, where, "name")}
	if c.err == nil && pc.name == "" {
		c.refuse(where, "name", errors.New("want a name"))
	}
	pc.input.Run = c.run(m["run"], where+".run")
	var tree []supervise.Run
	for i, item := range c.list(m["tree"], where+".tree") {
		tree = append(tree, c.run(item, at(where+".tree", i)))
	}
	if len(tree) > 0 {
		pc.input.Tree = append([]supervise.Run{pc.input.Run}, tree...)
	}
	for i, item := range c.list(m["evidence"], where+".evidence") {
		pc.input.Exports = append(pc.input.Exports, c.export(item, at(where+".evidence", i)))
	}
	if _, stated := m["sources"]; stated {
		for i, item := range c.list(m["sources"], where+".sources") {
			pc.input.Sources = append(pc.input.Sources, c.source(item, at(where+".sources", i)))
		}
	}
	if _, stated := m["sources_not_read"]; stated {
		pc.input.SourcesNotRead = c.strings(m, where, "sources_not_read")
	}
	pc.expect = c.expect(m["expect"], where+".expect")
	return pc
}

func (c *casesReader) run(raw json.RawMessage, where string) supervise.Run {
	m := c.object(raw, where, []string{"id", "tenant", "parent", "closed"}, nil)
	if c.err != nil {
		return supervise.Run{}
	}
	return supervise.Run{ID: c.string(m, where, "id"), Tenant: c.string(m, where, "tenant"),
		Parent: c.string(m, where, "parent"), Closed: c.bool(m, where, "closed")}
}

// export reads one export: a path to an export file, or its events inline
// with whether the case holds them whole.
func (c *casesReader) export(raw json.RawMessage, where string) supervise.Export {
	m := c.object(raw, where, nil, []string{"path", "events", "whole"})
	if c.err != nil {
		return supervise.Export{}
	}
	_, path := m["path"]
	_, events := m["events"]
	_, whole := m["whole"]
	switch {
	case path && (events || whole):
		c.fail(where, errors.New("a path or events, not both"))
	case path:
		return c.exportFile(c.string(m, where, "path"), where+".path")
	case !events:
		c.refuse(where, "events", errors.New("missing"))
	case !whole:
		c.refuse(where, "whole", errors.New("missing"))
	}
	x := supervise.Export{Whole: c.bool(m, where, "whole")}
	if !x.Whole {
		x.NotWhole = "the case states the export is not whole"
	}
	for i, item := range c.list(m["events"], where+".events") {
		ev := &controlv1.Event{}
		c.message(item, at(where+".events", i), ev)
		x.Events = append(x.Events, ev)
	}
	return x
}

// message decodes raw into msg as protojson does, refusing a member the
// message does not have.
func (c *casesReader) message(raw json.RawMessage, where string, msg proto.Message) {
	if err := protojson.Unmarshal(raw, msg); err != nil {
		c.fail(where, err)
	}
}

// exportFile reads an export file as supervise reads one, minus the owner
// check: a case's export is test input, not the plane's evidence.
func (c *casesReader) exportFile(path, where string) supervise.Export {
	if c.err != nil {
		return supervise.Export{}
	}
	resolved := c.resolve(path)
	raw, err := ondisk.ReadRegular(resolved, maxExportFileBytes, 0)
	var pathErr *fs.PathError
	if err != nil && !errors.As(err, &pathErr) {
		err = fmt.Errorf("%s: %w", resolved, err)
	}
	if err != nil {
		c.fail(where, err)
		return supervise.Export{}
	}
	x, err := coverage.ReadExport(bytes.NewReader(raw))
	if err != nil {
		c.fail(where, fmt.Errorf("%s: %w", resolved, err))
		return supervise.Export{}
	}
	events, err := exportEvents(raw)
	if err != nil {
		c.fail(where, fmt.Errorf("%s: %w", resolved, err))
	}
	return supervise.Export{Events: events, Whole: x.Whole, NotWhole: x.NotWhole}
}

// source reads one observation source: last_heard left out is a source
// never heard. A case's observations are an agent runtime's spans, so its
// source is of kind otel-genai-traces.
func (c *casesReader) source(raw json.RawMessage, where string) supervise.Source {
	m := c.object(raw, where, []string{"source_id", "heartbeat_seconds", "observations"}, []string{"last_heard"})
	if c.err != nil {
		return supervise.Source{}
	}
	s := supervise.Source{SourceID: c.string(m, where, "source_id"), Kind: observe.KindOTelGenAI}
	if hb := m["heartbeat_seconds"]; isNull(hb) || bytes.HasPrefix(bytes.TrimSpace(hb), []byte(`"`)) ||
		json.Unmarshal(hb, &s.HeartbeatSeconds) != nil {
		c.refuse(where, "heartbeat_seconds", errors.New("want a whole number of seconds"))
	}
	if _, heard := m["last_heard"]; heard {
		s.LastHeard, s.Heard = c.time(m, where, "last_heard"), true
	}
	for i, item := range c.list(m["observations"], where+".observations") {
		o := &observev1.Observation{}
		c.message(item, at(where+".observations", i), o)
		s.Observations = append(s.Observations, o)
	}
	return s
}

func (c *casesReader) expect(raw json.RawMessage, where string) caseExpect {
	m := c.object(raw, where, []string{"rules", "findings"}, []string{"never_heard", "silent", "not_read"})
	if c.err != nil {
		return caseExpect{}
	}
	e := caseExpect{rules: map[string]findingv1alpha1.RuleState{}}
	rules, err := strictjson.ReadObject(m["rules"])
	if err != nil {
		c.fail(where+".rules", err)
	}
	for _, id := range slices.Sorted(maps.Keys(rules)) {
		n, ok := enumNumber(findingv1alpha1.RuleState(0).Descriptor(), "RULE_STATE_", c.string(rules, where+".rules", id))
		if !ok || n == 0 {
			c.refuse(where+".rules", id, errors.New("want CHECKED, NOT_CHECKED or OFF"))
		}
		e.rules[id] = findingv1alpha1.RuleState(n)
	}
	for i, item := range c.list(m["findings"], where+".findings") {
		e.findings = append(e.findings, c.finding(item, at(where+".findings", i)))
	}
	for _, l := range []struct {
		key string
		ids *[]string
	}{{"never_heard", &e.neverHeard}, {"silent", &e.silent}, {"not_read", &e.notRead}} {
		if _, stated := m[l.key]; stated {
			*l.ids = c.ids(m, where, l.key)
		}
	}
	return e
}

func (c *casesReader) finding(raw json.RawMessage, where string) caseFinding {
	m := c.object(raw, where, []string{"rule", "verdict", "run", "requests"}, []string{"observations"})
	if c.err != nil {
		return caseFinding{}
	}
	f := caseFinding{rule: c.string(m, where, "rule"), run: c.string(m, where, "run")}
	n, ok := enumNumber(controlv1.FindingVerdict(0).Descriptor(), "FINDING_VERDICT_", c.string(m, where, "verdict"))
	if !ok || n == 0 {
		c.refuse(where, "verdict", errors.New("want CONFIRMED, SUSPECTED or INDETERMINATE"))
	}
	f.verdict = controlv1.FindingVerdict(n)
	f.requests = c.ids(m, where, "requests")
	if _, stated := m["observations"]; stated {
		f.observations = c.ids(m, where, "observations")
	}
	return f
}

// ids reads a list of ids, each once, sorted.
func (c *casesReader) ids(m map[string]json.RawMessage, where, key string) []string {
	list := c.strings(m, where, key)
	slices.Sort(list)
	for i := 1; i < len(list); i++ {
		if list[i] == list[i-1] {
			c.refuse(where, key, errors.New(list[i]+" twice"))
		}
	}
	return list
}
