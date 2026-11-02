package findinglog

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const childID = "run-ffeeddccbbaa99887766554433221100"

// Lines as the 0.9 writer wrote them, and as this one writes the same
// records in "0.2".
const (
	finding01 = `{"findingRecord":{"schemaVersion":"0.1","tenantId":"tenant-a","projectId":"project-a","procedure":{"procedureId":"refund","version":"1","digest":"aa"},"escalation":"ESCALATION_ALERT","refs":[{"event":{"eventId":"evt-1","requestId":"req-1"}}],"finding":{"findingId":"fnd-0123456789abcdef0123456789abcdef","ruleId":"REPEATED_DENIAL","ruleVersion":"1","severity":"FINDING_SEVERITY_HIGH","verdict":"FINDING_VERDICT_CONFIRMED","runId":"run-00112233445566778899aabbccddeeff","source":"FINDING_SOURCE_DETERMINISTIC"}}}` + "\n"
	report01  = `{"superviseReport":{"schemaVersion":"0.1","tenantId":"tenant-a","projectId":"project-a","runId":"run-00112233445566778899aabbccddeeff","procedure":{"procedureId":"refund","version":"1","digest":"aa"},"read":{"eventsTaken":"4","eventsLeftOut":{"another run":"2"}},"rules":[{"ruleId":"repeated_denial","ruleVersion":"1","state":"RULE_STATE_CHECKED"}],"findingsWritten":"1"}}` + "\n"
	finding02 = `{"findingRecord":{"schemaVersion":"0.2","tenantId":"tenant-a","projectId":"project-a","procedure":{"procedureId":"refund","version":"1","digest":"aa"},"escalation":"ESCALATION_ALERT","refs":[{"event":{"eventId":"evt-1","requestId":"req-1","runId":"run-ffeeddccbbaa99887766554433221100"}}],"finding":{"findingId":"fnd-0123456789abcdef0123456789abcdef","ruleId":"REPEATED_DENIAL","ruleVersion":"1","severity":"FINDING_SEVERITY_HIGH","verdict":"FINDING_VERDICT_CONFIRMED","runId":"run-ffeeddccbbaa99887766554433221100","source":"FINDING_SOURCE_DETERMINISTIC"}}}` + "\n"
	report02  = `{"superviseReport":{"schemaVersion":"0.2","tenantId":"tenant-a","projectId":"project-a","runId":"run-00112233445566778899aabbccddeeff","procedure":{"procedureId":"refund","version":"1","digest":"aa"},"read":{"eventsTaken":"4","eventsLeftOut":{"another run":"2"}},"rules":[{"ruleId":"repeated_denial","ruleVersion":"1","state":"RULE_STATE_CHECKED"}],"findingsWritten":"1","children":"CHILDREN_MODE_INHERIT","runTree":[{"runId":"run-00112233445566778899aabbccddeeff"},{"runId":"run-ffeeddccbbaa99887766554433221100","parentRunId":"run-00112233445566778899aabbccddeeff"}]}}` + "\n"
	cut02     = `{"findingRecord":{"schemaVersion":"0.2","tenantId":"tenant-a","projectId":"project-a","procedure":{"procedureId":"refund","version":"1","digest":"aa"},"escalation":"ESCALATION_ALERT","refs":[{"event":{"eventId":"evt-1","requestId":"req-1","runId":"run-ffeeddccbbaa99887766554433221100"}}],"finding":{"findingId":"fnd-0123456789abcdef0123456789abcdef","ruleId":"REPEATED_DENIAL","ruleVersion":"1","severity":"FINDING_SEVERITY_HIGH","verdict":"FINDING_VERDICT_CONFIRMED","runId":"run-ffeeddccbbaa99887766554433221100","source":"FINDING_SOURCE_DETERMINISTIC"},"refsLeftOut":"9999"}}` + "\n"
	sources02 = `{"superviseReport":{"schemaVersion":"0.2","tenantId":"tenant-a","projectId":"project-a","runId":"run-00112233445566778899aabbccddeeff","procedure":{"procedureId":"refund","version":"1","digest":"aa"},"read":{"eventsTaken":"4","eventsLeftOut":{"another run":"2"}},"rules":[{"ruleId":"repeated_denial","ruleVersion":"1","state":"RULE_STATE_CHECKED"}],"findingsWritten":"1","sourcesInDoubt":[{"state":"SOURCE_STATE_NOT_READ"},{"sourceId":"s3","state":"SOURCE_STATE_NEVER_HEARD","heartbeatSeconds":300},{"sourceId":"s2","state":"SOURCE_STATE_SILENT","heartbeatSeconds":300}]}}` + "\n"
	header02  = `{"logHeader":{"schemaVersion":"0.2","logId":"log-0123456789abcdef0123456789abcdef"}}` + "\n"
)

// finding02Record is a finding of "0.2": its one event names the child run
// it came from.
func finding02Record() *findingv1alpha1.FindingRecord {
	f := finding(idA, confirmed, "REPEATED_DENIAL")
	f.SchemaVersion = "0.2"
	f.Refs[0].GetEvent().RunId = childID
	f.Finding.RunId = childID
	return f
}

// cut02Record is finding02Record citing one record of ten thousand.
func cut02Record() *findingv1alpha1.FindingRecord {
	f := finding02Record()
	f.RefsLeftOut = 9999
	return f
}

// report02Record is a report of "0.2": a root and its one child, judged as
// one tree.
func report02Record() *findingv1alpha1.SuperviseReport {
	r := report()
	r.SchemaVersion = "0.2"
	r.Children = findingv1alpha1.ChildrenMode_CHILDREN_MODE_INHERIT
	r.RunTree = []*findingv1alpha1.RunTreeMember{{RunId: runID}, {RunId: childID, ParentRunId: runID}}
	return r
}

// sources02Record is a report of a 0.1 procedure that is "0.2" for the
// sources it could not rely on alone: one not read, one never heard, one
// silent.
func sources02Record() *findingv1alpha1.SuperviseReport {
	r := report()
	r.SchemaVersion = "0.2"
	r.SourcesInDoubt = []*findingv1alpha1.SourceInDoubt{
		{State: findingv1alpha1.SourceState_SOURCE_STATE_NOT_READ},
		{SourceId: "s3", State: findingv1alpha1.SourceState_SOURCE_STATE_NEVER_HEARD, HeartbeatSeconds: 300},
		{SourceId: "s2", State: findingv1alpha1.SourceState_SOURCE_STATE_SILENT, HeartbeatSeconds: 300},
	}
	return r
}

// namesThreeSources reports whether r is a report of no children mode
// naming sources02Record's three sources.
func namesThreeSources(r *findingv1alpha1.Record) bool {
	s := r.GetSuperviseReport().GetSourcesInDoubt()
	return len(s) == 3 && s[0].GetSourceId() == "" && s[0].GetState() == findingv1alpha1.SourceState_SOURCE_STATE_NOT_READ &&
		s[1].GetSourceId() == "s3" && s[1].GetState() == findingv1alpha1.SourceState_SOURCE_STATE_NEVER_HEARD &&
		s[2].GetSourceId() == "s2" && s[2].GetState() == findingv1alpha1.SourceState_SOURCE_STATE_SILENT &&
		s[2].GetHeartbeatSeconds() == 300 && r.GetSuperviseReport().GetChildren() == 0
}

// TestALineOfEitherSchemaReads: the 0.1 lines are the 0.9 writer's bytes,
// and each line reads as the record its literal spells.
func TestALineOfEitherSchemaReads(t *testing.T) {
	for name, c := range map[string]struct {
		line  string
		check func(*findingv1alpha1.Record) bool
	}{
		"a 0.1 finding": {finding01, func(r *findingv1alpha1.Record) bool {
			e := r.GetFindingRecord().GetRefs()[0].GetEvent()
			return r.GetFindingRecord().GetSchemaVersion() == "0.1" && e.GetEventId() == "evt-1" && e.GetRunId() == ""
		}},
		"a 0.1 report": {report01, func(r *findingv1alpha1.Record) bool {
			rep := r.GetSuperviseReport()
			return rep.GetSchemaVersion() == "0.1" && rep.GetChildren() == 0 && len(rep.GetRunTree()) == 0
		}},
		"a 0.2 finding": {finding02, func(r *findingv1alpha1.Record) bool {
			return r.GetFindingRecord().GetRefs()[0].GetEvent().GetRunId() == "run-ffeeddccbbaa99887766554433221100"
		}},
		"a 0.2 report": {report02, func(r *findingv1alpha1.Record) bool {
			tree := r.GetSuperviseReport().GetRunTree()
			return r.GetSuperviseReport().GetChildren() == findingv1alpha1.ChildrenMode_CHILDREN_MODE_INHERIT && len(tree) == 2 &&
				tree[0].GetParentRunId() == "" && tree[1].GetRunId() == "run-ffeeddccbbaa99887766554433221100" &&
				tree[1].GetParentRunId() == "run-00112233445566778899aabbccddeeff"
		}},
		"a 0.2 report of sources in doubt": {sources02, namesThreeSources},
		"a header": {header02, func(r *findingv1alpha1.Record) bool {
			return r.GetLogHeader().GetLogId() == "log-0123456789abcdef0123456789abcdef"
		}},
	} {
		r, err := unmarshalLine([]byte(c.line))
		if err != nil || !c.check(r) {
			t.Errorf("%s: unmarshalLine = %v, %v", name, r, err)
		}
	}
}

// TestALineThatLeavesReferencesOutReads: the count reads as the literal
// spells it, beside the one reference cited.
func TestALineThatLeavesReferencesOutReads(t *testing.T) {
	r, err := unmarshalLine([]byte(cut02))
	if err != nil || r.GetFindingRecord().GetRefsLeftOut() != 9999 || len(r.GetFindingRecord().GetRefs()) != 1 {
		t.Fatalf("unmarshalLine = %v, %v", r, err)
	}
}

// TestTheWriterSpellsEachSchemaAsTheLiterals: a record of either schema is
// written byte for byte as its literal.
func TestTheWriterSpellsEachSchemaAsTheLiterals(t *testing.T) {
	r01 := report()
	r01.FindingsWritten = 1
	r02 := report02Record()
	r02.FindingsWritten = 1
	s02 := sources02Record()
	s02.FindingsWritten = 1
	for name, c := range map[string]struct {
		r    *findingv1alpha1.Record
		want string
	}{
		"a 0.1 finding":                    {findingRecord(finding(idA, confirmed, "REPEATED_DENIAL")), finding01},
		"a 0.1 report":                     {reportRecord(r01), report01},
		"a 0.2 finding":                    {findingRecord(finding02Record()), finding02},
		"a 0.2 cut":                        {findingRecord(cut02Record()), cut02},
		"a 0.2 report":                     {reportRecord(r02), report02},
		"a 0.2 report of sources in doubt": {reportRecord(s02), sources02},
	} {
		if got := line(t, c.r); got != c.want {
			t.Errorf("%s: the writer wrote\n%s\nwant\n%s", name, got, c.want)
		}
	}
}

// TestARecordIsOfTheSchemaItsMembersCallFor: each case is a valid record of
// "0.1" or "0.2" with one change, refused on both sides and naming the field
// the check is about. The unchanged records are written above.
func TestARecordIsOfTheSchemaItsMembersCallFor(t *testing.T) {
	inherit, separate := findingv1alpha1.ChildrenMode_CHILDREN_MODE_INHERIT, findingv1alpha1.ChildrenMode_CHILDREN_MODE_SEPARATE
	member := func(run, parent string) *findingv1alpha1.RunTreeMember {
		return &findingv1alpha1.RunTreeMember{RunId: run, ParentRunId: parent}
	}
	const third = "run-0000000000000000000000000000000f"
	cases := map[string]struct {
		r     *findingv1alpha1.Record
		field string
	}{
		"a 0.1 finding with an event's run": {findingRecord(change01(func(f *findingv1alpha1.FindingRecord) { f.Refs[0].GetEvent().RunId = runID })), "refs.event.run_id"},
		"a 0.2 finding with none":           {findingRecord(change02(func(f *findingv1alpha1.FindingRecord) { f.Refs[0].GetEvent().RunId = "" })), "schema_version"},
		"a 0.2 finding with one event of no run": {findingRecord(change02(func(f *findingv1alpha1.FindingRecord) {
			f.Refs = append(f.Refs, &findingv1alpha1.Reference{Ref: &findingv1alpha1.Reference_Event{Event: &findingv1alpha1.EventRef{EventId: "evt-2", RequestId: "req-2"}}})
		})), "refs.event.run_id"},
		"a 0.2 finding with a run of another form": {findingRecord(change02(func(f *findingv1alpha1.FindingRecord) { f.Refs[0].GetEvent().RunId = "run-1" })), "refs.event.run_id"},
		"a 0.1 finding with references left out":   {findingRecord(change01(func(f *findingv1alpha1.FindingRecord) { f.RefsLeftOut = 1 })), "refs_left_out"},
		"a 0.2 cut whose event names no run": {findingRecord(change02(func(f *findingv1alpha1.FindingRecord) {
			f.RefsLeftOut, f.Refs[0].GetEvent().RunId = 1, ""
		})), "refs.event.run_id"},
		"a 0.3 finding":              {findingRecord(change02(func(f *findingv1alpha1.FindingRecord) { f.SchemaVersion = "0.3" })), "schema_version"},
		"a 0.1 report with children": {reportRecord(changeReport(report(), func(r *findingv1alpha1.SuperviseReport) { r.Children = separate })), "children"},
		"a 0.1 report with a tree": {reportRecord(changeReport(report(), func(r *findingv1alpha1.SuperviseReport) {
			r.RunTree = []*findingv1alpha1.RunTreeMember{member(runID, "")}
		})), "run_tree"},
		"a 0.2 report with neither":        {reportRecord(changeReport(report(), func(r *findingv1alpha1.SuperviseReport) { r.SchemaVersion = "0.2" })), "schema_version"},
		"a 0.2 report of no children mode": {reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) { r.Children = 0 })), "children"},
		"a 0.2 report of an unknown mode":  {reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) { r.Children = 3 })), "children"},
		"a 0.2 report of no tree":          {reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) { r.RunTree = nil })), "run_tree"},
		"a tree led by another run": {reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) {
			r.RunTree = []*findingv1alpha1.RunTreeMember{member(childID, ""), member(runID, childID)}
		})), "run_tree"},
		"an inherit root with a parent": {reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) { r.RunTree[0].ParentRunId = third })), "run_tree.parent_run_id"},
		"a member before its parent": {reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) {
			r.RunTree = append(r.RunTree[:1], member(third, childID), member(childID, runID))
		})), "run_tree.parent_run_id"},
		"a member listed twice": {reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) {
			r.RunTree = append(r.RunTree, member(childID, runID))
		})), "run_tree.run_id"},
		"a member of another form": {reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) { r.RunTree[1].RunId = "run-2" })), "run_tree.run_id"},
		"a separate grandchild": {reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) {
			r.Children = separate
			r.RunTree = append(r.RunTree, member(third, childID))
		})), "run_tree.parent_run_id"},
		"a separate first member's parent of another form": {reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) {
			r.Children = separate
			r.RunTree[0].ParentRunId = "run-3"
		})), "run_tree.parent_run_id"},
		"a 0.1 report naming a source": {reportRecord(changeReport(sources02Record(), func(r *findingv1alpha1.SuperviseReport) { r.SchemaVersion = "0.1" })), "sources_in_doubt"},
		"a source of no state":         {reportRecord(changeReport(sources02Record(), func(r *findingv1alpha1.SuperviseReport) { r.SourcesInDoubt[1].State = 0 })), "sources_in_doubt.state"},
		"a source of an unknown state": {reportRecord(changeReport(sources02Record(), func(r *findingv1alpha1.SuperviseReport) { r.SourcesInDoubt[2].State = 4 })), "sources_in_doubt.state"},
		"a source not read with an id": {reportRecord(changeReport(sources02Record(), func(r *findingv1alpha1.SuperviseReport) { r.SourcesInDoubt[0].SourceId = "s1" })), "sources_in_doubt.source_id"},
		"a silent source with no id":   {reportRecord(changeReport(sources02Record(), func(r *findingv1alpha1.SuperviseReport) { r.SourcesInDoubt[2].SourceId = "" })), "sources_in_doubt.source_id"},
		"sources beside a tree of no mode": {reportRecord(changeReport(sources02Record(), func(r *findingv1alpha1.SuperviseReport) {
			r.RunTree = []*findingv1alpha1.RunTreeMember{member(runID, "")}
		})), "children"},
		"a header of 0.1":            {headerRecord("0.1", "log-0123456789abcdef0123456789abcdef"), "log_header.schema_version"},
		"a header of another id":     {headerRecord("0.2", "log-0123"), "log_header.log_id"},
		"a header of upper-case hex": {headerRecord("0.2", "log-0123456789ABCDEF0123456789abcdef"), "log_header.log_id"},
	}
	for name, c := range cases {
		if _, err := marshalLine(c.r); err == nil || !strings.HasPrefix(err.Error(), c.field+":") {
			t.Errorf("%s: the writer: %v; want a refusal naming %s", name, err, c.field)
		}
		var fe fieldError
		if _, err := unmarshalLine(forge(t, c.r)); !errors.As(err, &fe) || !strings.HasPrefix(err.Error(), c.field+":") {
			t.Errorf("%s: the reader: %v; want a refusal naming %s", name, err, c.field)
		}
	}
	// The cases above change these, which both sides take.
	sep := changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) {
		r.Children = separate
		r.RunTree[0].ParentRunId = third
		r.RunTree = append(r.RunTree, member("run-0000000000000000000000000000000e", runID))
	})
	for name, r := range map[string]*findingv1alpha1.Record{
		"a 0.2 finding": findingRecord(finding02Record()),
		"a 0.2 cut":     findingRecord(cut02Record()),
		"a 0.2 cut citing observations alone": findingRecord(change02(func(f *findingv1alpha1.FindingRecord) {
			f.RefsLeftOut = 3
			f.Refs = []*findingv1alpha1.Reference{{Ref: &findingv1alpha1.Reference_Observation{
				Observation: &findingv1alpha1.ObservationRef{SourceId: "s1", ObservationId: "obs-0123456789abcdef0123456789abcdef"}}}}
		})),
		"a 0.2 report":                     reportRecord(report02Record()),
		"a 0.2 report of sources in doubt": reportRecord(sources02Record()),
		"a tree and sources in doubt": reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) {
			r.SourcesInDoubt = sources02Record().SourcesInDoubt
		})),
		"a deeper inherit tree": reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) {
			r.RunTree = append(r.RunTree, member(third, childID))
		})),
		"a separate child's report": reportRecord(sep),
		"inherit":                   reportRecord(changeReport(report02Record(), func(r *findingv1alpha1.SuperviseReport) { r.Children = inherit })),
		"a header":                  headerRecord("0.2", "log-0123456789abcdef0123456789abcdef"),
	} {
		if _, err := unmarshalLine([]byte(line(t, r))); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// forge is r as the writer would spell it, without the writer's checks.
func forge(t *testing.T, r *findingv1alpha1.Record) []byte {
	t.Helper()
	raw, err := protojson.Marshal(r)
	mustDo(t, err)
	var b bytes.Buffer
	mustDo(t, json.Compact(&b, raw))
	return b.Bytes()
}

func change01(f func(*findingv1alpha1.FindingRecord)) *findingv1alpha1.FindingRecord {
	r := finding(idA, confirmed, "REPEATED_DENIAL")
	f(r)
	return r
}

func change02(f func(*findingv1alpha1.FindingRecord)) *findingv1alpha1.FindingRecord {
	r := finding02Record()
	f(r)
	return r
}

func changeReport(r *findingv1alpha1.SuperviseReport, f func(*findingv1alpha1.SuperviseReport)) *findingv1alpha1.SuperviseReport {
	f(r)
	return r
}

func headerRecord(version, id string) *findingv1alpha1.Record {
	return &findingv1alpha1.Record{Record: &findingv1alpha1.Record_LogHeader{LogHeader: &findingv1alpha1.LogHeader{SchemaVersion: version, LogId: id}}}
}

// TestAZeroNineReaderRefusesEveryLineOfSchema02ByName: the 0.9 reader is
// simulated with the record's descriptor as 0.9 compiled it, decoded as that
// reader decodes, then held to its one version. It reads the 0.1 lines, so a
// refusal of the others is not a reader that refuses everything.
func TestAZeroNineReaderRefusesEveryLineOfSchema02ByName(t *testing.T) {
	record := zeroNineRecord(t)
	read := func(line string) error {
		m := dynamicpb.NewMessage(record)
		if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal([]byte(line), m); err != nil {
			return err
		}
		return zeroNineVersion(m)
	}
	for _, ok := range []string{finding01, report01} {
		if err := read(ok); err != nil {
			t.Fatalf("the 0.9 reader refuses a 0.1 line: %v", err)
		}
	}
	cutOnly := strings.Replace(cut02, `,"runId":"run-ffeeddccbbaa99887766554433221100"}}]`, `}}]`, 1)
	for line, name := range map[string]string{finding02: `"runId"`, report02: `"children"`, header02: `"logHeader"`, cutOnly: `"refsLeftOut"`, sources02: `"sourcesInDoubt"`} {
		if err := read(line); err == nil || !strings.Contains(err.Error(), "unknown field "+name) {
			t.Errorf("the 0.9 reader on %s: %v; want it to refuse the field %s by name", line, err, name)
		}
	}
	// A 0.2 line that carried nothing new would pass the decoder; the
	// version check alone refuses it.
	bare := strings.Replace(finding01, `"schemaVersion":"0.1"`, `"schemaVersion":"0.2"`, 1)
	if err := read(bare); err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("the 0.9 reader on a bare 0.2 line: %v; want a refusal naming schema_version", err)
	}
}

// TestAStrictDecoderWithoutSourcesInDoubtRefusesThem: the strict decoder of
// a build that reads "0.2" and does not know sources_in_doubt, simulated as
// above, refuses a report naming a source and still decodes the other "0.2"
// report, so such a build never takes that report for one that read every
// source. The build's own log reader then names no field: it refuses the log
// as damaged at that line.
func TestAStrictDecoderWithoutSourcesInDoubtRefusesThem(t *testing.T) {
	report := protodesc.ToFileDescriptorProto(findingv1alpha1.File_guardana_control_finding_v1alpha1_report_proto)
	report.EnumType = dropEnum(report.EnumType, "SourceState")
	report.MessageType = dropMessage(report.MessageType, "SourceInDoubt")
	dropFields(t, report.MessageType, "SuperviseReport", "sources_in_doubt")
	files := &protoregistry.Files{}
	fd, err := protodesc.NewFile(report, files)
	mustDo(t, err)
	read := func(line string) error {
		m := dynamicpb.NewMessage(fd.Messages().ByName("SuperviseReport"))
		inner := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), `{"superviseReport":`), "}")
		return (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal([]byte(inner), m)
	}
	if err := read(report02); err != nil {
		t.Fatalf("the earlier decoder refuses a 0.2 report of a tree: %v", err)
	}
	if err := read(sources02); err == nil || !strings.Contains(err.Error(), `unknown field "sourcesInDoubt"`) {
		t.Errorf("the earlier decoder on %s: %v; want it to refuse sourcesInDoubt", sources02, err)
	}
}

// zeroNineVersion is the 0.9 reader's version check.
func zeroNineVersion(m protoreflect.Message) error {
	var version string
	m.Range(func(_ protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		inner := v.Message()
		version = inner.Get(inner.Descriptor().Fields().ByName("schema_version")).String()
		return false
	})
	if version != "0.1" {
		return errors.New("schema_version: not 0.1")
	}
	return nil
}

// zeroNineRecord is Record as 0.9 declared it: this build's two files less
// every member 0.2 added.
func zeroNineRecord(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	report := protodesc.ToFileDescriptorProto(findingv1alpha1.File_guardana_control_finding_v1alpha1_report_proto)
	record := protodesc.ToFileDescriptorProto(findingv1alpha1.File_guardana_control_finding_v1alpha1_record_proto)
	report.EnumType = dropEnum(dropEnum(report.EnumType, "ChildrenMode"), "SourceState")
	report.MessageType = dropMessage(dropMessage(report.MessageType, "RunTreeMember"), "SourceInDoubt")
	dropFields(t, report.MessageType, "SuperviseReport", "children", "run_tree", "sources_in_doubt")
	record.MessageType = dropMessage(record.MessageType, "LogHeader")
	dropFields(t, record.MessageType, "EventRef", "run_id")
	dropFields(t, record.MessageType, "FindingRecord", "refs_left_out")
	dropFields(t, record.MessageType, "Record", "log_header")
	files := &protoregistry.Files{}
	v1, err := protoregistry.GlobalFiles.FindFileByPath("guardana/control/v1/finding.proto")
	mustDo(t, err)
	mustDo(t, files.RegisterFile(v1))
	for _, fdp := range []*descriptorpb.FileDescriptorProto{report, record} {
		fd, err := protodesc.NewFile(fdp, files)
		mustDo(t, err)
		mustDo(t, files.RegisterFile(fd))
	}
	d, err := files.FindDescriptorByName((&findingv1alpha1.Record{}).ProtoReflect().Descriptor().FullName())
	mustDo(t, err)
	return d.(protoreflect.MessageDescriptor)
}

func dropEnum(in []*descriptorpb.EnumDescriptorProto, name string) []*descriptorpb.EnumDescriptorProto {
	var out []*descriptorpb.EnumDescriptorProto
	for _, e := range in {
		if e.GetName() != name {
			out = append(out, e)
		}
	}
	return out
}

func dropMessage(in []*descriptorpb.DescriptorProto, name string) []*descriptorpb.DescriptorProto {
	var out []*descriptorpb.DescriptorProto
	for _, m := range in {
		if m.GetName() != name {
			out = append(out, m)
		}
	}
	return out
}

func dropFields(t *testing.T, msgs []*descriptorpb.DescriptorProto, msg string, fields ...string) {
	t.Helper()
	for _, m := range msgs {
		if m.GetName() != msg {
			continue
		}
		var kept []*descriptorpb.FieldDescriptorProto
		for _, f := range m.Field {
			drop := false
			for _, name := range fields {
				drop = drop || f.GetName() == name
			}
			if !drop {
				kept = append(kept, f)
			}
		}
		if len(kept) != len(m.Field)-len(fields) {
			t.Fatalf("%s holds not every field of %v", msg, fields)
		}
		m.Field = kept
		return
	}
	t.Fatalf("no message %s", msg)
}
