package findinglog

import (
	"strings"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// The record schemas this build writes and reads. A record is SchemaVersion02
// exactly when it carries a member SchemaVersion01 does not have, and a log
// header always is.
const (
	SchemaVersion01 = "0.1"
	SchemaVersion02 = "0.2"
)

// fieldError is a refusal by checkRecord. It names a field and is never
// built from a record's bytes, so a reader may repeat it.
type fieldError string

func (e fieldError) Error() string { return string(e) }

// checkRecord holds a record to ADR-0045 and ADR-0047: exactly one member,
// of the schema its members call for, whose and which run it is.
func checkRecord(r *findingv1alpha1.Record) error {
	switch {
	case r.GetLogHeader() != nil:
		return checkHeader(r.GetLogHeader())
	case r.GetFindingRecord() != nil:
		return checkFinding(r.GetFindingRecord())
	case r.GetSuperviseReport() != nil:
		return checkReport(r.GetSuperviseReport())
	}
	return fieldError("no record set")
}

func checkHeader(h *findingv1alpha1.LogHeader) error {
	switch {
	case h.GetSchemaVersion() != SchemaVersion02:
		return fieldError(`log_header.schema_version: not "0.2"`)
	case !prefixedHex(h.GetLogId(), "log-"):
		return fieldError(`log_header.log_id: not "log-" and 32 lowercase hex digits`)
	}
	return nil
}

// checkOrigin holds a record to its schema, given added, the first member it
// carries that SchemaVersion01 does not have, or "".
func checkOrigin(version, added, tenant, project string) error {
	switch {
	case version == SchemaVersion01 && added != "":
		return fieldError(added + `: not a member of schema "0.1"`)
	case version == SchemaVersion02 && added == "":
		return fieldError(`schema_version: "0.2" on a record with no member of "0.2"`)
	case version != SchemaVersion01 && version != SchemaVersion02:
		return fieldError(`schema_version: neither "0.1" nor "0.2"`)
	case tenant == "":
		return fieldError("tenant_id: required")
	case project == "":
		return fieldError("project_id: required")
	}
	return nil
}

func checkReport(r *findingv1alpha1.SuperviseReport) error {
	added := ""
	switch {
	case r.GetChildren() != findingv1alpha1.ChildrenMode_CHILDREN_MODE_UNSPECIFIED:
		added = "children"
	case len(r.GetRunTree()) != 0:
		added = "run_tree"
	case len(r.GetSourcesInDoubt()) != 0:
		added = "sources_in_doubt"
	}
	if err := checkOrigin(r.GetSchemaVersion(), added, r.GetTenantId(), r.GetProjectId()); err != nil {
		return err
	}
	if !prefixedHex(r.GetRunId(), "run-") {
		return fieldError(`run_id: not "run-" and 32 lowercase hex digits`)
	}
	for _, s := range r.GetSourcesInDoubt() {
		if err := checkSourceInDoubt(s); err != nil {
			return err
		}
	}
	if r.GetChildren() == findingv1alpha1.ChildrenMode_CHILDREN_MODE_UNSPECIFIED && len(r.GetRunTree()) == 0 {
		return nil
	}
	return checkTree(r)
}

// checkSourceInDoubt holds a source a report names: of a known state, and
// named by its id exactly when it was read.
func checkSourceInDoubt(s *findingv1alpha1.SourceInDoubt) error {
	notRead := s.GetState() == findingv1alpha1.SourceState_SOURCE_STATE_NOT_READ
	switch {
	case !known(int32(s.GetState()), findingv1alpha1.SourceState_name):
		return fieldError("sources_in_doubt.state: neither not read, never heard nor silent")
	case notRead && s.GetSourceId() != "":
		return fieldError("sources_in_doubt.source_id: set on a source not read")
	case !notRead && s.GetSourceId() == "":
		return fieldError("sources_in_doubt.source_id: required")
	}
	return nil
}

// checkTree holds a "0.2" report's tree to its children mode: the
// supervised run first, every other member after its parent, and under
// separate each of them a child of the supervised run.
func checkTree(r *findingv1alpha1.SuperviseReport) error {
	mode, tree := r.GetChildren(), r.GetRunTree()
	switch {
	case mode != findingv1alpha1.ChildrenMode_CHILDREN_MODE_INHERIT && mode != findingv1alpha1.ChildrenMode_CHILDREN_MODE_SEPARATE:
		return fieldError("children: neither inherit nor separate")
	case len(tree) == 0:
		return fieldError("run_tree: empty")
	case tree[0].GetRunId() != r.GetRunId():
		return fieldError("run_tree: the first member is not the supervised run")
	}
	listed := make(map[string]bool, len(tree))
	for i, m := range tree {
		if err := checkMember(mode, i, m, tree[0].GetRunId(), listed); err != nil {
			return err
		}
		listed[m.GetRunId()] = true
	}
	return nil
}

func checkMember(mode findingv1alpha1.ChildrenMode, i int, m *findingv1alpha1.RunTreeMember, first string, listed map[string]bool) error {
	switch {
	case !prefixedHex(m.GetRunId(), "run-"):
		return fieldError(`run_tree.run_id: not "run-" and 32 lowercase hex digits`)
	case listed[m.GetRunId()]:
		return fieldError("run_tree.run_id: a run listed twice")
	case i == 0:
		return checkFirstParent(mode, m.GetParentRunId())
	case mode == findingv1alpha1.ChildrenMode_CHILDREN_MODE_SEPARATE && m.GetParentRunId() != first:
		return fieldError("run_tree.parent_run_id: under separate, not the supervised run")
	case !listed[m.GetParentRunId()]:
		return fieldError("run_tree.parent_run_id: not a run listed before it")
	}
	return nil
}

// checkFirstParent holds the supervised run's parent: none under inherit,
// whose first member is the root, and under separate none or a run id.
func checkFirstParent(mode findingv1alpha1.ChildrenMode, parent string) error {
	switch {
	case parent == "":
		return nil
	case mode == findingv1alpha1.ChildrenMode_CHILDREN_MODE_INHERIT:
		return fieldError("run_tree.parent_run_id: set on the root of an inherited tree")
	case !prefixedHex(parent, "run-"):
		return fieldError(`run_tree.parent_run_id: not "run-" and 32 lowercase hex digits`)
	}
	return nil
}

// checkFinding holds the finding to what supervision alone produces: a
// deterministic finding whose typed references say what it rests on once,
// so the fields that would say it again stay empty.
func checkFinding(r *findingv1alpha1.FindingRecord) error {
	named, unnamed := eventRuns(r.GetRefs())
	added := findingAdded(r, named)
	if err := checkOrigin(r.GetSchemaVersion(), added, r.GetTenantId(), r.GetProjectId()); err != nil {
		return err
	}
	if err := checkEventRuns(r.GetRefs(), unnamed); err != nil {
		return err
	}
	if added != "" && unnamed > 0 {
		return fieldError(`refs.event.run_id: absent from an event of a "0.2" record`)
	}
	if !known(int32(r.GetEscalation()), findingv1alpha1.Escalation_name) {
		return fieldError("escalation: neither inform nor alert")
	}
	f := r.GetFinding()
	switch {
	case f == nil:
		return fieldError("finding: required")
	case !prefixedHex(f.GetFindingId(), "fnd-"):
		return fieldError(`finding.finding_id: not "fnd-" and 32 lowercase hex digits`)
	case f.GetSource() != controlv1.FindingSource_FINDING_SOURCE_DETERMINISTIC:
		return fieldError("finding.source: not deterministic")
	case !known(int32(f.GetVerdict()), controlv1.FindingVerdict_name):
		return fieldError("finding.verdict: not set")
	case !known(int32(f.GetSeverity()), controlv1.FindingSeverity_name):
		return fieldError("finding.severity: not set")
	}
	return checkSaidOnce(f)
}

// findingAdded is the first member of a finding record that "0.1" does
// not have, given how many of its events name their run, or "".
func findingAdded(r *findingv1alpha1.FindingRecord, named int) string {
	switch {
	case r.GetRefsLeftOut() != 0:
		return "refs_left_out"
	case named > 0:
		return "refs.event.run_id"
	}
	return ""
}

func checkSaidOnce(f *controlv1.Finding) error {
	switch {
	case len(f.GetEvidenceRefs()) != 0:
		return fieldError("finding.evidence_refs: set beside the typed references")
	case f.GetRequestId() != "":
		return fieldError("finding.request_id: set beside the typed references")
	case f.GetRecommendedAction() != "":
		return fieldError("finding.recommended_action: set")
	case len(f.GetFrameworkMappings()) != 0:
		return fieldError("finding.framework_mappings: set")
	}
	return nil
}

// eventRuns counts the record's event references that name their run and
// those that do not.
func eventRuns(refs []*findingv1alpha1.Reference) (named, unnamed int) {
	for _, ref := range refs {
		switch e := ref.GetEvent(); {
		case e == nil:
		case e.GetRunId() == "":
			unnamed++
		default:
			named++
		}
	}
	return named, unnamed
}

// checkEventRuns holds the run ids of a record's events: on none of them,
// or on every one in the form of a run id.
func checkEventRuns(refs []*findingv1alpha1.Reference, unnamed int) error {
	for _, ref := range refs {
		id := ref.GetEvent().GetRunId()
		switch {
		case id == "":
		case unnamed > 0:
			return fieldError("refs.event.run_id: absent from an event beside one that has it")
		case !prefixedHex(id, "run-"):
			return fieldError(`refs.event.run_id: not "run-" and 32 lowercase hex digits`)
		}
	}
	return nil
}

// known reports whether n is a value of its enum other than the unspecified
// zero.
func known(n int32, names map[int32]string) bool {
	_, ok := names[n]
	return ok && n != 0
}

// prefixedHex reports whether s is prefix and 32 lowercase hex digits.
func prefixedHex(s, prefix string) bool {
	hex, ok := strings.CutPrefix(s, prefix)
	if !ok || len(hex) != 32 {
		return false
	}
	for _, c := range []byte(hex) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
