package docscheck

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/coverage"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/findinglog"
	"github.com/guardana/control/internal/hookbridge"
	"github.com/guardana/control/internal/ingest"
	"github.com/guardana/control/internal/ingest/egresslog"
	"github.com/guardana/control/internal/observe"
	"github.com/guardana/control/internal/observelog"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/scenario"
	"github.com/guardana/control/internal/supervise"
	"github.com/guardana/control/internal/trailfile"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// versionSpecs is every row the page must hold, keyed by its Format cell's
// text before the parentheses.
func versionSpecs() map[string]versionSpec {
	return map[string]versionSpec{
		wireRowKey: {
			name: func() string { return protoPackage(&controlv1.Event{}) },
			cites: []versionCite{
				{"internal/evidence/event.go#SchemaVersion", writes},
				{"internal/core/codes.go#schemaVersion", writes},
				{"adapters/mcp/translate.go#schemaVersion", writes},
				{"adapters/enforce/translate.go#schemaVersion", writes},
				{"internal/gateway/decisions.go#decisionSchemaVersion", writes},
				{"internal/gateway/decisions.go#approvalSchemaVersion", writes},
				{"internal/gateway/decisions.go#resultSchemaVersion", writes},
			},
			refuses: func(v string) (bool, error) {
				return evidence.CheckEventVersion(&controlv1.Event{SchemaVersion: v}) != nil, nil
			},
		},
		"Evidence export": {
			name: func() string { return trailfile.ExportFormat },
			cites: []versionCite{
				{"internal/trailfile/export.go#ExportVersion", writes},
				{"internal/coverage/export.go#exportMajor", readsMajor},
			},
			refuses: evidenceExportRefuses,
		},
		"Policy document": {
			cites: []versionCite{{"internal/policy/rules/rules.go#apiVersion", reads}},
			refuses: func(v string) (bool, error) {
				_, _, err := rules.Parse([]byte(`{"apiVersion":` + strconv.Quote(v) + `,"bundle":{},"rules":[]}`))
				return errors.Is(err, rules.ErrAPIVersion), nil
			},
		},
		"Freshness statement": {
			cites: []versionCite{{"internal/policy/statement.go#StatementKind", writes | reads}},
		},
		"Floor directories": {
			cites: []versionCite{
				{"internal/policystate/format.go#SchemaVersion", writes},
				{"internal/policystate/format.go#checkSchemaVersion/major", readsMajor},
			},
		},
		"Scenario": {
			cites: []versionCite{{"internal/scenario/scenario.go#Kind", reads}},
			refuses: func(v string) (bool, error) {
				_, err := scenario.Read("probe.json", []byte(`{"kind":`+strconv.Quote(v)+`}`))
				return errors.Is(err, scenario.ErrKind), nil
			},
		},
		"Pause file": {
			cites: []versionCite{{"internal/pause/document.go#SchemaVersion", writes | reads}},
			refuses: func(v string) (bool, error) {
				_, err := pause.Parse([]byte(`{"schema_version":` + strconv.Quote(v) + `,"entries":[]}`))
				return errors.Is(err, pause.ErrVersion), nil
			},
		},
		"Approvals directory": {
			cites: []versionCite{
				{"internal/approvals/record.go#SchemaVersion", writes},
				{"internal/approvals/record.go#checkSchemaVersion/major", readsMajor},
			},
		},
		"Hold journal": {
			cites: []versionCite{
				{"internal/holdjournal/entry.go#SchemaVersion", writes},
				{"internal/gateway/journal.go#holdEntrySchemaVersion", writes},
				{"internal/holdjournal/codec.go#checkSchemaVersion/major", readsMajor},
			},
		},
		"Hook profile": {
			cites: []versionCite{{"internal/hookbridge/profile.go#Kind", reads}},
			refuses: func(v string) (bool, error) {
				_, err := hookbridge.ParseProfile([]byte(`{"kind":` + strconv.Quote(v) + `}`))
				return errors.Is(err, hookbridge.ErrProfileVersion), nil
			},
		},
		"Hook bridge handles": {
			cites: []versionCite{
				{"internal/hookbridge/store.go#entryVersion", writes},
				{"internal/hookbridge/store.go#parseEntry/major", readsMajor},
			},
		},
		"Runs directory marker and root state": {
			cites: []versionCite{
				{"internal/runs/strict.go#SchemaVersion", writes},
				{"internal/runs/strict.go#checkSchemaVersion/major", readsMajor},
			},
		},
		"Run record": {
			cites: []versionCite{
				{"internal/runs/strict.go#RecordVersion", writes},
				{"internal/runs/strict.go#checkRecordVersion/major", readsMajor},
			},
		},
		"Enforcement API": {
			name: func() string { return protoPackage(&enforcev1alpha1.AdmitRequest{}) },
			cites: []versionCite{
				{"adapters/enforce/adapter.go#APIVersion", writes | reads},
				{"internal/enforceclient/client.go#APIVersion", writes | reads},
			},
		},
		"Observation records and log": {
			name: func() string { return protoPackage(&observev1.Record{}) },
			cites: []versionCite{
				{"internal/observe/version.go#SchemaVersion", writes | reads},
				{"internal/observe/version.go#SchemaVersion02", writes | reads},
				{"internal/observe/version.go#SchemaVersion03", writes | reads},
				{"internal/observe/version.go#checkVersion/major", readsMajor},
			},
			refuses: func(v string) (bool, error) { return errors.Is(observe.CheckVersion(v), observe.ErrVersion), nil },
		},
		"Source descriptor": {
			cites: []versionCite{
				{"internal/observe/version.go#descriptorSchema01", reads},
				{"internal/observe/version.go#descriptorSchema02", reads},
				{"internal/observe/version.go#checkVersion/major", readsMajor},
			},
			refuses: func(v string) (bool, error) {
				_, err := ingest.ReadDescriptor([]byte(`{"schema_version":` + strconv.Quote(v) + `}`))
				return errors.Is(err, observe.ErrVersion), nil
			},
		},
		"OpenTelemetry GenAI spans, imported": {
			cites: []versionCite{
				{"internal/ingest/otelgenai/descriptor.go#ConventionVersion", reads},
				{"internal/ingest/otelgenai/descriptor.go#OTLPVersion", reads},
			},
		},
		"Egress access log, imported": {
			refuses: egressFormatRefuses,
		},
		"Observation export": {
			name:  func() string { return observelog.ExportFormat },
			cites: []versionCite{{"internal/observelog/export.go#ExportVersion", writes}},
		},
		"Coverage inventory": {
			cites: []versionCite{{"internal/coverage/inventory.go#InventoryVersion", reads}},
			refuses: func(v string) (bool, error) {
				_, err := coverage.ReadInventory([]byte(`{"schema_version":` + strconv.Quote(v) + `,"paths":[]}`))
				return err != nil && strings.Contains(err.Error(), "schema_version"), nil
			},
		},
		"Procedure": {
			cites: []versionCite{
				{"internal/supervise/ruletable.go#ProcedureSchema01", reads},
				{"internal/supervise/ruletable.go#ProcedureSchema02", reads},
			},
			refuses: func(v string) (bool, error) {
				_, err := supervise.ReadProcedure([]byte(`{"schema_version":` + strconv.Quote(v) + `}`))
				return err != nil && strings.Contains(err.Error(), "schema_version is neither"), nil
			},
		},
		"Procedure test cases": {
			cites: []versionCite{{"cmd/" + brand.CLI + "/procedure_cases.go#casesSchema", reads}},
		},
		"Finding records and log": {
			name: func() string { return protoPackage(&findingv1alpha1.Record{}) },
			cites: []versionCite{
				{"internal/supervise/evaluate.go#RecordSchemaVersion", writes},
				{"internal/supervise/record.go#recordSchema02", writes},
				{"internal/supervise/report.go#reportSchema02", writes},
				{"internal/findinglog/check.go#SchemaVersion01", reads},
				{"internal/findinglog/check.go#SchemaVersion02", writes | reads},
			},
		},
		"Findings export": {
			name:  func() string { return findinglog.ExportFormat },
			cites: []versionCite{{"internal/findinglog/export.go#ExportVersion", writes}},
		},
		"Reaction route": {
			cites: []versionCite{{"internal/reaction/route.go#RouteKind", reads}},
			refuses: func(v string) (bool, error) {
				_, err := reaction.ParseRoute([]byte(`{"kind":` + strconv.Quote(v) + `}`))
				return errors.Is(err, reaction.ErrRouteKind), nil
			},
		},
		"Stop list": {
			cites: []versionCite{{"internal/reaction/line.go#ListVersion", writes | reads}},
			refuses: func(v string) (bool, error) {
				_, err := reaction.ParseLine([]byte(`{"kind":"header","version":` + strconv.Quote(v) + `}`))
				return errors.Is(err, reaction.ErrLineVersion), nil
			},
		},
		"Lift": {
			cites: []versionCite{
				{"internal/reaction/lift.go#LiftKind", writes | reads},
				{"internal/reaction/lift.go#LiftVersion", writes | reads},
			},
		},
	}
}

func protoPackage(m interface {
	ProtoReflect() protoreflect.Message
}) string {
	return string(m.ProtoReflect().Descriptor().ParentFile().Package())
}

// evidenceExportRefuses reads a whole export golden with its header's
// version set to v. Anything but the version left as the golden has it, the
// golden is read, so a refusal is the version's.
func evidenceExportRefuses(v string) (bool, error) {
	golden, err := fs.ReadFile(os.DirFS(versionsRepoRoot()), versionsExportGolden)
	if err != nil {
		return false, err
	}
	header, rest, _ := bytes.Cut(golden, []byte("\n"))
	const written = `"version":"` + trailfile.ExportVersion + `"`
	if bytes.Count(header, []byte(written)) != 1 {
		return false, errors.New(versionsExportGolden + ": the header does not name the written version once")
	}
	header = bytes.Replace(header, []byte(written), []byte(`"version":`+strconv.Quote(v)), 1)
	_, err = coverage.ReadExport(bytes.NewReader(append(append(header, '\n'), rest...)))
	return err != nil, nil
}

const versionsExportGolden = "testdata/export/records.jsonl"

// egressFormatRefuses reads the Envoy fixture's descriptor with its format
// set to v. The format is the only member changed, so a refusal is the
// format's.
func egressFormatRefuses(v string) (bool, error) {
	raw, err := fs.ReadFile(os.DirFS(versionsRepoRoot()), versionsEgressDescriptor)
	if err != nil {
		return false, err
	}
	const written = `"format": "` + egresslog.Format + `"`
	if bytes.Count(raw, []byte(written)) != 1 {
		return false, errors.New(versionsEgressDescriptor + ": the descriptor does not name the format once")
	}
	if _, err := ingest.ReadDescriptor(raw); err != nil {
		return false, fmt.Errorf("%s does not load as written: %w", versionsEgressDescriptor, err)
	}
	_, err = ingest.ReadDescriptor(bytes.Replace(raw, []byte(written), []byte(`"format": `+strconv.Quote(v)), 1))
	return err != nil, nil
}

const versionsEgressDescriptor = "internal/ingest/egresslog/testdata/envoy.descriptor.json"

// versionsRepoRoot is the repository root, three directories above this file.
func versionsRepoRoot() string {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(self)))
}
