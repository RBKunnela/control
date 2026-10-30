// Package ingest is the one way a source descriptor is read and its input
// imported. It holds the registry of the kinds this build imports: for each
// kind of observe's table, the checks of the members that kind owns, its
// importer and the labels observe import prints. A kind with no entry has no
// importer and is refused.
//
// It is pure, as its importers are: it reads only the bytes and the reader it
// is given. See ADR-0040.
package ingest

import (
	"fmt"
	"io"
	"slices"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/ingest/egresslog"
	"github.com/guardana/control/internal/ingest/otelgenai"
	"github.com/guardana/control/internal/observe"
)

// Batch is what one import yields: the observations in input order and the
// report that accounts for everything read.
type Batch struct {
	Observations []*observev1.Observation
	Report       *observev1.ImportReport
}

// Count is one count observe import prints, after the read count and what
// the log wrote.
type Count struct {
	Label string
	Of    func(*observev1.ImportCounts) uint64
}

// Labels are what observe import prints for a kind: Read labels the read
// count, which says what the kind's input is made of, and Counts follow in
// order.
type Labels struct {
	Read   string
	Counts []Count
}

// Kind is one kind's entry: Check holds the members the kind owns, Import
// maps its input to observations, and Labels name its counts.
type Kind struct {
	Name   string
	Check  func(*observev1.SourceDescriptor) error
	Import func(r io.Reader, desc *observev1.SourceDescriptor, descriptorSHA256 string, received time.Time) (Batch, error)
	Labels Labels
}

func refused(c *observev1.ImportCounts) uint64        { return c.GetRefused() }
func stringsDropped(c *observev1.ImportCounts) uint64 { return c.GetStringsDropped() }

var kinds = []Kind{
	{
		Name:  observe.KindOTelGenAI,
		Check: otelgenai.Check,
		Import: func(r io.Reader, desc *observev1.SourceDescriptor, sha string, received time.Time) (Batch, error) {
			b, err := otelgenai.Import(r, desc, sha, received)
			return Batch{Observations: b.Observations, Report: b.Report}, err
		},
		Labels: Labels{Read: otelgenai.ReadLabel, Counts: []Count{
			{"other_resource", func(c *observev1.ImportCounts) uint64 { return c.GetOtherResource() }},
			{"refused", refused},
			{"content_attributes_dropped", func(c *observev1.ImportCounts) uint64 { return c.GetContentAttributesDropped() }},
			{"reasoning_parts_dropped", func(c *observev1.ImportCounts) uint64 { return c.GetReasoningPartsDropped() }},
			{"content_unparsed", func(c *observev1.ImportCounts) uint64 { return c.GetContentUnparsed() }},
			{"run_ids_dropped", func(c *observev1.ImportCounts) uint64 { return c.GetRunIdsDropped() }},
			{"strings_dropped", stringsDropped},
			{"skipped", skipped},
		}},
	},
	{
		Name:  observe.KindEgressAccessLog,
		Check: egresslog.Check,
		Import: func(r io.Reader, desc *observev1.SourceDescriptor, sha string, received time.Time) (Batch, error) {
			b, err := egresslog.Import(r, desc, sha, received)
			return Batch{Observations: b.Observations, Report: b.Report}, err
		},
		Labels: Labels{Read: egresslog.ReadLabel, Counts: []Count{
			{"refused", refused},
			{"strings_dropped", stringsDropped},
			{"callers_dropped", func(c *observev1.ImportCounts) uint64 { return c.GetCallersDropped() }},
		}},
	},
}

func skipped(c *observev1.ImportCounts) uint64 {
	var n uint64
	for _, v := range c.GetSkipped() {
		n += v
	}
	return n
}

// Kinds returns the registry in a copy the caller may change.
func Kinds() []Kind {
	out := make([]Kind, len(kinds))
	for i, k := range kinds {
		k.Labels.Counts = slices.Clone(k.Labels.Counts)
		out[i] = k
	}
	return out
}

// Lookup returns the entry of the named kind, and false when the registry
// has none.
func Lookup(name string) (Kind, bool) {
	for _, k := range Kinds() {
		if k.Name == name {
			return k, true
		}
	}
	return Kind{}, false
}

// ReadDescriptor parses an operator's source descriptor and holds it to every
// rule of ADR-0040: observe's checks, which every kind shares, then the
// checks of the members its kind owns. A kind the registry has no entry for
// is refused. Every refusal wraps observe.ErrDescriptor.
func ReadDescriptor(raw []byte) (*observev1.SourceDescriptor, error) {
	d, err := observe.ReadNeutral(raw)
	if err != nil {
		return nil, err
	}
	k, ok := Lookup(d.GetKind())
	if !ok {
		return nil, fmt.Errorf("%w: kind: %q has no importer in this build", observe.ErrDescriptor, d.GetKind())
	}
	if err := k.Check(d); err != nil {
		return nil, fmt.Errorf("%w: %w", observe.ErrDescriptor, err)
	}
	return d, nil
}
