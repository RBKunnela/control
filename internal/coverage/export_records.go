package coverage

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
	"google.golang.org/protobuf/encoding/protojson"
)

// gapReasons are the reasons ADR-0035 names for a gap.
var gapReasons = []string{"malformed", "too_long", "unsupported_version", "conflicting_event_id", "carriage_return", gapPartialTail}

func (er *exportReader) readHeader(line []byte) error {
	m, err := object(line, "type", "format", "version", "file", "source", "pruned_before", "query")
	if err != nil {
		return err
	}
	if f, err := m.str("format"); err != nil || f != exportFormat {
		return fmt.Errorf("format: want %s", exportFormat)
	}
	v, err := m.str("version")
	if err != nil || !versionOfMajor(v, exportMajor) {
		return fmt.Errorf("version: want major %s", exportMajor)
	}
	if _, ok := m["file"]; !ok {
		return errors.New("file: required")
	}
	if er.x.File, err = m.str("file"); err != nil {
		return err
	}
	if err := er.readSource(m); err != nil {
		return err
	}
	if er.prunedBefore, err = prunedBefore(m, v); err != nil {
		return err
	}
	if err := er.readQuery(m); err != nil {
		return fmt.Errorf("query: %w", err)
	}
	er.header = true
	return nil
}

// prunedBefore reads the header's count of segments pruned before the one
// exported, which a header of version, of minor 0, does not name and so has
// none. A writer of minor 1 or later always names it, so a header of one
// without it is refused rather than read as the most trusting count.
func prunedBefore(m members, version string) (uint64, error) {
	raw, ok := m["pruned_before"]
	switch {
	case !ok && minorZero(version):
		return 0, nil
	case !ok:
		return 0, errors.New("pruned_before: required from minor 1")
	case string(raw) == "null":
		return 0, errors.New("pruned_before: not a count")
	}
	return m.count("pruned_before")
}

// readQuery notes a cursor to start after and any filter: either leaves
// lines of the file out of the export.
func (er *exportReader) readQuery(header members) error {
	if _, ok := header["query"]; !ok {
		return errors.New("required")
	}
	q, err := object(header["query"], "after", "limit", "max_bytes", "request", "run", "tenant", "project", "kind")
	if err != nil {
		return err
	}
	if err := er.readBounds(q); err != nil {
		return err
	}
	for _, filter := range []string{"request", "run", "tenant", "project", "kind"} {
		if _, err := q.list(filter); err != nil {
			return err
		}
		_, present := q[filter]
		er.filtered = er.filtered || present
	}
	return nil
}

func (er *exportReader) readEvent(line []byte) error {
	m, err := object(line, "type", "offset", "cursor", "event")
	if err != nil {
		return err
	}
	if err := er.wholeLine(); err != nil {
		return err
	}
	if _, err := m.count("offset"); err != nil {
		return err
	}
	if err := m.nonEmpty("cursor"); err != nil {
		return err
	}
	raw, ok := m["event"]
	if !ok {
		return errors.New("event: required")
	}
	ev := &controlv1.Event{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, ev); err != nil {
		return errors.New("event: not one Event")
	}
	if !versionOfMajor(ev.GetSchemaVersion(), eventMajor()) {
		return fmt.Errorf("event: schema_version: want major %s", eventMajor())
	}
	er.x.Events++
	if er.keep {
		er.events = append(er.events, ev)
	}
	if at := ev.GetOccurredAt(); at.IsValid() {
		er.x.widen(at.AsTime())
	}
	er.x.index(ev)
	er.counts[recordEvent]++
	return nil
}

// index keeps a proposal by its envelope's trace and span id, the only one an
// observation can join. One whose envelope the contract refuses is only
// noted: a plane records a refused call too, and the agent chose its ids.
func (x *Export) index(ev *controlv1.Event) {
	env := ev.GetProposed()
	if ev.GetKind() != controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED || env.GetTraceId() == "" || env.GetSpanId() == "" {
		return
	}
	k := proposalKey{env.GetTraceId(), env.GetSpanId()}
	if err := contract.Validate(env); err != nil && !lacksEffect(err) {
		x.refused[k] = append(x.refused[k], ev)
		return
	}
	x.proposals[k] = append(x.proposals[k], ev)
}

// lacksEffect is Validate's refusal of an envelope with no effect class: a
// call nothing classifies, which a plane records as proposed and, in OBSERVE,
// lets run. Validate stops there, so such an envelope passed the size, schema
// version and field bounds and carries its ids and time, but its delegation,
// destination host, labels and arguments were not checked.
func lacksEffect(err error) bool {
	var ve *contract.ValidationError
	return errors.As(err, &ve) && ve.Field == "action.effect" && errors.Is(err, contract.ErrMissingField)
}

func (er *exportReader) readGap(line []byte) error {
	m, err := object(line, "type", "offset", "cursor", "reason")
	if err != nil {
		return err
	}
	if _, err := m.count("offset"); err != nil {
		return err
	}
	reason, err := m.str("reason")
	if err != nil || !slices.Contains(gapReasons, reason) {
		return errors.New("reason: not one ADR-0035 names")
	}
	if err := er.readGapCursor(m, reason); err != nil {
		return err
	}
	er.counts[recordGap]++
	return nil
}

func (er *exportReader) readDuplicate(line []byte) error {
	m, err := object(line, "type", "offset", "event_id", "first_offset")
	if err != nil {
		return err
	}
	if err := er.wholeLine(); err != nil {
		return err
	}
	if _, err := m.count("offset"); err != nil {
		return err
	}
	if err := m.nonEmpty("event_id"); err != nil {
		return err
	}
	if _, err := m.count("first_offset"); err != nil {
		return err
	}
	er.counts[recordDuplicate]++
	return nil
}

// widen takes t into the export's window of event times.
func (x *Export) widen(t time.Time) {
	if !x.window || t.Before(x.earliest) {
		x.earliest = t
	}
	if !x.window || t.After(x.latest) {
		x.latest = t
	}
	x.window = true
}

// readTrailer takes the trailer's end_reached, and refuses counts that
// disagree with the records read: a record taken out of the export.
func (er *exportReader) readTrailer(line []byte) error {
	m, err := object(line, "type", "next_cursor", "end_reached", "tail_bytes", "writer_held", "counts",
		"scanned_bytes", "dedup_scope")
	if err != nil {
		return err
	}
	switch string(m["end_reached"]) {
	case "true":
		er.endReached = true
	case "false":
	default:
		return errors.New("end_reached: want true or false")
	}
	c, err := object(m["counts"], recordEvent, recordGap, recordDuplicate)
	if err != nil {
		return fmt.Errorf("counts: %w", err)
	}
	for _, name := range []string{recordEvent, recordGap, recordDuplicate} {
		var n int
		if err := json.Unmarshal(c[name], &n); err != nil || n != er.counts[name] {
			return fmt.Errorf("counts: %s does not count the %d records read", name, er.counts[name])
		}
	}
	if err := er.readTrailerMembers(m); err != nil {
		return err
	}
	er.trailer = true
	return nil
}

// versionOfMajor reports whether v is MAJOR.MINOR in decimal with this major.
func versionOfMajor(v, major string) bool {
	maj, minor, ok := strings.Cut(v, ".")
	return ok && maj == major && decimal(maj) && decimal(minor)
}

// minorZero reports whether a version versionOfMajor took is of minor 0.
func minorZero(v string) bool {
	_, minor, ok := strings.Cut(v, ".")
	return ok && minor != "" && strings.Trim(minor, "0") == ""
}

func decimal(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

// eventMajor is the major of the contract package this build was generated
// from, so a build of another major refuses these events.
func eventMajor() string {
	pkg := string((&controlv1.Event{}).ProtoReflect().Descriptor().ParentFile().Package())
	return strings.TrimPrefix(pkg[strings.LastIndex(pkg, ".")+1:], "v")
}
