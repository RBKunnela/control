package runs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"time"
)

// judgeRecord takes a record read from a signed layout through what every
// reader checks: signed for the records/ at records, then taken by j.
func judgeRecord(ctx context.Context, sr SignedRecord, records string, j Judge) (SignedBy, error) {
	if sr.Records != records {
		return SignedBy{}, fmt.Errorf("%w: %s, not %s", ErrOtherDirectory, clip(sr.Records), clip(records))
	}
	if j == nil {
		return SignedBy{}, ErrUnjudged
	}
	return j.Judge(ctx, sr)
}

// take judges a record of the signed layout and counts the answer.
func (p *Plane) take(ctx context.Context, sr SignedRecord) error {
	if _, err := judgeRecord(ctx, sr, p.records, p.judge); err != nil {
		p.counts.refused(err)
		return err
	}
	p.counts.add("judged")
	return nil
}

// notReplayed refuses, with ErrReplayed, an open record of a run whose close
// state/ holds or the handle failed to carry. It is nil off a signed layout
// and for a closed record.
func (p *Plane) notReplayed(rec Record) error {
	if !p.signed || rec.Closed() {
		return nil
	}
	if p.uncarried.has(rec.ID) {
		p.counts.refused(ErrReplayed)
		return fmt.Errorf("%w: %s, whose close was not carried", ErrReplayed, rec.ID)
	}
	switch closed, err := p.marked(rec.ID + closedSuffix); {
	case err != nil:
		return fmt.Errorf("the close of %s: %w", rec.ID, err)
	case !closed:
		return nil
	}
	p.counts.refused(ErrReplayed)
	return fmt.Errorf("%w: %s", ErrReplayed, rec.ID)
}

// closesAnyway reports whether a closed record the judge refused still
// carries its close: one whose signature an operator key of the roster makes,
// for this directory and the plane's tenant and project, whose signer may no
// longer operate there. Carrying it errs toward closed, and leaving it would
// let the open record put back count again.
func closesAnyway(rec Record, err error) bool {
	return rec.Closed() && errors.Is(err, ErrUnauthorized)
}

// carry writes the close of run id into state/, where it outlives the closed
// record: a run once closed stays closed whatever records/ holds later. A
// close carried already is left as it is. A close it fails to write is held
// in the handle instead, so the run's open record put back is refused, until
// writeHeld writes it.
func (p *Plane) carry(id string) error {
	p.uncarried.writing.Lock()
	defer p.uncarried.writing.Unlock()
	if err := p.st.createEmpty(id + closedSuffix); err != nil {
		p.uncarried.add(id)
		p.counts.add("carry_failed")
		return fmt.Errorf("the close of %s was not carried: %w", id, err)
	}
	p.counts.add("closes_carried")
	return nil
}

// maxUncarried is the most closes a plane holds that state/ did not take.
// Holding one more could fail, and a close forgotten would let the run's open
// record count again, so at the bound the plane refuses every signed resolve,
// counting with the closes held each resolve admitted, which may hold one.
const maxUncarried = 64

// writeHeld writes into state/ every close the handle holds, dropping each
// once written, and returns what still refused, each naming its run and
// counted as carry_failed. A signed resolve calls it first, as do the survey
// and Close, so a held close reaches state/ as soon as state/ takes it.
func (p *Plane) writeHeld() error {
	p.uncarried.writing.Lock()
	defer p.uncarried.writing.Unlock()
	var errs []error
	for _, id := range p.uncarried.list() {
		if err := p.st.createEmpty(id + closedSuffix); err != nil {
			p.counts.add("carry_failed")
			errs = append(errs, fmt.Errorf("the close of %s was not carried: %w", id, err))
			continue
		}
		p.uncarried.remove(id)
		p.counts.add("closes_carried")
	}
	return errors.Join(errs...)
}

// ready writes the held closes and admits one resolve, refusing with
// ErrUncarried while the closes held and the resolves admitted reach
// maxUncarried. The resolve calls the func it returns when it ends.
func (p *Plane) ready() (func(), error) {
	err := p.writeHeld()
	if n, ok := p.uncarried.admit(maxUncarried); !ok {
		return nil, errors.Join(fmt.Errorf("%w: %d held", ErrUncarried, n), err)
	}
	return p.uncarried.done, nil
}

// closeSet is a set of run ids safe for concurrent use, with the resolves
// admitted that may each add one.
type closeSet struct {
	mu       sync.Mutex
	ids      map[string]bool
	admitted int
	// writing makes a close's write and the set's change one step, so a
	// write that finds another's file half made never drops the id.
	writing sync.Mutex
}

// admit counts one more resolve and reports true, or the ids held and false
// where they and the resolves counted already reach bound.
func (c *closeSet) admit(bound int) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.ids)+c.admitted >= bound {
		return len(c.ids), false
	}
	c.admitted++
	return 0, true
}

func (c *closeSet) done() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.admitted--
}

func (c *closeSet) remove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.ids, id)
}

func (c *closeSet) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ids)
}

func (c *closeSet) list() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.ids))
	for id := range c.ids {
		out = append(out, id)
	}
	return out
}

func (c *closeSet) add(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ids == nil {
		c.ids = map[string]bool{}
	}
	c.ids[id] = true
}

func (c *closeSet) has(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ids[id]
}

// createEmpty creates the empty file name and forces it and the directory to
// disk, and leaves a file already at name alone.
func (d *dir) createEmpty(name string) error {
	f, err := d.createNew(name)
	switch {
	case errors.Is(err, fs.ErrExist):
		return nil
	case err != nil:
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	return d.syncDir()
}

// Survey is what a plane read of every record of a signed layout found.
type Survey struct {
	// Records is how many records were read, at most the bound asked for.
	Records int
	// Open, Closed and Expired count the records the judge took: open and
	// unexpired, closed, and open but expired at the reading.
	Open, Closed, Expired int
	// Refused counts the records that did not count, by cause.
	Refused map[string]int
	// Signers counts the records taken by the subject that signed them.
	Signers map[string]int
	// Carried is how many closes CarryCloses wrote into state/.
	Carried int
	// Complete is false when the bound stopped the read.
	Complete bool
}

// CarryCloses reads every record of a signed layout and writes into state/
// the close of each closed record its judge takes, so that the open record
// put back after a close the plane never resolved is refused all the same.
// A serving plane calls it at its start. A record that does not count is
// counted and left: it refuses only the calls it would cover. A close it
// cannot write, one the handle held among them, stops the read with an error
// naming the run, which a serving plane does not start past.
func (p *Plane) CarryCloses(ctx context.Context, bound int, now time.Time) (Survey, error) {
	return p.survey(ctx, bound, now, true)
}

// Inspect is CarryCloses with nothing written: what a check that may not
// change the directory reports.
func (p *Plane) Inspect(ctx context.Context, bound int, now time.Time) (Survey, error) {
	return p.survey(ctx, bound, now, false)
}

func (p *Plane) survey(ctx context.Context, bound int, now time.Time, carry bool) (Survey, error) {
	if !p.Signed() {
		return Survey{}, fmt.Errorf("%w: an unsigned directory has no record to judge", ErrLayout)
	}
	if bound <= 0 {
		return Survey{}, fmt.Errorf("%w: %d", ErrBound, bound)
	}
	end, err := p.begin(ctx)
	if err != nil {
		return Survey{}, err
	}
	defer end()
	if carry {
		if err := p.writeHeld(); err != nil {
			return Survey{}, err
		}
	}
	entries, err := p.d.readDir()
	if err != nil {
		return Survey{}, err
	}
	ids, err := p.d.scan(entries)
	if err != nil {
		return Survey{}, err
	}
	out := Survey{Refused: map[string]int{}, Signers: map[string]int{}, Complete: len(ids) <= bound}
	if !out.Complete {
		ids = ids[:bound]
	}
	for _, id := range ids {
		if err := p.surveyOne(ctx, id, now, carry, &out); err != nil {
			return out, err
		}
	}
	return out, nil
}

// surveyOne judges the record of id and counts it into out, carrying its
// close where carry; the error is a close it could not carry.
func (p *Plane) surveyOne(ctx context.Context, id string, now time.Time, carry bool, out *Survey) error {
	out.Records++
	stored, err := p.d.readStored(id)
	var by SignedBy
	if err == nil {
		by, err = judgeRecord(ctx, stored, p.records, p.judge)
	}
	if err == nil {
		err = p.notReplayed(stored.Record)
	}
	if err != nil {
		out.Refused[recordCause(err)]++
		if carry && closesAnyway(stored.Record, err) {
			return p.carryCounted(id, out)
		}
		return nil
	}
	out.Signers[by.Subject]++
	rec := stored.Record
	switch {
	case rec.Closed():
		out.Closed++
		if carry {
			return p.carryCounted(id, out)
		}
	case now.IsZero() || !now.Before(rec.ExpiresAt):
		out.Expired++
	default:
		out.Open++
	}
	return nil
}

// carryCounted carries the close of id and counts it into out.
func (p *Plane) carryCounted(id string, out *Survey) error {
	if err := p.carry(id); err != nil {
		return err
	}
	out.Carried++
	return nil
}

// RecordCauses is every label a record that did not count is counted under,
// in the order a counter lists them. None names a run.
func RecordCauses() []string {
	return []string{"unsigned", "malformed", "other_directory", "unauthenticated", "other_scope", "unauthorized",
		"authority", "unjudged", "replayed", "parent_closed", "plane_owned", "unreadable"}
}

// recordCause is the label of a refusal of a record.
func recordCause(err error) string {
	for _, c := range []struct {
		err   error
		label string
	}{
		{ErrUnsigned, "unsigned"}, {ErrOtherDirectory, "other_directory"}, {ErrUnauthenticated, "unauthenticated"},
		{ErrOtherScope, "other_scope"}, {ErrUnauthorized, "unauthorized"}, {ErrAuthority, "authority"},
		{ErrUnjudged, "unjudged"}, {ErrReplayed, "replayed"}, {ErrParentClosed, "parent_closed"}, {ErrPlaneOwned, "plane_owned"},
		{ErrMalformed, "malformed"}, {ErrSchemaVersion, "malformed"}, {ErrUnknownField, "malformed"},
		{ErrMissingField, "malformed"}, {ErrDuplicateField, "malformed"}, {ErrEncoding, "malformed"},
		{ErrNameMismatch, "malformed"},
	} {
		if errors.Is(err, c.err) {
			return c.label
		}
	}
	return "unreadable"
}

// signedCounts is what a plane of a signed layout counted since it opened.
type signedCounts struct {
	mu sync.Mutex
	n  map[string]uint64
}

func newSignedCounts() *signedCounts {
	n := map[string]uint64{"judged": 0, "closes_carried": 0, "carry_failed": 0}
	for _, c := range RecordCauses() {
		n["refused_"+c] = 0
	}
	return &signedCounts{n: n}
}

func (c *signedCounts) add(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n[key]++
}

func (c *signedCounts) refused(err error) { c.add("refused_" + recordCause(err)) }

// SignedCounts is what the handle counted since it opened, every key present
// from zero: records judged and taken, refused by cause, closes carried and
// carries that failed. It is nil off a signed layout.
func (p *Plane) SignedCounts() map[string]uint64 {
	if !p.Signed() || p.counts == nil {
		return nil
	}
	p.counts.mu.Lock()
	defer p.counts.mu.Unlock()
	out := make(map[string]uint64, len(p.counts.n))
	for k, v := range p.counts.n {
		out[k] = v
	}
	return out
}
