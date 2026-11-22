package stopwrite_test

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// model is what the list holds, kept apart from the judge, to say which
// write it must accept.
type model struct {
	lines    int64
	findings map[string]bool
	lifts    map[string]bool
	// stops is the line of each stop of a run; through is the last line a
	// lift of the run ended its stops through.
	stops   map[string][]int64
	through map[string]int64
}

func (m *model) name(finding string) {
	m.findings[finding] = true
}

// ends reports whether a lift of run through line ends a stop no lift ended.
func (m *model) ends(run string, line int64) bool {
	for _, s := range m.stops[run] {
		if s > m.through[run] && s <= line {
			return true
		}
	}
	return false
}

// propertyRun is one sequence of writes from one seed.
type propertyRun struct {
	t      *testing.T
	rng    *rand.Rand
	r      reaction.Route
	dir    string
	listID string
	plane  *stoplist.Poller
	m      model
}

// outcome is one random write: whether the model accepts it, what the
// writer said, and what the write was.
type outcome struct {
	ok   bool
	n    int64
	err  error
	what string
}

func (p *propertyRun) step() outcome {
	finding := fmt.Sprintf("f-%d", p.rng.IntN(24))
	run := fmt.Sprintf("run-%d", p.rng.IntN(3))
	switch p.rng.IntN(4) {
	case 0:
		ok := !p.m.findings[finding]
		n, err := stopwrite.AppendStop(bg, p.dir, p.r, stopOf(p.t, finding, run, clock0), clock0)
		if ok {
			p.m.name(finding)
			p.m.stops[run] = append(p.m.stops[run], p.m.lines+1)
		}
		return outcome{ok, n, err, "stop " + finding + " of " + run}
	case 1:
		c := coveredOf(finding, run, clock0)
		if p.rng.IntN(5) == 0 {
			c.TenantID = "other"
		}
		ok := !p.m.findings[finding] && c.TenantID == "acme"
		n, err := stopwrite.AppendCovered(bg, p.dir, p.r, c, clock0)
		if ok {
			p.m.name(finding)
		}
		return outcome{ok, n, err, "covered " + finding + " of " + run + " of " + c.TenantID}
	case 2:
		through := 1 + p.rng.Int64N(p.m.lines+1)
		key := fmt.Sprintf("%s@%d", run, through)
		ok := through <= p.m.lines && !p.m.lifts[key] && p.m.ends(run, through)
		n, err := stopwrite.AppendLift(bg, p.dir, p.r, liftOf(p.t, liftKey(), p.r, p.listID, run, through), clock0)
		if ok {
			p.m.lifts[key] = true
			p.m.through[run] = max(p.m.through[run], through)
		}
		return outcome{ok, n, err, "lift " + key}
	default:
		n, err := stopwrite.AppendLift(bg, p.dir, p.r, liftOf(p.t, otherKey(), p.r, p.listID, run, 1), clock0)
		return outcome{false, n, err, "lift under another key"}
	}
}

// tear leaves part of a line at the list's end, as a writer that died would.
func (p *propertyRun) tear() {
	line := must(p.t)(stopOf(p.t, "f-torn", "run-0", clock0).Marshal())
	setContent(p.t, p.dir, append(content(p.t, p.dir), line[:1+p.rng.IntN(len(line))]...))
}

func (p *propertyRun) check(i int) {
	if p.rng.IntN(6) == 0 {
		p.tear()
	}
	before := content(p.t, p.dir)
	o := p.step()
	p.verdict(i, o, before)
	if o.ok {
		p.m.lines++
	}
	p.read(i, o)
}

// verdict fails unless the writer said what the model says, and a refused
// write left the list as before.
func (p *propertyRun) verdict(i int, o outcome, before []byte) {
	t := p.t
	switch {
	case o.ok && (o.err != nil || o.n != p.m.lines+1):
		t.Fatalf("write %d, %s: %d, %v; the model accepts it as line %d", i, o.what, o.n, o.err, p.m.lines+1)
	case !o.ok && (!errors.Is(o.err, stopwrite.ErrRefused) || o.n != 0):
		t.Fatalf("write %d, %s: %d, %v; the model refuses it", i, o.what, o.n, o.err)
	case !o.ok && !bytes.Equal(content(t, p.dir), before):
		t.Fatalf("write %d, %s: refused, and the list changed", i, o.what)
	}
}

// read fails unless the list holds the model's lines, an accepted write left
// no torn tail, and the plane accepts every complete line.
func (p *propertyRun) read(i int, o outcome) {
	t := p.t
	after := content(t, p.dir)
	complete := int64(bytes.LastIndexByte(after, '\n') + 1)
	if o.ok && complete != int64(len(after)) {
		t.Fatalf("write %d, %s: an accepted write left a torn tail", i, o.what)
	}
	s := p.plane.Poll()
	if s.State() == reaction.Unknown || s.Accepted().Length() != complete {
		t.Fatalf("write %d, %s: the plane reads %s (%s), accepted %d of %d bytes", i, o.what, s.State(), s.Detail(), s.Accepted().Length(), complete)
	}
	if got := int64(bytes.Count(after, []byte{'\n'})); got != p.m.lines {
		t.Fatalf("write %d, %s: the list holds %d lines, the model %d", i, o.what, got, p.m.lines)
	}
}

// TestEveryLineTheWriterWritesThePlaneAccepts: over random sequences of
// stops, covered lines and lifts, good and bad, with torn tails left between
// them, the writer accepts exactly what a model of the grammar accepts,
// leaves the list as it was on a refusal, and the plane's poller, judging
// each read from the one before, accepts every list the writer made.
func TestEveryLineTheWriterWritesThePlaneAccepts(t *testing.T) {
	r := testRoute(t)
	for seed := range uint64(6) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			t.Parallel()
			dir, h := initDir(t, r)
			p := &propertyRun{
				t: t, rng: rand.New(rand.NewPCG(seed, seed^0x5eed)), //nolint:gosec // G404: a reproducible sequence of writes, not a secret
				r: r, dir: dir, listID: h.ListID, plane: planeOn(t, dir, r),
				m: model{lines: 1, findings: map[string]bool{}, lifts: map[string]bool{}, stops: map[string][]int64{}, through: map[string]int64{}},
			}
			accepted := int64(0)
			for i := range 80 {
				p.check(i)
				accepted = p.m.lines - 1
			}
			if accepted < 20 {
				t.Errorf("only %d of 80 writes were accepted; the sequence examined little", accepted)
			}
		})
	}
}
