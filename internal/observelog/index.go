package observelog

import (
	"fmt"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
)

// index maps each observation id the log holds to what it was written with.
// It is rebuilt from the file on every open and never written down, so it
// cannot disagree with the lines it describes.
type index map[string]held

// held is an id's content digest and the run its observation claims, or "".
type held struct{ sum, run string }

func heldOf(o *observev1.Observation) held {
	return held{sum: observe.ContentDigest(o), run: o.GetCorrelation().GetRunId()}
}

// batch is what one write appends and what it found, and the runs its
// conflicting observations claim.
type batch struct {
	lines []byte
	added index
	found Written
	doubt observe.Doubt
}

// fresh encodes the observations neither the index nor an earlier one of obs
// holds, and counts the rest: a duplicate when the content is the same, a
// conflict when it is not. A conflict puts in doubt the run each copy
// claims. An observation the codec refuses, or one with no digest, refuses
// the whole write.
func (ids index) fresh(obs []*observev1.Observation) (batch, error) {
	b := batch{added: index{}}
	for i, o := range obs {
		line, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_Observation{Observation: o}})
		if err != nil {
			return batch{}, fmt.Errorf("%w: observation %d: %w", ErrRecord, i, err)
		}
		h := heldOf(o)
		if h.sum == "" {
			return batch{}, fmt.Errorf("%w: observation %d has no content digest", ErrRecord, i)
		}
		id := o.GetObservationId()
		kept, ok := ids[id]
		if !ok {
			kept, ok = b.added[id]
		}
		switch {
		case ok && kept.sum == h.sum:
			b.found.Duplicates++
		case ok:
			b.found.Conflicts++
			b.doubt.ClaimOf(o)
			// The copy kept may be the false one, so its run is in doubt too;
			// a copy that claims no run is no run's.
			if kept.run != "" {
				b.doubt.Claim(kept.run)
			}
		default:
			b.added[id] = h
			b.lines = append(b.lines, line...)
			b.found.Observations++
		}
	}
	return b, nil
}

func (ids index) add(added index) {
	for id, h := range added {
		ids[id] = h
	}
}
