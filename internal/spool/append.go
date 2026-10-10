package spool

import (
	"bytes"
	"context"
	"fmt"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
)

// trail names the reservation an ACTION_STARTED opens: the request it records
// and the execution it started. A closing record spends the reservation only
// when it names both, so a record of another call, or of another attempt at
// this one, cannot spend an allowance that is not its.
type trail struct {
	request   string
	execution string
}

func trailOf(event *controlv1.Event) trail {
	return trail{request: event.GetRequestId(), execution: event.GetExecutionId()}
}

// Append writes one event as a framed, checksummed record and returns when it
// is durable under the fsync policy. It answers ErrFull when the budget is
// reached, and a caller blocks the call it was recording.
//
// An ACTION_STARTED reserves ClosingReserve bytes for its trail, the request
// and execution it names. It is ErrTrail when it names no request_id or its
// trail already holds a reservation, and ErrFull past MaxOpenTrails. The
// ACTION_COMPLETED or ACTION_FAILED naming the same trail spends the
// reservation: it is never refused on the budget for the bytes the reservation
// covers, and the bytes past them are checked like any record's. A closing
// record naming another trail is an ordinary append, budget and all. A closing
// append can still fail on I/O, and on an event the codec refuses, which is an
// error of evidence and not of the disk.
func (s *Spool) Append(ctx context.Context, event *controlv1.Event) error {
	if event == nil {
		return evidence.ErrNoEvent
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var line bytes.Buffer
	if err := evidence.EncodeJSONL(&line, []*controlv1.Event{event}); err != nil {
		return err
	}
	record := frame(line.Bytes())

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	at := trailOf(event)
	reserve, closes, err := s.admit(event.GetKind(), at, int64(len(record)))
	if err != nil {
		return err
	}
	if err := s.write(record); err != nil {
		return err
	}
	switch {
	case closes:
		s.reservedTotal -= s.reserved[at]
		delete(s.reserved, at)
	case reserve > 0:
		s.reserved[at] = reserve
		s.reservedTotal += reserve
	}
	close(s.notify)
	s.notify = make(chan struct{})
	return nil
}

// admit decides an append of size bytes: the reservation it opens, whether it
// closes a trail holding one, or why it is refused.
func (s *Spool) admit(kind controlv1.EventKind, at trail, size int64) (reserve int64, closes bool, err error) {
	held, open := s.reserved[at]
	// extra is what the append adds to the bytes on disk, reserve what it adds
	// to the reservations.
	extra := size
	switch kind {
	case controlv1.EventKind_EVENT_KIND_ACTION_STARTED:
		switch {
		case at.request == "":
			return 0, false, fmt.Errorf("%w: ACTION_STARTED names no request_id", ErrTrail)
		case open:
			return 0, false, fmt.Errorf("%w: trail %+v already holds a reservation", ErrTrail, at)
		case len(s.reserved) >= s.opts.MaxOpenTrails:
			return 0, false, fmt.Errorf("%w: %d trails hold a reservation, the ceiling", ErrFull, len(s.reserved))
		}
		reserve = s.opts.ClosingReserve
	case controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED, controlv1.EventKind_EVENT_KIND_ACTION_FAILED:
		if open {
			closes = true
			extra -= held
			if extra <= 0 {
				return 0, true, nil
			}
		}
	}
	// Compared by what is left, never by a sum: a reserve near the type's
	// limit would wrap the sum and admit the append.
	room := s.opts.MaxBytes - s.bytesLocked() - s.reservedTotal
	if extra > room || reserve > room-extra {
		return 0, false, ErrFull
	}
	return reserve, closes, nil
}
