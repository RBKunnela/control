package stopwrite

import (
	"context"
	"fmt"
	"time"

	"github.com/guardana/control/internal/reaction"
)

// AppendStop appends s whatever the list holds, as no writer of a finding
// may: the tests build lists AppendFinding would not write.
func AppendStop(ctx context.Context, dir string, route reaction.Route, s reaction.Stop, now time.Time) (int64, error) {
	if err := reaction.CheckCurrent(s); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return appendLine(ctx, dir, route, at(now), fixed(s.Marshal()))
}

// AppendCovered appends c with no stop of its run behind it, which only a
// test may write: the list's judge leaves that rule to AppendFinding.
func AppendCovered(ctx context.Context, dir string, route reaction.Route, c reaction.Covered, now time.Time) (int64, error) {
	return appendLine(ctx, dir, route, at(now), fixed(c.Marshal()))
}

// SetJudged makes f run once the judge accepted an append and before it is
// written, until the returned function puts the writer back.
func SetJudged(f func()) func() {
	judged = f
	return func() { judged = nil }
}

// SetCarrying makes f run once a carry read the old list and before it
// writes the new one, until the returned function puts the writer back.
func SetCarrying(f func()) func() {
	carrying = f
	return func() { carrying = nil }
}
