package reaction_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// slowKind is a rosterVoucher that answers each question about a document
// of kind delay late, and every other at once.
type slowKind struct {
	*rosterVoucher
	kind  reaction.SignedKind
	delay *time.Duration
}

func (v slowKind) Vouch(kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	if kind == v.kind {
		time.Sleep(*v.delay)
	}
	return v.rosterVoucher.Vouch(kind, env)
}

// TestALiftFirstReadPastThePollsIntervalIsUnknown: a list accepted with a
// stop and no lift, then a lift appended whose signer the voucher answers
// for only past the poll's interval, makes the poll unknown, the ports' own
// cause, rather than clear.
func TestALiftFirstReadPastThePollsIntervalIsUnknown(t *testing.T) {
	delay := new(time.Duration)
	r := vouchedRoute(t, slowKind{rosterVoucher: newRosterVoucher(), kind: reaction.VouchLift, delay: delay})
	header, head := signedHeaderLine(t, r, headerOpts{key: strangerKey()})
	stop := signedStop(t, sProject)
	dir := filepath.Join(t.TempDir(), "stops")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, stoplist.FileName)
	if err := os.WriteFile(file, joinLines(header, stop), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := stoplist.Open(stoplist.Options{Dir: dir, Route: r, Interval: 100 * time.Millisecond, Clock: func() time.Time { return sNow },
		Owner: stoplist.AnyOwner})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if s := p.Current(); s.State() != reaction.Stopped {
		t.Fatalf("the list with its stop: %v %q %s", s.State(), s.Cause(), s.Detail())
	}
	if err := os.WriteFile(file, joinLines(header, stop, liftOf(t, head, strangerKey(), 2)), 0o600); err != nil {
		t.Fatal(err)
	}
	*delay = 150 * time.Millisecond
	if s := p.Poll(); s.State() != reaction.Unknown || s.Cause() != reaction.CauseUnanswered {
		t.Errorf("a lift answered for past the interval: %v %q %s, want unknown with %q", s.State(), s.Cause(), s.Detail(), reaction.CauseUnanswered)
	}
	*delay = 0
	if s := p.Poll(); s.State() != reaction.Clear {
		t.Errorf("the lift answered for at once: %v %q %s, want clear", s.State(), s.Cause(), s.Detail())
	}
}

// TestAHeaderFirstReadPastThePollsIntervalIsNotServed: a header whose signer
// the voucher answers for only past the poll's interval makes the first
// read unknown, so the poller does not open.
func TestAHeaderFirstReadPastThePollsIntervalIsNotServed(t *testing.T) {
	delay := new(time.Duration)
	r := vouchedRoute(t, slowKind{rosterVoucher: newRosterVoucher(), kind: reaction.VouchHeader, delay: delay})
	header, _ := signedHeaderLine(t, r, headerOpts{key: strangerKey()})
	dir := filepath.Join(t.TempDir(), "stops")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stoplist.FileName), joinLines(header, signedStop(t, sProject)), 0o600); err != nil {
		t.Fatal(err)
	}
	*delay = 150 * time.Millisecond
	_, err := stoplist.Open(stoplist.Options{Dir: dir, Route: r, Interval: 100 * time.Millisecond, Clock: func() time.Time { return sNow },
		Owner: stoplist.AnyOwner})
	if !errors.Is(err, stoplist.ErrNotServable) || !strings.Contains(err.Error(), string(reaction.CauseUnanswered)) {
		t.Fatalf("Open over a header answered for past the interval: %v, want not servable, %q", err, reaction.CauseUnanswered)
	}
}
