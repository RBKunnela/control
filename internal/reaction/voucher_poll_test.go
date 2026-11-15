package reaction_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// slowVoucher is a rosterVoucher that answers each question delay late.
type slowVoucher struct {
	*rosterVoucher
	delay *time.Duration
}

func (v slowVoucher) Vouch(kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	time.Sleep(*v.delay)
	return v.rosterVoucher.Vouch(kind, env)
}

// slowPoller is a poller at interval over bob's lifted list under a route
// alice signed, opened while the voucher answers at once.
func slowPoller(t *testing.T, interval time.Duration) (*stoplist.Poller, *time.Duration) {
	t.Helper()
	delay := new(time.Duration)
	v := slowVoucher{rosterVoucher: newRosterVoucher(), delay: delay}
	r := vouchedRoute(t, v)
	header, head := signedHeaderLine(t, r, headerOpts{key: strangerKey()})
	dir := filepath.Join(t.TempDir(), "stops")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := joinLines(header, signedStop(t, sProject), liftOf(t, head, strangerKey(), 2))
	if err := os.WriteFile(filepath.Join(dir, stoplist.FileName), content, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := stoplist.Open(stoplist.Options{Dir: dir, Route: r, Interval: interval, Clock: func() time.Time { return sNow },
		Owner: stoplist.AnyOwner})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return p, delay
}

// TestAPollWhoseVoucherOutlastsTheIntervalIsUnknown: once the list was
// accepted, a voucher that answers each of the route, the header and the
// lift 60ms late makes a poll at 100ms unknown, the ports' own cause, and a
// poll at one second clear.
func TestAPollWhoseVoucherOutlastsTheIntervalIsUnknown(t *testing.T) {
	p, delay := slowPoller(t, 100*time.Millisecond)
	*delay = 60 * time.Millisecond
	if s := p.Poll(); s.State() != reaction.Unknown || s.Cause() != reaction.CauseUnanswered {
		t.Errorf("a poll past its interval: %v %q %s, want unknown with %q", s.State(), s.Cause(), s.Detail(), reaction.CauseUnanswered)
	}
	p, delay = slowPoller(t, time.Second)
	*delay = 60 * time.Millisecond
	if s := p.Poll(); s.State() != reaction.Clear {
		t.Errorf("a poll within its interval: %v %q %s, want clear", s.State(), s.Cause(), s.Detail())
	}
}

// cancelling is a rosterVoucher that, once armed, ends the poll's context
// while it answers the last question, as a voucher whose last answer comes
// after the deadline.
type cancelling struct {
	*rosterVoucher
	cancel *context.CancelFunc
	left   *int
}

func (v cancelling) Vouch(kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	if *v.cancel != nil {
		if *v.left--; *v.left == 0 {
			(*v.cancel)()
		}
	}
	return v.rosterVoucher.Vouch(kind, env)
}

// contextual is a rosterVoucher that is a ContextVoucher and counts the
// questions it was asked through a context.
type contextual struct {
	*rosterVoucher
	within *int
}

func (v contextual) VouchContext(ctx context.Context, kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	if ctx.Err() != nil {
		return reaction.Signer{}, fmt.Errorf("%w: %w", reaction.ErrUnanswered, ctx.Err())
	}
	*v.within++
	return v.Vouch(kind, env)
}

// TestAVoucherAskedAgainIsHeldToThePollsContext: a context ended before a
// poll asks nothing and is unknown; a last answer, of the route's, the
// header's and the lift's, that comes after the context ended is unknown; a
// ContextVoucher is asked through the context.
func TestAVoucherAskedAgainIsHeldToThePollsContext(t *testing.T) {
	_, content, s := liftedByBob(t, newRosterVoucher())
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	v := newRosterVoucher()
	r := vouchedRoute(t, v)
	v.asked = 0
	expectUnknown(t, "a poll whose context ended", s.NextContext(ended, r, content, sNow, time.Second), reaction.CauseUnanswered)
	if v.asked != 0 {
		t.Errorf("a poll whose context ended asked the voucher %d times", v.asked)
	}
	var arm context.CancelFunc
	left := 3
	late := vouchedRoute(t, cancelling{rosterVoucher: newRosterVoucher(), cancel: &arm, left: &left})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	arm = cancel
	expectUnknown(t, "an answer after the context ended", s.NextContext(ctx, late, content, sNow, time.Second), reaction.CauseUnanswered)
	within := 0
	cr := vouchedRoute(t, contextual{rosterVoucher: newRosterVoucher(), within: &within})
	within = 0
	if again := s.NextContext(t.Context(), cr, content, sNow, time.Second); again.State() != reaction.Clear || within != 3 {
		t.Errorf("a ContextVoucher: %v %q, asked %d times through the context, want clear after 3", again.State(), again.Cause(), within)
	}
}
