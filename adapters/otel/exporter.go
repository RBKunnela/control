package otel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/spool"
)

// Error is a refusal by the exporter, matched with errors.Is.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

const (
	// ErrNoReader is a nil spool reader, or Run on an exporter nobody built.
	ErrNoReader Error = "otel: no spool reader"
	// ErrInvalidOptions is a New whose options cannot reach a collector.
	ErrInvalidOptions Error = "otel: invalid options"
	// ErrRunning is a second Run on one exporter. Two runs share one reader,
	// and each one's acknowledgement covers what the other took, so the second
	// is refused rather than left to release evidence nobody delivered.
	ErrRunning Error = "otel: a run is already draining this reader"
)

// Defaults for the options that may be left zero.
const (
	DefaultMaxBatch   = 128
	DefaultLinger     = 100 * time.Millisecond
	DefaultBackoff    = 500 * time.Millisecond
	DefaultMaxBackoff = 30 * time.Second
)

// Exporter drains one spool reader into one collector. New is the only way to
// make a usable one; the zero value exports nothing.
type Exporter struct {
	opts   Options
	reader *spool.Reader
	client *http.Client
	log    *slog.Logger
	// where is the endpoint as logs name it: its scheme and host, since a
	// userinfo, a path or a query can hold a credential.
	where  string
	secret []string
	// encode is the seam a test makes the encoder fail through.
	encode func([]*controlv1.Event) ([]byte, error)

	// running is held for the length of a Run, so a second one is refused.
	running atomic.Bool

	counters [classes]atomic.Uint64
	// ackMu holds a release of the spool and its count together, and Stats
	// reads the count under it: whoever saw the spool released then sees the
	// records counted.
	ackMu       sync.Mutex
	acked       uint64
	quarantined atomic.Uint64
	skipped     atomic.Uint64
	partial     atomic.Uint64
	refused     atomic.Uint64
}

// New checks opts and returns an exporter over r.
func New(opts Options, r *spool.Reader) (*Exporter, error) {
	if r == nil {
		return nil, ErrNoReader
	}
	u, err := opts.check()
	if err != nil {
		return nil, err
	}
	opts.fill()
	e := &Exporter{opts: opts, reader: r, log: opts.Logger, encode: encode}
	e.client = &http.Client{}
	if opts.Client != nil {
		c := *opts.Client
		e.client = &c
	}
	e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if e.log == nil {
		e.log = slog.Default()
	}
	e.where = (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
	if u.User != nil {
		e.secret = append(e.secret, u.User.String())
	}
	if u.RawQuery != "" {
		e.secret = append(e.secret, u.RawQuery)
	}
	return e, nil
}

// Stats reports the counters as they stand.
func (e *Exporter) Stats() Stats {
	e.ackMu.Lock()
	acked := e.acked
	e.ackMu.Unlock()
	st := Stats{
		Acknowledged:     acked,
		Quarantined:      e.quarantined.Load(),
		QuarantineHeld:   e.skipped.Load(),
		PartialRejected:  e.partial.Load(),
		Refused:          e.refused.Load(),
		RetriedTransport: e.counters[classTransport].Load(),
		RetriedRedirect:  e.counters[classRedirect].Load(),
		RetriedAuth:      e.counters[classAuth].Load(),
		RetriedThrottled: e.counters[classThrottled].Load(),
		RetriedServer:    e.counters[classServer].Load(),
		RetriedAnswer:    e.counters[classAnswer].Load(),
		RetriedStatus:    e.counters[classStatus].Load(),
	}
	for i := range e.counters {
		st.Retries += e.counters[i].Load()
	}
	return st
}

// release acknowledges b to the spool and counts its records, as one step
// for Stats.
func (e *Exporter) release(b *batch) error {
	e.ackMu.Lock()
	defer e.ackMu.Unlock()
	if err := e.reader.Ack(b.cursor); err != nil {
		return err
	}
	e.acked += uint64(len(b.events))
	return nil
}

// batch is one request's worth of records and the cursor past the last.
type batch struct {
	events []*controlv1.Event
	cursor spool.Cursor
}

// pending is a batch in flight and what its delivery ended with: nil when
// every record in it was accepted or quarantined.
type pending struct {
	batch *batch
	done  chan error
}

// Run drains the reader from the spool's acknowledged position until ctx is
// done, and acknowledges each batch, in order, once every record in it was
// accepted or quarantined. Whatever an earlier Run took and did not
// acknowledge is delivered again. At most InFlight requests are
// unacknowledged at a time. It returns nil when ctx ends it, and the error
// when the reader, a quarantine or an acknowledgement fails.
//
// One Run drains one reader: a second Run while this one is going is
// ErrRunning, because both would take records the other does not see and each
// one's acknowledgement would cover the other's.
func (e *Exporter) Run(ctx context.Context) error {
	if e.reader == nil {
		return ErrNoReader
	}
	if !e.running.CompareAndSwap(false, true) {
		return ErrRunning
	}
	defer e.running.Store(false)
	if err := e.reader.Rewind(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	slots := make(chan struct{}, e.opts.InFlight)
	queue := make(chan *pending, e.opts.InFlight)
	var wg sync.WaitGroup
	ackErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ackErr <- e.acknowledge(queue, slots, cancel)
	}()

	var err error
	for err == nil {
		err = e.dispatch(ctx, queue, slots, &wg)
	}
	cancel()
	close(queue)
	wg.Wait()
	if aerr := <-ackErr; aerr != nil {
		return aerr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

// dispatch collects one batch, takes an in-flight slot and delivers it in the
// background. The queue is what the acknowledger drains, in order.
func (e *Exporter) dispatch(ctx context.Context, queue chan<- *pending, slots chan struct{}, wg *sync.WaitGroup) error {
	b, err := e.collect(ctx)
	if err != nil {
		return err
	}
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	p := &pending{batch: b, done: make(chan error, 1)}
	queue <- p
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.done <- e.deliver(ctx, b.events)
	}()
	return nil
}

// collect reads one batch: it blocks for the first record and then takes what
// arrives within Linger, up to MaxBatch. Records it read and drops on an error
// are read again by the next Run, which starts at the acknowledged position.
func (e *Exporter) collect(ctx context.Context) (*batch, error) {
	ev, c, err := e.reader.Next(ctx)
	if err != nil {
		return nil, err
	}
	b := &batch{events: []*controlv1.Event{ev}, cursor: c}
	linger, cancel := context.WithTimeout(ctx, e.opts.Linger)
	defer cancel()
	for len(b.events) < e.opts.MaxBatch {
		ev, c, err := e.reader.Next(linger)
		if err != nil {
			if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
				break
			}
			return nil, err
		}
		b.events = append(b.events, ev)
		b.cursor = c
	}
	return b, nil
}

// acknowledge takes the batches in the order they were sent and moves the
// cursor past each one delivered. The cursor is linear, so the first batch
// that was not delivered stops it: nothing after that batch is acknowledged
// in this Run, and the next one sends it all again. A failure other than the
// end of the context stops the Run. Every batch's in-flight slot is released.
func (e *Exporter) acknowledge(queue <-chan *pending, slots <-chan struct{}, stop context.CancelFunc) error {
	var failed error
	halted := false
	for p := range queue {
		err := <-p.done
		switch {
		case halted:
		case err != nil:
			halted = true
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				failed = err
				stop()
			}
		default:
			if aerr := e.release(p.batch); aerr != nil {
				halted = true
				failed = fmt.Errorf("otel: acknowledging %d records: %w", len(p.batch.events), aerr)
				stop()
			}
		}
		<-slots
	}
	return failed
}
