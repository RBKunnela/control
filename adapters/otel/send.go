package otel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/transportcause"
)

// maxAnswerBytes bounds what is read of a collector's answer. An accepting
// answer longer than this is not an acceptance, and the request is sent again.
const maxAnswerBytes = 64 << 10

// errAnswerTooLong is an answer longer than maxAnswerBytes.
const errAnswerTooLong Error = "otel: the answer is longer than the bound"

// maxRefusals is how many times running a collector may refuse one record
// before it goes to the quarantine.
const maxRefusals = 3

// deliver sends events until every one of them is accepted or quarantined,
// and returns nil then. It returns ctx's error when ctx ends first, and the
// error of a quarantine that failed; either way nothing may be acknowledged
// past these records. Only a refusal of the records themselves splits the
// request; every other answer that is not an acceptance sends it again, with
// backoff, for as long as it takes.
func (e *Exporter) deliver(ctx context.Context, events []*controlv1.Event) error {
	body, err := e.encode(events)
	if err != nil {
		if len(events) > 1 {
			return e.split(ctx, events)
		}
		return e.quarantine(events, "the encoder refused the record", err.Error())
	}
	delay := e.opts.Backoff
	refusals := 0
	for {
		a := e.post(ctx, body, len(events))
		if err := ctx.Err(); err != nil {
			return err
		}
		if done, err := e.settle(ctx, events, a, &refusals); done {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(2*delay, e.opts.MaxBackoff)
	}
}

// settle acts on one answer. It reports done, with deliver's result, when the
// answer settles the records; otherwise it counts and logs the answer, and
// refusals holds how many times running the collector refused them.
func (e *Exporter) settle(ctx context.Context, events []*controlv1.Event, a answer, refusals *int) (bool, error) {
	switch {
	case a.class == classAccepted && a.rejected > 0:
		e.partial.Add(uint64(a.rejected))
		return true, e.quarantine(events, "the collector dropped records from an accepted request",
			append(a.fields(), "rejected", a.rejected)...)
	case a.class == classAccepted:
		return true, nil
	case a.class == classRefused && len(events) > 1:
		e.refused.Add(1)
		e.log.Warn("otel: collector refused the records; splitting the request",
			append(a.fields(), "records", len(events))...)
		return true, e.split(ctx, events)
	case a.class == classRefused:
		e.refused.Add(1)
		*refusals++
		if *refusals >= maxRefusals {
			return true, e.quarantine(events, "the collector refused the record "+strconv.Itoa(*refusals)+" times running", a.fields()...)
		}
		e.log.Warn("otel: collector refused a record; sending it again",
			append(a.fields(), "refusals", *refusals)...)
	case a.class == classPeer:
		*refusals = 0
		e.counters[a.class].Add(1)
		e.notePeer(a.err)
	default:
		*refusals = 0
		e.counters[a.class].Add(1)
		e.log.Warn("otel: request not accepted; sending it again",
			append(a.fields(), "error", e.scrub(a.err), "records", len(events))...)
	}
	return false, nil
}

// split delivers each half of events in turn.
func (e *Exporter) split(ctx context.Context, events []*controlv1.Event) error {
	half := len(events) / 2
	if err := e.deliver(ctx, events[:half]); err != nil {
		return err
	}
	return e.deliver(ctx, events[half:])
}

// quarantine keeps events in the spool's quarantine, so the cursor may pass
// them without dropping them, and logs why. Records the quarantine already
// holds are not written again, which is what a run stopped between
// quarantining and acknowledging leaves behind.
func (e *Exporter) quarantine(events []*controlv1.Event, why string, fields ...any) error {
	written, err := e.reader.Quarantine(events)
	if err != nil {
		return fmt.Errorf("otel: quarantining %d records: %w", len(events), err)
	}
	e.quarantined.Add(uint64(written)) //nolint:gosec // G115: a count of records written is never negative
	held := len(events) - written
	if held > 0 {
		e.skipped.Add(uint64(held))
	}
	e.log.Error("otel: records quarantined",
		append([]any{"why", why, "records", len(events), "written", written, "held_already", held}, fields...)...)
	return nil
}

// post sends one request and classifies its answer over a batch of batch
// records.
func (e *Exporter) post(ctx context.Context, body []byte, batch int) answer {
	ctx, cancel := context.WithTimeout(ctx, e.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.target, bytes.NewReader(body))
	if err != nil {
		return answer{class: classTransport, err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.opts.Headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	var peer *peerRefusal
	switch {
	case errors.As(err, &peer):
		return answer{class: classPeer, err: err}
	case err != nil:
		return answer{class: classTransport, err: err}
	}
	defer resp.Body.Close() //nolint:errcheck // the answer is read; nothing to lose on close
	// One byte past the bound is read, so an answer that reaches it is told
	// from one whose valid prefix ends there.
	text, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	if err == nil && len(text) > maxAnswerBytes {
		err = errAnswerTooLong
	}
	return classify(resp.StatusCode, text, err, batch)
}

// The causes scrub words a failure by when its text is not printed.
const (
	causeWithheld = "the transport failed; its text is withheld, since it can quote what the collector sent"
	causeDeadline = "the collector did not answer in time"
	causeCanceled = transportcause.Canceled
	causeClosed   = transportcause.Closed
	causeSocket   = transportcause.Socket
)

var causes = transportcause.Words{Withheld: causeWithheld, Deadline: causeDeadline}

// scrub renders an error for a log line by what failed: a transport's failure
// by the operation, the endpoint without its userinfo or query, and a cause
// chosen from the error's type; the exporter's own error by its words. No
// other error's text is printed, since the HTTP client quotes a malformed
// answer's bytes, which can echo the request line and its headers.
func (e *Exporter) scrub(err error) string {
	if err == nil {
		return ""
	}
	var ue *url.Error
	var own Error
	text := causes.Of(err)
	switch {
	case errors.As(err, &ue):
		text = ue.Op + " " + e.where + ": " + causes.Of(ue.Err)
	case errors.As(err, &own):
		text = own.Error()
	}
	for _, secret := range e.secret {
		text = strings.ReplaceAll(text, secret, "[redacted]")
	}
	return text
}
