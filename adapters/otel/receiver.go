package otel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// ErrNoSink is a receiver built with nothing to keep what it accepts.
const ErrNoSink Error = "otel: no sink for the records a receiver accepts"

// ErrSinkRefused is what a sink's error matches, with errors.Is, when the sink
// will never keep the events it was handed, as against not keeping them now.
// The receiver answers it with 400, as it answers a request it cannot read.
const ErrSinkRefused Error = "otel: the sink refuses the records for good"

// Sink keeps the events a receiver accepted. Append returns nil only once
// every event it was handed is durable, because the answer the receiver gives
// on a nil lets the sender release them.
type Sink interface {
	Append(ctx context.Context, events []*controlv1.Event) error
}

// ErrCredential is a credential a receiver will not require: none, or one
// outside the bounds and the characters NewCredential takes.
const ErrCredential Error = "otel: a receiver requires a credential of printable ASCII with no space, 32 to 512 bytes" //nolint:gosec // G101: an error's text, which holds no credential

// The bounds of a credential's length.
const (
	MinCredentialBytes = 32
	MaxCredentialBytes = 512
)

// Credential is the bearer token a receiver requires in the Authorization
// header of every request. Only its digest is kept. The zero value is no
// credential, which NewReceiver refuses.
type Credential struct {
	sum [sha256.Size]byte
	set bool
}

// NewCredential takes token as the credential every request must carry, as
// "Authorization: Bearer <token>". A token is printable ASCII with no space,
// so it travels in a header as it is, of MinCredentialBytes to
// MaxCredentialBytes.
func NewCredential(token string) (Credential, error) {
	if len(token) < MinCredentialBytes || len(token) > MaxCredentialBytes {
		return Credential{}, fmt.Errorf("%w: %d bytes", ErrCredential, len(token))
	}
	for i := range len(token) {
		if c := token[i]; c <= ' ' || c > '~' {
			return Credential{}, fmt.Errorf("%w: byte %d is not printable ASCII", ErrCredential, i)
		}
	}
	return Credential{sum: sha256.Sum256([]byte(token)), set: true}, nil
}

// admits reports whether header carries the credential: one Authorization
// header, of the Bearer scheme, whose token is the credential. The digests
// are compared in constant time, so neither the token nor its length is
// learned from how long a refusal takes.
func (c Credential) admits(header http.Header) bool {
	values := header.Values("Authorization")
	if !c.set || len(values) != 1 {
		return false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], c.sum[:]) == 1
}

// NewReceiver returns the handler of OTLP/HTTP logs requests in the JSON
// encoding that hands the events ReadRequest reads to sink, and answers:
//
//   - 401 for a request without cred, before anything else of it is read,
//     closing the connection, which the exporter answers by sending it again, so a sender without
//     the credential writes nothing; the first is logged, then a count at
//     most once a minute;
//   - 200 with an empty body once sink.Append returned nil, which is what
//     lets the exporter release the records;
//   - 400 for a request ReadRequest refuses or the sink refuses with
//     ErrSinkRefused, and 413 for one over MaxRequestBytes, which the
//     exporter answers by halving the batch and in the end quarantining the
//     record it cannot deliver;
//   - 503 when the sink fails otherwise, which the exporter answers by sending the same
//     records again, and which fills the plane's spool while it lasts;
//   - 503 too for a body that could not be read to its end within the bound,
//     as one arriving slower than the server's read timeout or cut by a reset
//     connection: the exporter sends it again, so a body that can never be
//     read in time is retried, fills the spool and blocks material calls;
//   - 405 for a method other than POST, and 415 for a body that is not
//     application/json in UTF-8, or that carries a content coding.
//
// No answer carries a body, and a log line names a refusal without quoting
// the request. The previews of arguments and results, and the profiles naming
// them, are cleared before the sink sees an event, whatever the sender's
// capture setting was.
func NewReceiver(sink Sink, log *slog.Logger, cred Credential) (http.Handler, error) {
	if sink == nil {
		return nil, ErrNoSink
	}
	if !cred.set {
		return nil, fmt.Errorf("%w: none given", ErrCredential)
	}
	if log == nil {
		log = slog.Default()
	}
	return &receiver{sink: sink, log: log, cred: cred, maxBytes: MaxRequestBytes, refused: refusals{now: time.Now}}, nil
}

type receiver struct {
	sink Sink
	log  *slog.Logger
	cred Credential
	// maxBytes is MaxRequestBytes; a test lowers it to go over it cheaply.
	maxBytes int64
	refused  refusals
}

// unauthorizedEvery bounds how often the requests refused for want of the
// credential are logged: once, then a count at most this often, so a local
// account looping requests cannot fill the log.
const unauthorizedEvery = time.Minute

// refusals counts the requests refused 401 since the last line that said so.
type refusals struct {
	mu      sync.Mutex
	now     func() time.Time
	last    time.Time
	pending int
}

// note counts one refusal and logs the count when the last line is older
// than unauthorizedEvery, or there was none.
func (r *refusals) note(log *slog.Logger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending++
	at := r.now()
	if !r.last.IsZero() && at.Sub(r.last) < unauthorizedEvery {
		return
	}
	log.Warn("otel: requests refused", "status", http.StatusUnauthorized,
		"why", "they did not carry the credential", "requests", r.pending)
	r.last, r.pending = at, 0
}

func (h *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.cred.admits(r.Header) {
		h.refused.note(h.log)
		w.Header().Set("WWW-Authenticate", "Bearer")
		// An HTTP/1.1 server reads a small unread body before it answers, to
		// keep the connection; one it closes it answers first.
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if why := unsupported(r.Header); why != "" {
		h.log.Warn("otel: request refused", "status", http.StatusUnsupportedMediaType, "why", why)
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBytes))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		h.refuse(w, http.StatusRequestEntityTooLarge, ErrRequestTooLarge)
		return
	case err != nil:
		h.refuse(w, http.StatusServiceUnavailable, err)
		return
	}
	events, err := ReadRequest(body)
	switch {
	case errors.Is(err, ErrRequestTooLarge):
		h.refuse(w, http.StatusRequestEntityTooLarge, err)
		return
	case err != nil:
		h.refuse(w, http.StatusBadRequest, err)
		return
	}
	for _, ev := range events {
		uncapture(ev)
	}
	if len(events) > 0 {
		err := h.sink.Append(r.Context(), events)
		if errors.Is(err, ErrSinkRefused) {
			h.refuse(w, http.StatusBadRequest, err)
			return
		}
		if err != nil {
			h.log.Error("otel: the records could not be kept; the sender will send them again",
				"status", http.StatusServiceUnavailable, "records", len(events), "error", err.Error())
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// uncapture clears the previews on ev in place, the fields the plane clears
// before its own sink when capture is off. Neither is a digest input, and the
// chain links events by id, so a trail checks the same without them.
func uncapture(ev *controlv1.Event) {
	if a := ev.GetProposed().GetArguments(); a != nil {
		a.RedactedPreview, a.RedactionProfile = "", ""
	}
	if r := ev.GetResult(); r != nil {
		r.RedactedResultPreview, r.RedactionProfile = "", ""
	}
}

func (h *receiver) refuse(w http.ResponseWriter, status int, err error) {
	h.log.Warn("otel: request refused", "status", status, "why", err.Error())
	w.WriteHeader(status)
}

// unsupported says why a request's headers name a body this receiver does not
// read, or nothing when they name JSON in UTF-8 with no content coding. Every
// Content-Encoding field is read, as a coding in any one applies, and a
// second Content-Type field is refused, as the two name no one media type.
func unsupported(header http.Header) string {
	for _, coding := range header.Values("Content-Encoding") {
		if coding != "" && !strings.EqualFold(coding, "identity") {
			return "the body carries a content coding"
		}
	}
	if len(header.Values("Content-Type")) > 1 {
		return "the request carries more than one content type"
	}
	media, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	switch {
	case err != nil:
		return "the content type does not parse"
	case media != "application/json":
		return "the content type is not application/json"
	}
	for name, value := range params {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			return "the content type carries a parameter other than charset=utf-8"
		}
	}
	return ""
}
