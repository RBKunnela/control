package otel

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Options configure an exporter once, at New.
type Options struct {
	// Endpoint is the collector's OTLP/HTTP logs URL: https, or
	// unix:///path, a Unix socket the logs are posted to at UnixLogsPath. An
	// http endpoint is refused, since anyone on its path could read the
	// headers and forge the acceptance that releases the evidence. Its
	// userinfo and query are sent and never logged.
	Endpoint string
	// CollectorUID is the account a unix endpoint's collector runs as, which
	// such an endpoint requires and any other refuses. The exporter reads the
	// peer's account on every connection it opens and sends nothing, the
	// headers included, on one of another account.
	CollectorUID *uint32
	// Headers go on every request, for the collector's authentication. A name
	// has to be an HTTP token and a value free of CR, LF and NUL.
	Headers map[string]string
	// InFlight bounds the unacknowledged requests; it has to be positive.
	InFlight int
	// Timeout bounds one request; it has to be positive.
	Timeout time.Duration
	// MaxBatch bounds the records in one request; zero means DefaultMaxBatch.
	MaxBatch int
	// Linger is how long a batch holding one record waits for more before it
	// is sent; zero means DefaultLinger.
	Linger time.Duration
	// Backoff is the wait before the first retry, doubled each time up to
	// MaxBackoff; zero means the defaults.
	Backoff    time.Duration
	MaxBackoff time.Duration
	// Logger takes one line per answer that is not an acceptance; nil means
	// the process's default logger.
	Logger *slog.Logger
	// Client sends the requests; nil means a client of its own. The exporter
	// uses a copy that follows no redirect, and leaves this one as it is. The
	// request's context carries Timeout, so a client needs no timeout of its
	// own.
	Client *http.Client
}

// Stats counts what the exporter did, for a health answer.
type Stats struct {
	// Acknowledged is the records the spool released past: accepted by a
	// collector, or quarantined.
	Acknowledged uint64
	// Quarantined is the records the exporter put in the spool's quarantine:
	// refused as records three times running, in a request whose answer
	// reported records dropped, or not encodable.
	Quarantined uint64
	// QuarantineHeld is the records the quarantine already held when the
	// exporter offered them again, which a run stopped between quarantining
	// and acknowledging causes.
	QuarantineHeld uint64
	// PartialRejected is the records collectors reported dropped inside
	// requests they otherwise accepted.
	PartialRejected uint64
	// Refused is the answers 400, 413 and 422: the collector refused the
	// records themselves, and the request was split or its record sent again.
	Refused uint64
	// Retries is the requests sent again after an answer that neither
	// accepts nor refuses the records; the fields below count each class.
	Retries uint64
	// RetriedTransport is no answer: a timeout or a connection failure.
	RetriedTransport uint64
	// RetriedPeer is a unix endpoint's connection closed unused because its
	// peer was not CollectorUID or could not be named.
	RetriedPeer uint64
	// RetriedRedirect is a 3xx, which is never followed.
	RetriedRedirect uint64
	// RetriedAuth is 401, 403 and 407.
	RetriedAuth uint64
	// RetriedThrottled is 408 and 429.
	RetriedThrottled uint64
	// RetriedServer is every 5xx.
	RetriedServer uint64
	// RetriedAnswer is a 200 or 202 whose body cannot be read or is not the
	// protocol's answer.
	RetriedAnswer uint64
	// RetriedStatus is any other status.
	RetriedStatus uint64
}

func (o Options) check() (*url.URL, error) {
	u, err := o.endpoint()
	if err != nil {
		return nil, err
	}
	switch {
	case o.InFlight <= 0:
		return nil, fmt.Errorf("%w: InFlight %d is not positive", ErrInvalidOptions, o.InFlight)
	case o.Timeout <= 0:
		return nil, fmt.Errorf("%w: Timeout %v is not positive", ErrInvalidOptions, o.Timeout)
	case o.MaxBatch < 0 || o.Linger < 0 || o.Backoff < 0 || o.MaxBackoff < 0:
		return nil, fmt.Errorf("%w: a negative batch size, linger or backoff", ErrInvalidOptions)
	}
	return u, checkHeaders(o.Headers)
}

// endpoint checks the collector's URL: https with a host, or a unix socket.
// Its refusals quote nothing of the URL, which may carry a credential.
func (o Options) endpoint() (*url.URL, error) {
	u, err := url.Parse(o.Endpoint)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: the endpoint does not parse as a URL", ErrInvalidOptions)
	case u.Scheme == "unix":
		return u, o.checkUnix(u)
	case o.CollectorUID != nil:
		return nil, fmt.Errorf("%w: CollectorUID is set for an endpoint that is not a unix socket", ErrInvalidOptions)
	case u.Scheme == "http":
		return nil, fmt.Errorf("%w: the endpoint is plaintext http, which was removed in 0.17; use https, or a unix socket with CollectorUID", ErrInvalidOptions)
	case u.Scheme != "https" || u.Host == "":
		return nil, fmt.Errorf("%w: the endpoint is not an https URL with a host", ErrInvalidOptions)
	}
	return u, nil
}

// checkHeaders refuses a name that is not an HTTP token and a value that
// could end the header. The refusal names the header, never its value.
func checkHeaders(headers map[string]string) error {
	for name, value := range headers {
		if !isToken(name) {
			return fmt.Errorf("%w: header name %q is not an HTTP token", ErrInvalidOptions, name)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("%w: the value of header %q holds CR, LF or NUL", ErrInvalidOptions, name)
		}
	}
	return nil
}

// isToken reports whether s is an HTTP token (RFC 9110, section 5.6.2).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

func (o *Options) fill() {
	if o.MaxBatch == 0 {
		o.MaxBatch = DefaultMaxBatch
	}
	if o.Linger == 0 {
		o.Linger = DefaultLinger
	}
	if o.Backoff == 0 {
		o.Backoff = DefaultBackoff
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = DefaultMaxBackoff
	}
	if o.MaxBackoff < o.Backoff {
		o.MaxBackoff = o.Backoff
	}
}
