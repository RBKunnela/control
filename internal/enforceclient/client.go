package enforceclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// The operations' paths and the header a request presents its run token in.
const (
	PathAdmit      = "/enforce/v1alpha1/admit"
	PathComplete   = "/enforce/v1alpha1/complete"
	PathAbort      = "/enforce/v1alpha1/abort"
	RunTokenHeader = "Run-Token"
)

// MaxAnswerBytes bounds an answer's body. An admit answer carries at most
// one envelope's worth of authorized bytes and a decision; anything longer
// is malformed.
const MaxAnswerBytes = contract.MaxEnvelopeBytes

// Config is what a Client needs. Every field but Now is required.
type Config struct {
	// Socket is the path of the receiver's Unix socket.
	Socket string
	// Token is the run token every request presents.
	Token string
	// Timeout bounds each request, including the complete or abort sent
	// after the caller's context ended.
	Timeout time.Duration
	// Now reads the clock for the start and end of a tool run that does not
	// report its own. Nil reads the system clock.
	Now func() time.Time
}

// Client speaks the enforcement API to one receiver as one run. It is safe
// for concurrent use.
type Client struct {
	token   string
	timeout time.Duration
	now     func() time.Time
	http    *http.Client
}

// New returns a Client for cfg, or the refusal of its first missing field.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.Socket == "":
		return nil, ErrNoSocket
	case cfg.Token == "":
		return nil, ErrNoToken
	case cfg.Timeout <= 0:
		return nil, ErrNoTimeout
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	socket := cfg.Socket
	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		MaxResponseHeaderBytes: 1 << 16,
	}
	return &Client{
		token:   cfg.Token,
		timeout: cfg.Timeout,
		now:     now,
		http: &http.Client{
			Transport: transport,
			// A redirect is an answer this contract does not have; following
			// one would send the run token somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// post sends req to path and decodes the answer into resp. The request is
// detached from ctx's cancellation and bounded by the client's timeout: an
// answer lost to the caller giving up leaves an execution only the
// receiver's sweep can close, and only as unknown.
func (c *Client) post(ctx context.Context, path string, req, resp proto.Message) error {
	body, err := protojson.Marshal(req)
	if err != nil {
		return fmt.Errorf("enforceclient: encoding %s: %w", path, err)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://enforce"+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("enforceclient: building %s: %w", path, err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set(RunTokenHeader, c.token)
	hresp, err := c.http.Do(hreq)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrTransport, path, err)
	}
	defer func() { _ = hresp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(hresp.Body, MaxAnswerBytes+1))
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrTransport, path, err)
	}
	return decodeAnswer(hresp.StatusCode, data, resp)
}

// decodeAnswer reads a 200 answer strictly into resp, and any other status
// as the receiver's Error body.
func decodeAnswer(status int, data []byte, resp proto.Message) error {
	if len(data) > MaxAnswerBytes {
		return fmt.Errorf("%w: more than %d bytes", ErrMalformedAnswer, MaxAnswerBytes)
	}
	strict := protojson.UnmarshalOptions{DiscardUnknown: false}
	if status != http.StatusOK {
		var body enforcev1alpha1.Error
		if err := strict.Unmarshal(data, &body); err != nil {
			return fmt.Errorf("%w: status %d with no readable error body: %w", ErrMalformedAnswer, status, err)
		}
		return &RefusalError{Status: status, Code: body.GetCode(), Message: body.GetMessage(), Ending: body.GetEnding()}
	}
	if err := strict.Unmarshal(data, resp); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedAnswer, err)
	}
	if a, ok := resp.(*enforcev1alpha1.AdmitResponse); ok {
		return checkDecisionVersion(a.GetDecision())
	}
	return nil
}

// checkDecisionVersion refuses a decision whose schema_version is absent or
// not MAJOR.MINOR in decimal on the major the generated Decision carries. An
// answer with no decision is left to its outcome.
func checkDecisionVersion(d *controlv1.Decision) error {
	if d == nil {
		return nil
	}
	major, minor, ok := strings.Cut(d.GetSchemaVersion(), ".")
	if !ok || !decimal(major) || !decimal(minor) || major != decisionMajor() {
		return fmt.Errorf("%w: a decision of a schema_version this client does not read", ErrMalformedAnswer)
	}
	return nil
}

func decisionMajor() string {
	pkg := string((&controlv1.Decision{}).ProtoReflect().Descriptor().ParentFile().Package())
	return strings.TrimPrefix(pkg[strings.LastIndex(pkg, ".")+1:], "v")
}

// decimal is ParseUint at base 10, which takes no sign, no underscore and no
// empty string, and 32 bits, as pkg/contract reads a version.
func decimal(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

// refusal returns the receiver's Error body err carries, if any.
func refusal(err error) (*RefusalError, bool) {
	var r *RefusalError
	ok := errors.As(err, &r)
	return r, ok
}
