package otel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
)

// UnixLogsPath is the path a unix endpoint's logs are posted to, OTLP's
// default for logs.
const UnixLogsPath = "/v1/logs"

// unixTarget is the URL of a request over a unix socket: the transport dials
// the socket whatever the host says.
const unixTarget = "http://localhost" + UnixLogsPath

// The causes of a refused peer, each logged once.
const (
	peerOther      = "the collector socket's peer is another account"
	peerUnreadable = "the collector socket's peer cannot be named"
)

// peerRefusal is a connection to a unix endpoint closed before anything was
// written to it.
type peerRefusal struct {
	cause string
	uid   uint32
	err   error
}

func (p *peerRefusal) Error() string {
	if p.cause == peerOther {
		return p.cause + ": uid " + strconv.FormatUint(uint64(p.uid), 10)
	}
	return p.cause + ": " + p.err.Error()
}

// checkUnix refuses a unix endpoint that is anything but an absolute, clean
// socket path, one without the collector's account, one under the plaintext
// setting, and one beside a client of the caller's, whose transport would
// dial without the peer check.
func (o Options) checkUnix(u *url.URL) error {
	switch {
	case u.Host != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" ||
		!path.IsAbs(u.Path) || path.Clean(u.Path) != u.Path:
		return fmt.Errorf("%w: a unix endpoint is unix:// followed by an absolute, clean socket path", ErrInvalidOptions)
	case o.CollectorUID == nil:
		return fmt.Errorf("%w: a unix endpoint needs CollectorUID", ErrInvalidOptions)
	case o.AllowPlaintext:
		return fmt.Errorf("%w: AllowPlaintext is set for a unix endpoint, where it applies to nothing", ErrInvalidOptions)
	case o.Client != nil:
		return fmt.Errorf("%w: a unix endpoint is dialled by the exporter's own transport, and a Client is given", ErrInvalidOptions)
	}
	return nil
}

// unixTransport dials the socket at socketPath and hands a connection to the
// client only once its peer is want. It uses no proxy, which would otherwise
// receive the headers.
func (e *Exporter) unixTransport(socketPath string, want uint32) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			uid, err := e.peerUID(conn)
			switch {
			case err != nil:
				return nil, errors.Join(&peerRefusal{cause: peerUnreadable, err: err}, conn.Close())
			case uid != want:
				return nil, errors.Join(&peerRefusal{cause: peerOther, uid: uid}, conn.Close())
			}
			return conn, nil
		},
	}
}

// notePeer logs a refused peer the first time its cause is met. The count is
// in Stats, so a collector that stays wrong does not fill the log.
func (e *Exporter) notePeer(err error) {
	var p *peerRefusal
	if !errors.As(err, &p) {
		return
	}
	if _, seen := e.peerLogged.LoadOrStore(p.cause, true); seen {
		return
	}
	fields := []any{"why", p.cause, "endpoint", e.where, "collector_uid", *e.opts.CollectorUID}
	if p.cause == peerOther {
		fields = append(fields, "peer_uid", p.uid)
	} else {
		fields = append(fields, "error", p.err.Error())
	}
	e.log.Error("otel: nothing was sent to the collector socket; the records stay in the spool and are sent again", fields...)
}
