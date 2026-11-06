package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/guardana/control/internal/peercred"
)

// serveWholeHealth answers the health answer whole: the stops' entries and
// the runs they name with the counts.
func (p *plane) serveWholeHealth(w http.ResponseWriter, _ *http.Request) {
	answer, ok := p.health(p.pauseSource(), time.Now)
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, p.logger, status, answer)
}

// bindHealthSocket binds health.socket, when configured, beside bound, and
// returns bound with it; a socket it cannot bind releases bound.
func (p *plane) bindHealthSocket(stdout io.Writer, bound []listening) ([]listening, error) {
	if p.cfg.Health.Socket == "" {
		return bound, nil
	}
	allowed := []uint32{uint32(os.Geteuid())} //nolint:gosec // G115: a uid fits 32 bits
	if a := p.cfg.Health.SocketUID; a.Set {
		allowed = append(allowed, a.ID)
	}
	path := p.cfg.Resolve(p.cfg.Health.Socket)
	ln, err := listenHealthSocket(path, p.cfg.Health.SocketUID.Set)
	if err != nil {
		return nil, errors.Join(err, closeListeners(bound))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", p.serveWholeHealth)
	listener := &peerListener{Listener: ln, allowed: allowed, uid: peercred.UID, log: p.logger}
	writeLine(stdout, "answering the whole /healthz on "+path)
	return append(bound, listening{server: newServer(path, mux, idleTimeout, healthReadTimeout), listener: listener}), nil
}

// peerListener hands the server only the connections whose peer is one of
// allowed. Any other is closed unanswered, and each cause of a refusal is
// logged once.
type peerListener struct {
	net.Listener
	allowed []uint32
	// uid reads a connection's peer; a test names another account through it.
	uid    func(net.Conn) (uint32, error)
	log    *slog.Logger
	logged sync.Map
}

// The causes of a refused peer on the health socket.
const (
	healthPeerOther      = "a peer of an account health.socket does not answer"
	healthPeerUnreadable = "a peer whose account cannot be named"
)

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := l.uid(conn)
		if err == nil && slices.Contains(l.allowed, uid) {
			return conn, nil
		}
		cause, fields := healthPeerOther, []any{"peer_uid", uid}
		if err != nil {
			cause, fields = healthPeerUnreadable, []any{"err", err}
		}
		if _, seen := l.logged.LoadOrStore(cause, true); !seen {
			l.log.Warn("health.socket closed a connection unanswered: "+cause, fields...)
		}
		if err := conn.Close(); err != nil {
			l.log.Debug("a refused connection did not close", "err", err)
		}
	}
}
