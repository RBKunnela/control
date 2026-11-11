package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
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
	allowed, reachable, err := healthSocketReaders(p.cfg)
	if err != nil {
		return nil, errors.Join(err, closeListeners(bound))
	}
	path := p.cfg.Resolve(p.cfg.Health.Socket)
	ln, err := listenHealthSocket(path, reachable)
	if err != nil {
		return nil, errors.Join(err, closeListeners(bound))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", p.serveWholeHealth)
	listener := &peerListener{Listener: ln, allowed: allowed, uid: peercred.UID, log: p.logger}
	writeLine(stdout, "answering the whole /healthz on "+path)
	return append(bound, listening{server: newServer(path, mux, idleTimeout, healthReadTimeout), listener: listener}), nil
}

// healthSocketReaders is the accounts health.socket answers, the plane's
// own and health.socket_uid's, and whether another account is to reach it.
// A health.socket_uid that is the plane's own account is refused: it would
// open the socket 0666 and its directory to others for an account the socket
// answers already.
func healthSocketReaders(cfg *gatewayconfig.Config) ([]uint32, bool, error) {
	own := uint32(os.Geteuid()) //nolint:gosec // G115: a uid fits 32 bits
	a := cfg.Health.SocketUID
	switch {
	case !a.Set:
		return []uint32{own}, false, nil
	case a.ID == own:
		return nil, false, fmt.Errorf("health.socket_uid: %d is the plane's own account, which health.socket answers already; unset it, or name the other account that is to read the socket", a.ID)
	}
	return []uint32{own, a.ID}, true, nil
}

// healthSocket says whom health.socket answers and judges its directory as
// a start does. Where another account is to reach the socket, a directory
// on its path that account may not search is named in a warning: the plane
// starts, and that account is never answered.
func (d *examination) healthSocket(context.Context) (string, string, string) {
	const name = "health.socket"
	allowed, reachable, err := healthSocketReaders(d.cfg)
	if err != nil {
		return verdictFail, name, err.Error()
	}
	path := d.cfg.Resolve(d.cfg.Health.Socket)
	if err := healthDir(filepath.Dir(path), reachable); err != nil {
		return verdictFail, name, err.Error()
	}
	if reachable {
		blocked, err := unsearchable(filepath.Dir(path), allowed[1])
		if err != nil {
			return verdictUnknown, name, "whether health.socket_uid may reach the socket is not known: " + err.Error()
		}
		if blocked != "" {
			writeLine(d.out, "       warning: health.socket: "+oneLine(blocked))
		}
	}
	found := fmt.Sprintf("the whole /healthz on %s, to uid %d", path, allowed[0])
	if reachable {
		found += fmt.Sprintf(" and uid %d, socket mode 0666, every other peer closed unanswered", allowed[1])
	} else {
		found += ", socket mode 0600"
	}
	return verdictOK, name, found
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
