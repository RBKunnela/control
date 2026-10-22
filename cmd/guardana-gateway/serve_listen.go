package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
)

// listenFunc binds the address a plane's configuration names, or returns the
// listener already bound at it.
type listenFunc func(addr string) (net.Listener, error)

func listenTCP(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }

// listening is one bound address and the server that will answer on it.
type listening struct {
	server   *http.Server
	listener net.Listener
}

// bind takes every address this configuration asks for before anything serves:
// the enforcement API's socket, or the agent-facing listener when it speaks
// HTTP, and the plane's own answers when an address is configured for them.
// An address that is taken is a refusal, and whatever was bound before it is
// released.
func (p *plane) bind(stdout io.Writer, listen listenFunc) ([]listening, error) {
	if p.enforce != nil {
		ln, err := p.enforce.Listen()
		if err != nil {
			return nil, err
		}
		p.socket = ln
		writeLine(stdout, "listening for tools on "+ln.Addr().String())
	}
	bound, err := p.bindTCP(stdout, listen)
	if err != nil && p.socket != nil {
		err = errors.Join(err, p.socket.Close())
	}
	return bound, err
}

func (p *plane) bindTCP(stdout io.Writer, listen listenFunc) ([]listening, error) {
	var wanted []wantedServer
	if p.cfg.Listener.Kind != gatewayconfig.ListenerStdio && p.enforce == nil {
		agents := func() (http.Handler, error) {
			h, err := p.adapter.Handler()
			if err != nil {
				return nil, err
			}
			return p.calls.wrap(h), nil
		}
		wanted = append(wanted, wantedServer{p.cfg.Listener.Address, agents, "listening for agents on ", 0, p.boundSendBuffer})
	}
	if p.cfg.Health.Address != "" {
		health := func() (http.Handler, error) { return p.healthMux(), nil }
		wanted = append(wanted, wantedServer{p.cfg.Health.Address, health, "answering /healthz, /metrics and /brand on ", healthReadTimeout, nil})
	}
	var out []listening
	for _, w := range wanted {
		handler, err := w.handler()
		if err != nil {
			return nil, errors.Join(err, closeListeners(out))
		}
		listener, err := listen(w.addr)
		if err != nil {
			return nil, errors.Join(err, closeListeners(out))
		}
		server := newServer(w.addr, handler, idleTimeout, w.read)
		server.ConnState = w.conns
		out = append(out, listening{server: server, listener: listener})
		writeLine(stdout, w.says+listener.Addr().String())
	}
	return out, nil
}

// agentSendBuffer is the send buffer an agent's connection keeps. The answer
// bound gives each 64 KiB slice of an answer its deadline, and Linux grows a
// send buffer to megabytes and wakes a blocked write only once much of it has
// drained, so a slice would otherwise wait on far more of the agent's reading
// than its own.
const agentSendBuffer = 64 << 10

// boundSendBuffer gives a connection the server has just accepted the agent's
// send buffer. One that cannot take it is served as it is, its answer bound
// then measuring progress in larger steps, and the log says so.
func (p *plane) boundSendBuffer(c net.Conn, state http.ConnState) {
	if state != http.StateNew {
		return
	}
	conn, ok := c.(interface{ SetWriteBuffer(bytes int) error })
	if !ok {
		return
	}
	if err := conn.SetWriteBuffer(agentSendBuffer); err != nil {
		p.logger.Warn("an agent's connection keeps the system's send buffer, so its answer bound measures progress in larger steps", "err", err)
	}
}

// newServer answers on addr with the plane's connection bounds; a read above
// zero bounds a whole request, its body included.
func newServer(addr string, handler http.Handler, idle, read time.Duration) *http.Server {
	return &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: read, IdleTimeout: idle}
}

// wantedServer is one address this configuration asks to be answered on, the
// bound on reading a request there, zero where the handler bounds a body
// itself, and what each of its connections is set to as it changes state.
type wantedServer struct {
	addr    string
	handler func() (http.Handler, error)
	says    string
	read    time.Duration
	conns   func(net.Conn, http.ConnState)
}

func closeListeners(bound []listening) error {
	var errs []error
	for _, b := range bound {
		errs = append(errs, b.listener.Close())
	}
	return errors.Join(errs...)
}
