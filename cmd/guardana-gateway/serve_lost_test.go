package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

var errAcceptBroken = errors.New("accept broken for good")

// agentsListener says when it accepted a connection and when the stop
// closes it.
type agentsListener struct {
	net.Listener
	accepted chan<- struct{}
	closing  chan struct{}
	once     sync.Once
}

func (l *agentsListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted <- struct{}{}
	}
	return c, err
}

func (l *agentsListener) Close() error {
	l.once.Do(func() { close(l.closing) })
	return l.Listener.Close()
}

// brokenAfter fails Accept for good once closing is closed.
type brokenAfter struct {
	net.Listener
	closing <-chan struct{}
}

func (l *brokenAfter) Accept() (net.Conn, error) {
	<-l.closing
	return nil, errAcceptBroken
}

// TestRunReportsAListenerThatFailedWhileItStopped: a listener that fails on
// its own after the stop began, while another listener's shutdown still
// waits on a connection, is an error run returns, never a clean stop.
func TestRunReportsAListenerThatFailedWhileItStopped(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "127.0.0.1:0")
	p := tr.plane(t)
	p.grace = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := p.startUpstreams(ctx); err != nil {
		t.Fatalf("startUpstreams: %v", err)
	}
	accepted, closing := make(chan struct{}, 1), make(chan struct{})
	var bound int
	listen := func(addr string) (net.Listener, error) {
		ln, err := listenTCP(addr)
		if err != nil {
			return nil, err
		}
		if bound++; bound == 1 {
			return &agentsListener{Listener: ln, accepted: accepted, closing: closing}, nil
		}
		return &brokenAfter{Listener: ln, closing: closing}, nil
	}
	stdout := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- p.run(ctx, stdout, listen, 0) }()
	const says = "listening for agents on "
	line := waitFor(t, stdout, says)
	conn, err := net.Dial("tcp", strings.TrimSpace(line[strings.Index(line, says)+len(says):]))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // the test's own connection
	// A request begun and not finished keeps the agents' shutdown waiting
	// out its grace.
	if _, err := conn.Write([]byte("POST /mcp HTTP/1.1\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("the agents' listener accepted no connection")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, errAcceptBroken) {
			t.Errorf("run returned %v, want the listener's failure", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not return")
	}
}
