//go:build !unix

package main

import (
	"errors"
	"net"
)

// listenHealthSocket refuses: the configuration refuses health.socket where
// no peer's account can be named, so nothing reaches here but a defect.
func listenHealthSocket(string, bool) (net.Listener, error) {
	return nil, errors.New("health.socket: this platform cannot name a socket peer's account")
}
