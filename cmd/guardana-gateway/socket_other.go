//go:build !unix

package main

import (
	"errors"
	"net"
)

// listenCollectSocket refuses: nothing here can bind a socket no other
// account could replace.
func listenCollectSocket(string) (net.Listener, error) {
	return nil, errors.New("a unix socket is not served on this platform")
}
