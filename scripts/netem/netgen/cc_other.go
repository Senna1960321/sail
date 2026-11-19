//go:build !linux

package main

import (
	"errors"
	"net"
	"syscall"
)

// setCongestion: only Linux chooses a socket's congestion control.
func setCongestion(c syscall.RawConn, name string) error {
	return errors.New("-cc: Linux only")
}

// tcpState: only Linux is read for a connection's state.
func tcpState(c net.Conn) (string, error) {
	return "", errors.New("TCP state: Linux only")
}
