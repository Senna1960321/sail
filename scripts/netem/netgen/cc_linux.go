//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// setCongestion gives a socket the congestion control `name`
// (TCP_CONGESTION), before it connects or listens.
func setCongestion(c syscall.RawConn, name string) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, name)
	}); err != nil {
		return err
	}
	return serr
}

// tcpStates names the kernel's TCP states (include/net/tcp_states.h), as
// TCP_INFO's tcpi_state gives them.
var tcpStates = map[uint8]string{1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV",
	4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
	9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING"}

// tcpState is where a connection stands (TCP_INFO), read without reading
// from it: a stalled one's unread data stays ahead of the peer's FIN, so
// only the state tells that the peer ended it (CLOSE_WAIT) or reset it
// (CLOSE).
func tcpState(c net.Conn) (string, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return "", errors.New("not a TCP connection")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return "", err
	}
	var info syscall.TCPInfo
	var serr error
	if err := raw.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(info))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP,
			syscall.TCP_INFO, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			serr = errno
		}
	}); err != nil {
		return "", err
	}
	if serr != nil {
		return "", serr
	}
	if name, ok := tcpStates[info.State]; ok {
		return name, nil
	}
	return fmt.Sprintf("STATE_%d", info.State), nil
}
