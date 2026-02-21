//go:build linux

package server

import (
	"net"
	"syscall"
)

func setConnOpts(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	tc.SetNoDelay(true)

	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)
	})
}
