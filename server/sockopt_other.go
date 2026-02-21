//go:build !linux

package server

import "net"

func setConnOpts(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	tc.SetNoDelay(true)
}
