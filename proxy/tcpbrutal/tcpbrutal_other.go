//go:build !linux

package tcpbrutal

import (
	"errors"
	"net"
)

func apply(conn net.Conn, config Config) error {
	_ = conn
	_ = config
	return errors.New("tcp brutal is only supported on Linux")
}
