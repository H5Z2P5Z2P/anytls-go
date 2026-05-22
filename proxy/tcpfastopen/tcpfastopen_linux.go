//go:build linux

package tcpfastopen

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func listen(ctx context.Context, network, address string, config Config) (net.Listener, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("tcp fast open requires a TCP listener")
	}

	listenConfig := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var sockoptErr error
			if err := conn.Control(func(fd uintptr) {
				sockoptErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, config.QueueLength)
			}); err != nil {
				return err
			}
			return sockoptErr
		},
	}
	return listenConfig.Listen(ctx, network, address)
}
