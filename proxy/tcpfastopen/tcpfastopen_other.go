//go:build !linux

package tcpfastopen

import (
	"context"
	"errors"
	"net"
)

func listen(ctx context.Context, network, address string, config Config) (net.Listener, error) {
	_ = ctx
	_ = network
	_ = address
	_ = config
	return nil, errors.New("tcp fast open is only supported on Linux")
}
