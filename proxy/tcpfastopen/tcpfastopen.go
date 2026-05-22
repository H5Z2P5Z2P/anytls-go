package tcpfastopen

import (
	"context"
	"fmt"
	"net"
)

const DefaultQueueLength = 4096

type Config struct {
	QueueLength int
}

func NewConfig(queueLength int) (*Config, error) {
	if queueLength == 0 {
		queueLength = DefaultQueueLength
	}
	if queueLength < 0 {
		return nil, fmt.Errorf("tcp fast open queue length must be non-negative")
	}
	return &Config{QueueLength: queueLength}, nil
}

func Listen(ctx context.Context, network, address string, config *Config) (net.Listener, error) {
	if config == nil {
		var listenConfig net.ListenConfig
		return listenConfig.Listen(ctx, network, address)
	}
	return listen(ctx, network, address, *config)
}
