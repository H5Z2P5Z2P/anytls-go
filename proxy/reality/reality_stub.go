//go:build !with_utls

package reality

import (
	"context"
	"errors"
)

func NewServer(ctx context.Context, config ServerConfig) (Server, error) {
	_ = ctx
	_ = config
	return nil, errors.New("reality requires rebuilding anytls-go with -tags with_utls")
}

func NewClient(ctx context.Context, config ClientConfig) (Client, error) {
	_ = ctx
	_ = config
	return nil, errors.New("reality requires rebuilding anytls-go with -tags with_utls")
}
