package tcpbrutal

import (
	"errors"
	"net"
)

const DefaultCwndGain uint32 = 15

type Config struct {
	Rate     uint64
	CwndGain uint32
}

func NewConfig(rate uint64, cwndGain uint32) (*Config, error) {
	if rate == 0 {
		return nil, errors.New("tcp brutal rate must be greater than 0")
	}
	if cwndGain == 0 {
		return nil, errors.New("tcp brutal cwnd gain must be greater than 0")
	}
	return &Config{Rate: rate, CwndGain: cwndGain}, nil
}

func Apply(conn net.Conn, config *Config) error {
	if config == nil {
		return nil
	}
	return apply(conn, *config)
}

func MbpsToBytesPerSecond(mbps uint64) (uint64, error) {
	if mbps == 0 {
		return 0, errors.New("tcp brutal mbps must be greater than 0")
	}
	if mbps > ^uint64(0)/125000 {
		return 0, errors.New("tcp brutal rate overflowed while converting Mbps to bytes/s")
	}
	return mbps * 125000, nil
}
