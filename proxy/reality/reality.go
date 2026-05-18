package reality

import "net"

type ServerConfig struct {
	Dest        string
	ServerNames []string
	PrivateKey  string
	ShortIDs    []string
	Fingerprint string
}

type ClientConfig struct {
	ServerAddress string
	ServerName    string
	PublicKey     string
	ShortID       string
	Fingerprint   string
}

type Server interface {
	ServerHandshake(conn net.Conn) (net.Conn, error)
}

type Client interface {
	ClientHandshake(conn net.Conn) (net.Conn, error)
}
