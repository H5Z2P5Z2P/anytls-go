//go:build with_utls

package reality

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"time"

	"anytls/proxy"

	utls "github.com/metacubex/utls"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

type realityServer struct {
	config *utls.RealityConfig
}

func NewServer(ctx context.Context, config ServerConfig) (Server, error) {
	_ = ctx
	privateKey, err := decodeKey(config.PrivateKey)
	if err != nil {
		return nil, err
	}
	serverNames := make(map[string]bool, len(config.ServerNames))
	for _, serverName := range config.ServerNames {
		serverNames[serverName] = true
	}
	shortIDs, err := decodeShortIDs(config.ShortIDs)
	if err != nil {
		return nil, err
	}
	serverName := ""
	if len(config.ServerNames) > 0 {
		serverName = config.ServerNames[0]
	}
	return &realityServer{config: &utls.RealityConfig{
		DialContext: proxy.SystemDialer.DialContext,
		Type:        "tcp",
		Dest:        config.Dest,
		ServerNames: serverNames,
		PrivateKey:  privateKey,
		ShortIds:    shortIDs,
		Config: utls.Config{
			ServerName:             serverName,
			SessionTicketsDisabled: true,
			Time:                   time.Now,
		},
	}}, nil
}

func (s *realityServer) ServerHandshake(conn net.Conn) (net.Conn, error) {
	return utls.RealityServer(context.Background(), conn, s.config)
}

type realityClient struct {
	config boxTLS.Config
}

func NewClient(ctx context.Context, config ClientConfig) (Client, error) {
	fingerprint := config.Fingerprint
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	publicKey, err := normalizeKey(config.PublicKey)
	if err != nil {
		return nil, err
	}
	clientConfig, err := boxTLS.NewRealityClient(ctx, nil, config.ServerAddress, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: config.ServerName,
		Insecure:   true,
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fingerprint,
		},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: publicKey,
			ShortID:   config.ShortID,
		},
	})
	if err != nil {
		return nil, err
	}
	return &realityClient{config: clientConfig}, nil
}

func (c *realityClient) ClientHandshake(conn net.Conn) (net.Conn, error) {
	return boxTLS.ClientHandshake(context.Background(), conn, c.config)
}

func normalizeKey(key string) (string, error) {
	decoded, err := decodeKey(key)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(decoded), nil
}

func decodeKey(key string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(key)
	}
	if err != nil {
		return nil, err
	}
	if len(decoded) != 32 {
		return nil, base64.CorruptInputError(0)
	}
	return decoded, nil
}

func decodeShortIDs(values []string) (map[[8]byte]bool, error) {
	shortIDs := make(map[[8]byte]bool)
	if len(values) == 0 {
		shortIDs[[8]byte{}] = true
		return shortIDs, nil
	}
	for _, value := range values {
		var shortID [8]byte
		decodedLen, err := hex.Decode(shortID[:], []byte(value))
		if err != nil {
			return nil, err
		}
		if decodedLen > 8 {
			return nil, hex.ErrLength
		}
		shortIDs[shortID] = true
	}
	return shortIDs, nil
}
