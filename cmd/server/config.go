package main

import (
	"fmt"
	"os"

	"anytls/proxy/tcpbrutal"

	"gopkg.in/yaml.v3"
)

const (
	defaultServerListen   = "0.0.0.0:8443"
	defaultServerSecurity = "tls"
)

type ServerFileConfig struct {
	Listen        string                `yaml:"listen"`
	Password      string                `yaml:"password"`
	PaddingScheme *string               `yaml:"padding_scheme"`
	Security      string                `yaml:"security"`
	TLS           *TLSFileConfig        `yaml:"tls"`
	Reality       *RealityFileConfig    `yaml:"reality"`
	TCPBrutal     ServerTCPBrutalConfig `yaml:"tcp_brutal"`
}

type TLSFileConfig struct {
	ServerName      string `yaml:"server_name"`
	CertificatePath string `yaml:"certificate_path"`
	KeyPath         string `yaml:"key_path"`
}

type RealityFileConfig struct {
	Dest        string   `yaml:"dest"`
	ServerNames []string `yaml:"server_names"`
	PrivateKey  string   `yaml:"private_key"`
	PublicKey   string   `yaml:"public_key"`
	ShortIDs    []string `yaml:"short_ids"`
	Fingerprint string   `yaml:"fingerprint"`
}

type ServerTCPBrutalConfig struct {
	Enabled  bool   `yaml:"enabled"`
	UpMbps   uint64 `yaml:"up_mbps"`
	DownMbps uint64 `yaml:"down_mbps"`
	CwndGain uint32 `yaml:"cwnd_gain"`
}

func LoadServerFileConfig(path string) (*ServerFileConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config ServerFileConfig
	if err := yaml.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("invalid yaml config %s: %w", path, err)
	}
	config.setDefaults()
	return &config, nil
}

func (c *ServerFileConfig) setDefaults() {
	if c.Listen == "" {
		c.Listen = defaultServerListen
	}
	if c.Security == "" {
		c.Security = defaultServerSecurity
	}
	if c.TCPBrutal.CwndGain == 0 {
		c.TCPBrutal.CwndGain = tcpbrutal.DefaultCwndGain
	}
	if c.Reality != nil && c.Reality.Fingerprint == "" {
		c.Reality.Fingerprint = "chrome"
	}
}

func (c ServerTCPBrutalConfig) ToServerTCPBrutal() (*tcpbrutal.Config, error) {
	if !c.Enabled {
		return nil, nil
	}
	if c.DownMbps == 0 {
		return nil, fmt.Errorf("tcp_brutal.enabled requires tcp_brutal.down_mbps in server yaml config")
	}
	rate, err := tcpbrutal.MbpsToBytesPerSecond(c.DownMbps)
	if err != nil {
		return nil, err
	}
	return tcpbrutal.NewConfig(rate, c.CwndGain)
}
