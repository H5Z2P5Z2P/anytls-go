package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestServerYAMLParsesRealityAndBrutalSections(t *testing.T) {
	var config ServerFileConfig
	if err := yaml.Unmarshal([]byte(`
listen: 0.0.0.0:28088
password: secret
security: reality
reality:
  dest: pypi.org:443
  server_names:
    - pypi.org
  private_key: QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=
tcp_brutal:
  enabled: true
  up_mbps: 500
  down_mbps: 50
`), &config); err != nil {
		t.Fatal(err)
	}
	config.setDefaults()

	if config.Listen != "0.0.0.0:28088" {
		t.Fatalf("unexpected listen: %s", config.Listen)
	}
	if config.Security != "reality" {
		t.Fatalf("unexpected security: %s", config.Security)
	}
	if config.Reality == nil || len(config.Reality.ServerNames) != 1 || config.Reality.ServerNames[0] != "pypi.org" {
		t.Fatalf("unexpected reality config: %#v", config.Reality)
	}
	if config.TCPBrutal.DownMbps != 50 {
		t.Fatalf("unexpected down_mbps: %d", config.TCPBrutal.DownMbps)
	}
}

func TestServerYAMLParsesTLSSection(t *testing.T) {
	var config ServerFileConfig
	if err := yaml.Unmarshal([]byte(`
listen: 0.0.0.0:10443
password: secret
security: tls
tls:
  server_name: green.hhdaisy.com
  certificate_path: /etc/ssl/certimate/cert.crt
  key_path: /etc/ssl/certimate/cert.key
`), &config); err != nil {
		t.Fatal(err)
	}

	if config.TLS == nil || config.TLS.ServerName != "green.hhdaisy.com" {
		t.Fatalf("unexpected tls config: %#v", config.TLS)
	}
}

func TestTCPBrutalServerRateUsesDownMbps(t *testing.T) {
	config := ServerTCPBrutalConfig{Enabled: true, UpMbps: 500, DownMbps: 50, CwndGain: 15}
	brutal, err := config.ToServerTCPBrutal()
	if err != nil {
		t.Fatal(err)
	}
	if brutal.Rate != 6250000 {
		t.Fatalf("unexpected brutal rate: %d", brutal.Rate)
	}
	if brutal.CwndGain != 15 {
		t.Fatalf("unexpected cwnd gain: %d", brutal.CwndGain)
	}
}
