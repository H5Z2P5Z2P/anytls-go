package main

import (
	"strings"
	"testing"
)

func TestPublicKeyFromPrivateKeyMatchesKnownValue(t *testing.T) {
	privateKey := "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
	publicKey, err := publicKeyFromPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if publicKey != "ehpOcJvwhaxJSroEabmx7aCrH3ixaqu3n_7akGI-hSI" {
		t.Fatalf("unexpected public key: %s", publicKey)
	}
}

func TestRealityServerConfigRequiresBothBrutalDirections(t *testing.T) {
	_, err := buildRealityServerConfig(realityServerConfigOptions{
		Listen:      "0.0.0.0:443",
		Server:      "203.0.113.1",
		Port:        443,
		SNI:         "pypi.org",
		Fingerprint: "chrome",
		UpMbps:      100,
		CwndGain:    15,
		UpSet:       true,
	})
	if err == nil || !strings.Contains(err.Error(), "both --up-mbps and --down-mbps") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildRealityServerConfigIncludesYAMLAndURI(t *testing.T) {
	output, err := buildRealityServerConfig(realityServerConfigOptions{
		Listen:      "0.0.0.0:443",
		Server:      "203.0.113.1",
		Port:        443,
		SNI:         "pypi.org",
		Fingerprint: "firefox",
		Password:    "secret",
		PrivateKey:  "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
		ShortID:     "0123456789abcdef",
		UpMbps:      300,
		DownMbps:    200,
		CwndGain:    15,
		TagLabel:    "SJC Test",
		UpSet:       true,
		DownSet:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	checks := []string{
		"# anytls uri",
		"anytls://secret@203.0.113.1:443?security=reality&type=tcp&sni=pypi.org&fp=firefox&pbk=ehpOcJvwhaxJSroEabmx7aCrH3ixaqu3n_7akGI-hSI&network=tcp&sid=0123456789abcdef#sjc-test-go-anyreality",
		"security: reality",
		"private_key: QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
		"public_key: ehpOcJvwhaxJSroEabmx7aCrH3ixaqu3n_7akGI-hSI",
		"down_mbps: 200",
		"./anytls-server --config anyreality.yaml",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("output missing %q:\n%s", check, output)
		}
	}
}
