package proxy

import "testing"

func TestGaiPrecedencePrefersIPv4MappedAddresses(t *testing.T) {
	config := parseGaiConfig("precedence ::/0 40\nprecedence ::ffff:0:0/96 100\n")
	addrs := []string{"[2606:4700:7::da]:443", "162.159.140.220:443"}

	config.sortSocketAddrs(addrs)

	if addrs[0] != "162.159.140.220:443" {
		t.Fatalf("expected IPv4 address first, got %v", addrs)
	}
}

func TestGaiPrecedenceUsesLongestMatchingPrefix(t *testing.T) {
	config := parseGaiConfig("precedence ::/0 100\nprecedence ::ffff:0:0/96 10\n")
	addrs := []string{"162.159.140.220:443", "[2606:4700:7::da]:443"}

	config.sortSocketAddrs(addrs)

	if addrs[0] != "[2606:4700:7::da]:443" {
		t.Fatalf("expected IPv6 address first, got %v", addrs)
	}
}

func TestEmptyGaiConfigPreservesResolverOrder(t *testing.T) {
	config := parseGaiConfig("# no active rules\n")
	addrs := []string{"[2606:4700:7::da]:443", "162.159.140.220:443"}

	config.sortSocketAddrs(addrs)

	if addrs[0] != "[2606:4700:7::da]:443" || addrs[1] != "162.159.140.220:443" {
		t.Fatalf("expected original order, got %v", addrs)
	}
}
