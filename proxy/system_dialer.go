package proxy

import (
	"bytes"
	"context"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var SystemDialer = &GaiDialer{
	Dialer: net.Dialer{
		Timeout: time.Second * 5,
	},
}

type GaiDialer struct {
	net.Dialer
}

func (d *GaiDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return d.Dialer.DialContext(ctx, network, address)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return d.Dialer.DialContext(ctx, network, address)
	}
	if net.ParseIP(host) != nil {
		return d.Dialer.DialContext(ctx, network, address)
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	socketAddrs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if network == "tcp4" && addr.IP.To4() == nil {
			continue
		}
		if network == "tcp6" && (addr.IP.To4() != nil || addr.IP.To16() == nil) {
			continue
		}
		socketAddrs = append(socketAddrs, net.JoinHostPort(addr.IP.String(), port))
	}
	if len(socketAddrs) == 0 {
		return nil, &net.DNSError{Err: "no suitable address", Name: host}
	}
	sortSocketAddrsByGai(socketAddrs)

	var lastErr error
	for _, addr := range socketAddrs {
		conn, err := d.Dialer.DialContext(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

var (
	gaiOnce         sync.Once
	loadedGaiConfig gaiConfig
)

type gaiConfig struct {
	precedence []gaiPrecedence
}

type gaiPrecedence struct {
	prefix ipPrefix
	value  int
}

type ipPrefix struct {
	ip     net.IP
	length int
}

func sortSocketAddrsByGai(addrs []string) {
	gaiOnce.Do(func() {
		loadedGaiConfig = loadGaiConfig("/etc/gai.conf")
	})
	loadedGaiConfig.sortSocketAddrs(addrs)
}

func loadGaiConfig(path string) gaiConfig {
	content, err := os.ReadFile(path)
	if err != nil {
		return gaiConfig{}
	}
	return parseGaiConfig(string(content))
}

func parseGaiConfig(content string) gaiConfig {
	var config gaiConfig
	for _, line := range strings.Split(content, "\n") {
		if before, _, ok := strings.Cut(line, "#"); ok {
			line = before
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "precedence" {
			continue
		}
		prefix, ok := parseIPPrefix(fields[1])
		if !ok {
			continue
		}
		value, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		config.precedence = append(config.precedence, gaiPrecedence{prefix: prefix, value: value})
	}
	return config
}

func (c gaiConfig) sortSocketAddrs(addrs []string) {
	if len(c.precedence) == 0 {
		return
	}
	sort.SliceStable(addrs, func(i, j int) bool {
		return c.precedenceValue(socketAddrIP(addrs[i])) > c.precedenceValue(socketAddrIP(addrs[j]))
	})
}

func (c gaiConfig) precedenceValue(ip net.IP) int {
	bestLength := -1
	bestValue := 0
	for _, entry := range c.precedence {
		if entry.prefix.matches(ip) && entry.prefix.length > bestLength {
			bestLength = entry.prefix.length
			bestValue = entry.value
		}
	}
	return bestValue
}

func parseIPPrefix(value string) (ipPrefix, bool) {
	addr, rawLength, hasLength := strings.Cut(value, "/")
	if !hasLength {
		rawLength = "128"
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return ipPrefix{}, false
	}
	length, err := strconv.Atoi(rawLength)
	if err != nil || length < 0 {
		return ipPrefix{}, false
	}
	if !strings.Contains(addr, ":") {
		ip4 := ip.To4()
		if ip4 == nil {
			return ipPrefix{}, false
		}
		if length > 32 {
			return ipPrefix{}, false
		}
		return ipPrefix{ip: ipv4Mapped(ip4), length: 96 + length}, true
	}
	if length > 128 {
		return ipPrefix{}, false
	}
	return ipPrefix{ip: ip.To16(), length: length}, true
}

func (p ipPrefix) matches(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ipv4Mapped(ip4)
	} else {
		ip = ip.To16()
	}
	if ip == nil {
		return false
	}
	if p.length == 0 {
		return true
	}
	fullBytes := p.length / 8
	remainingBits := p.length % 8
	if fullBytes > 0 && !bytes.Equal(p.ip[:fullBytes], ip[:fullBytes]) {
		return false
	}
	if remainingBits == 0 {
		return true
	}
	mask := byte(0xff << (8 - remainingBits))
	return p.ip[fullBytes]&mask == ip[fullBytes]&mask
}

func socketAddrIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func ipv4Mapped(ip4 net.IP) net.IP {
	mapped := make(net.IP, net.IPv6len)
	mapped[10] = 0xff
	mapped[11] = 0xff
	copy(mapped[12:], ip4.To4())
	return mapped
}
