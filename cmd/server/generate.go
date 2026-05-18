package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"
)

const (
	defaultRealityListen      = "0.0.0.0:443"
	defaultRealityFingerprint = "chrome"
	defaultTCPBrutalCwndGain  = uint(15)
)

type realityServerConfigOptions struct {
	Listen      string
	Server      string
	Port        uint
	SNI         string
	Dest        string
	Fingerprint string
	Password    string
	PrivateKey  string
	ShortID     string
	UpMbps      uint64
	DownMbps    uint64
	CwndGain    uint32
	TagLabel    string
	UpSet       bool
	DownSet     bool
}

func runGenerateCommand(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}

	switch args[0] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	case "reality-keypair":
		return runRealityKeypair(stdout)
	case "rand":
		return runRand(args[1:], stdout)
	case "reality-server-config":
		return runRealityServerConfig(args[1:], stdout)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: anytls-server generate <command> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  reality-keypair          generate a Reality X25519 keypair")
	fmt.Fprintln(w, "  rand --hex N             generate N random bytes as hex")
	fmt.Fprintln(w, "  rand --base64 N          generate N random bytes as base64")
	fmt.Fprintln(w, "  reality-server-config    generate Reality YAML, URI, and client JSON")
}

func runRealityKeypair(stdout io.Writer) error {
	privateKey, publicKey, err := generateRealityKeypair()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "PrivateKey: %s\n", privateKey)
	fmt.Fprintf(stdout, "PublicKey: %s\n", publicKey)
	return nil
}

func runRand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("rand", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	hexBytes := fs.Uint("hex", 0, "random byte length to encode as hex")
	base64Bytes := fs.Uint("base64", 0, "random byte length to encode as base64")
	if err := fs.Parse(args); err != nil {
		return err
	}
	hexSet := flagWasSet(fs, "hex")
	base64Set := flagWasSet(fs, "base64")
	switch {
	case hexSet && base64Set:
		return errors.New("rand accepts either --hex or --base64")
	case !hexSet && !base64Set:
		return errors.New("rand requires --hex <bytes> or --base64 <bytes>")
	case hexSet:
		if *hexBytes == 0 {
			return errors.New("random hex byte length must be greater than 0")
		}
		value, err := randomHex(int(*hexBytes))
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, value)
	case base64Set:
		if *base64Bytes == 0 {
			return errors.New("random base64 byte length must be greater than 0")
		}
		value, err := randomBase64(int(*base64Bytes))
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, value)
	}
	return nil
}

func runRealityServerConfig(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("reality-server-config", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	options := realityServerConfigOptions{}
	fs.StringVar(&options.Listen, "listen", defaultRealityListen, "server listen address")
	fs.StringVar(&options.Server, "server", "", "public server host or IP for client URI")
	fs.UintVar(&options.Port, "port", 0, "public server port for client URI")
	fs.StringVar(&options.SNI, "sni", "", "Reality server name")
	fs.StringVar(&options.Dest, "dest", "", "Reality handshake destination host:port")
	fs.StringVar(&options.Fingerprint, "fingerprint", defaultRealityFingerprint, "Reality/uTLS fingerprint")
	fs.StringVar(&options.Password, "password", "", "password; generated when omitted")
	fs.StringVar(&options.PrivateKey, "private-key", "", "Reality private key; generated when omitted")
	fs.StringVar(&options.ShortID, "short-id", "", "Reality short ID hex; empty by default")
	fs.Uint64Var(&options.UpMbps, "up-mbps", 0, "TCP Brutal client upload Mbps")
	fs.Uint64Var(&options.DownMbps, "down-mbps", 0, "TCP Brutal server send Mbps")
	cwndGain := fs.Uint("cwnd-gain", defaultTCPBrutalCwndGain, "TCP Brutal cwnd gain")
	fs.StringVar(&options.TagLabel, "tag-label", "", "URI tag label; hostname -s is used when omitted")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cwndGain > uint(^uint32(0)) {
		return errors.New("tcp brutal cwnd gain overflows uint32")
	}
	options.CwndGain = uint32(*cwndGain)
	options.UpSet = flagWasSet(fs, "up-mbps")
	options.DownSet = flagWasSet(fs, "down-mbps")

	result, err := buildRealityServerConfig(options)
	if err != nil {
		return err
	}
	_, err = stdout.Write([]byte(result))
	return err
}

func buildRealityServerConfig(options realityServerConfigOptions) (string, error) {
	if strings.TrimSpace(options.Server) == "" {
		return "", errors.New("reality-server-config requires --server")
	}
	if options.Port == 0 || options.Port > 65535 {
		return "", errors.New("reality-server-config requires --port 1..65535")
	}
	if strings.TrimSpace(options.SNI) == "" {
		return "", errors.New("reality-server-config requires --sni")
	}
	if options.UpSet != options.DownSet {
		return "", errors.New("reality-server-config requires both --up-mbps and --down-mbps when enabling tcp brutal")
	}
	if options.UpSet && (options.UpMbps == 0 || options.DownMbps == 0) {
		return "", errors.New("tcp brutal Mbps values must be greater than 0")
	}
	if options.CwndGain == 0 {
		return "", errors.New("tcp brutal cwnd gain must be greater than 0")
	}
	if err := validateShortID(options.ShortID); err != nil {
		return "", err
	}

	password := options.Password
	if password == "" {
		var err error
		password, err = randomURLSafeBase64(32)
		if err != nil {
			return "", err
		}
	}

	privateKey := options.PrivateKey
	publicKey := ""
	var err error
	if privateKey == "" {
		privateKey, publicKey, err = generateRealityKeypair()
	} else {
		publicKey, err = publicKeyFromPrivateKey(privateKey)
	}
	if err != nil {
		return "", err
	}

	dest := options.Dest
	if dest == "" {
		dest = net.JoinHostPort(options.SNI, "443")
	}

	tcpBrutal := ServerTCPBrutalConfig{CwndGain: options.CwndGain}
	if options.UpSet {
		tcpBrutal = ServerTCPBrutalConfig{
			Enabled:  true,
			UpMbps:   options.UpMbps,
			DownMbps: options.DownMbps,
			CwndGain: options.CwndGain,
		}
	}

	serverConfig := ServerFileConfig{
		Listen:        options.Listen,
		Password:      password,
		PaddingScheme: nil,
		Security:      "reality",
		Reality: &RealityFileConfig{
			Dest:        dest,
			ServerNames: []string{options.SNI},
			PrivateKey:  privateKey,
			PublicKey:   publicKey,
			ShortIDs:    []string{options.ShortID},
			Fingerprint: options.Fingerprint,
		},
		TCPBrutal: tcpBrutal,
	}

	serverYAML, err := marshalYAML(serverConfig)
	if err != nil {
		return "", err
	}

	tag := buildShareTag(options.TagLabel, options.Server, "anyreality")
	uri := buildAnyTLSURI(password, options.Server, uint16(options.Port), "reality", options.SNI, options.Fingerprint, publicKey, options.ShortID, tag)
	clientJSON, err := buildClientJSON(options.Server, uint16(options.Port), options.SNI, options.Fingerprint, password, publicKey, options.ShortID, tcpBrutal)
	if err != nil {
		return "", err
	}

	var builder strings.Builder
	fmt.Fprintln(&builder, "# Generated values")
	fmt.Fprintf(&builder, "server: %s\n", options.Server)
	fmt.Fprintf(&builder, "port: %d\n", options.Port)
	fmt.Fprintf(&builder, "password: %s\n", password)
	fmt.Fprintf(&builder, "private_key: %s\n", privateKey)
	fmt.Fprintf(&builder, "public_key: %s\n", publicKey)
	fmt.Fprintf(&builder, "short_id: %s\n", options.ShortID)
	if tcpBrutal.Enabled {
		fmt.Fprintf(&builder, "tcp_brutal_up_mbps: %d\n", tcpBrutal.UpMbps)
		fmt.Fprintf(&builder, "tcp_brutal_down_mbps: %d\n", tcpBrutal.DownMbps)
	}
	fmt.Fprintln(&builder)
	fmt.Fprintln(&builder, "# anytls uri")
	fmt.Fprintln(&builder, uri)
	fmt.Fprintln(&builder)
	fmt.Fprintln(&builder, "# anytls server yaml")
	builder.Write(serverYAML)
	fmt.Fprintln(&builder)
	fmt.Fprintln(&builder, "# anyreality client json")
	builder.Write(clientJSON)
	fmt.Fprintln(&builder)
	fmt.Fprintln(&builder)
	fmt.Fprintln(&builder, "# Linux manual deployment helpers")
	fmt.Fprintf(&builder, "cat > anyreality.yaml <<'EOF'\n%sEOF\n", serverYAML)
	fmt.Fprintln(&builder, "./anytls-server --config anyreality.yaml")
	if tcpBrutal.Enabled {
		fmt.Fprintf(&builder, "# tcp-brutal server send rate: %d bytes/s\n", tcpBrutal.DownMbps*125000)
	}
	return builder.String(), nil
}

func marshalYAML(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(value); err != nil {
		_ = encoder.Close()
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func buildClientJSON(server string, port uint16, sni, fingerprint, password, publicKey, shortID string, tcpBrutal ServerTCPBrutalConfig) ([]byte, error) {
	outbound := map[string]any{
		"type":               "anyreality",
		"tag":                "anyreality",
		"server":             server,
		"port":               port,
		"sni":                sni,
		"client-fingerprint": fingerprint,
		"skip-cert-verify":   false,
		"reality-opts":       map[string]any{"public-key": publicKey},
		"network":            "tcp",
		"password":           password,
		"security":           "reality",
		"fp":                 fingerprint,
		"pbk":                publicKey,
		"sid":                shortID,
	}
	if tcpBrutal.Enabled {
		outbound["multiplex"] = map[string]any{
			"enabled": true,
			"brutal": map[string]any{
				"enabled":   true,
				"up_mbps":   tcpBrutal.UpMbps,
				"down_mbps": tcpBrutal.DownMbps,
			},
		}
	}
	return json.MarshalIndent(outbound, "", "  ")
}

func buildAnyTLSURI(password, server string, port uint16, security, sni, fingerprint, publicKey, shortID, tag string) string {
	query := []string{
		"security=" + url.QueryEscape(security),
		"type=tcp",
		"sni=" + url.QueryEscape(sni),
		"fp=" + url.QueryEscape(fingerprint),
	}
	if security == "reality" {
		query = append(query, "pbk="+url.QueryEscape(publicKey))
		query = append(query, "network=tcp")
		query = append(query, "sid="+url.QueryEscape(shortID))
	}
	return fmt.Sprintf("anytls://%s@%s?%s#%s", url.User(password), net.JoinHostPort(server, strconv.Itoa(int(port))), strings.Join(query, "&"), tag)
}

func buildShareTag(label, server, suffix string) string {
	if strings.TrimSpace(label) == "" {
		if hostname, err := os.Hostname(); err == nil {
			label = strings.Split(hostname, ".")[0]
		}
	}
	if strings.TrimSpace(label) == "" {
		label = server
	}
	parts := []string{normalizeTagSegment(label), "go", suffix}
	out := parts[:0]
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, "-")
}

func normalizeTagSegment(value string) string {
	var builder strings.Builder
	for _, ch := range strings.TrimSpace(value) {
		switch {
		case ch >= 'a' && ch <= 'z':
			builder.WriteRune(ch)
		case ch >= 'A' && ch <= 'Z':
			builder.WriteRune(ch + ('a' - 'A'))
		case ch >= '0' && ch <= '9':
			builder.WriteRune(ch)
		default:
			builder.WriteByte('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}

func generateRealityKeypair() (string, string, error) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return "", "", err
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(privateKey), base64.RawURLEncoding.EncodeToString(publicKey), nil
}

func publicKeyFromPrivateKey(privateKey string) (string, error) {
	decoded, err := decodeRealityKey(privateKey)
	if err != nil {
		return "", err
	}
	publicKey, err := curve25519.X25519(decoded, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(publicKey), nil
}

func decodeRealityKey(key string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(key)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to decode Reality key: %w", err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("Reality key must be 32 bytes, got %d", len(decoded))
	}
	return decoded, nil
}

func validateShortID(value string) error {
	if value == "" {
		return nil
	}
	if len(value)%2 != 0 {
		return errors.New("short ID hex length must be even")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("invalid short ID hex: %w", err)
	}
	if len(decoded) > 8 {
		return errors.New("short ID must be at most 8 bytes")
	}
	return nil
}

func randomHex(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func randomBase64(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buffer), nil
}

func randomURLSafeBase64(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
