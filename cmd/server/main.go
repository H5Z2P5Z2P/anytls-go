package main

import (
	"anytls/proxy/padding"
	"anytls/proxy/reality"
	"anytls/proxy/tcpbrutal"
	"anytls/proxy/tcpfastopen"
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var passwordSha256 []byte

func main() {
	if len(os.Args) > 1 && os.Args[1] == "generate" {
		if err := runGenerateCommand(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	listen := flag.String("l", "0.0.0.0:8443", "server listen port")
	password := flag.String("p", "", "password")
	paddingScheme := flag.String("padding-scheme", "", "padding-scheme")
	configPath := flag.String("config", "", "yaml config file")
	security := flag.String("security", "tls", "server security: tls or reality")
	tlsCertPath := flag.String("tls-cert", "", "TLS certificate path")
	tlsKeyPath := flag.String("tls-key", "", "TLS key path")
	realityDest := flag.String("reality-dest", "", "Reality handshake destination host:port")
	realityServerNames := flag.String("reality-server-names", "", "comma-separated Reality server names")
	realityPrivateKey := flag.String("reality-private-key", "", "Reality private key")
	realityShortIDs := flag.String("reality-short-ids", "", "comma-separated Reality short IDs")
	realityFingerprint := flag.String("reality-fingerprint", "chrome", "Reality client fingerprint hint")
	tcpBrutalRate := flag.Uint64("tcp-brutal-rate", 0, "enable tcp brutal with send rate in bytes/s")
	tcpBrutalCwndGain := flag.Uint("tcp-brutal-cwnd-gain", uint(tcpbrutal.DefaultCwndGain), "tcp brutal cwnd gain")
	tcpFastOpen := flag.Bool("tcp-fast-open", true, "enable TCP Fast Open on the server listener")
	tcpFastOpenQueue := flag.Int("tcp-fast-open-queue", tcpfastopen.DefaultQueueLength, "TCP Fast Open pending SYN data queue length")
	flag.Parse()

	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	ctx := context.Background()
	runtimeConfig, err := buildServerRuntimeConfig(ctx, serverFlagConfig{
		listen:             *listen,
		password:           *password,
		paddingScheme:      *paddingScheme,
		configPath:         *configPath,
		security:           *security,
		tlsCertPath:        *tlsCertPath,
		tlsKeyPath:         *tlsKeyPath,
		realityDest:        *realityDest,
		realityServerNames: *realityServerNames,
		realityPrivateKey:  *realityPrivateKey,
		realityShortIDs:    *realityShortIDs,
		realityFingerprint: *realityFingerprint,
		tcpBrutalRate:      *tcpBrutalRate,
		tcpBrutalCwndGain:  uint32(*tcpBrutalCwndGain),
		tcpFastOpen:        *tcpFastOpen,
		tcpFastOpenQueue:   *tcpFastOpenQueue,
	})
	if err != nil {
		logrus.Fatalln(err)
	}
	if runtimeConfig.password == "" {
		logrus.Fatalln("please set password")
	}
	if runtimeConfig.paddingScheme != "" {
		loadPaddingScheme(runtimeConfig.paddingScheme)
	}

	var sum = sha256.Sum256([]byte(runtimeConfig.password))
	passwordSha256 = sum[:]

	logrus.Infoln("[Server]", util.ProgramVersionName)
	logrus.Infoln("[Server] Listening TCP", runtimeConfig.listen)

	listener, err := tcpfastopen.Listen(ctx, "tcp", runtimeConfig.listen, runtimeConfig.tcpFastOpen)
	if err != nil {
		logrus.Fatalln("listen server tcp:", err)
	}
	if runtimeConfig.tcpFastOpen != nil {
		logrus.Infoln("[Server] TCP Fast Open enabled, queue length", runtimeConfig.tcpFastOpen.QueueLength)
	}

	server := NewMyServer(runtimeConfig.tlsConfig, runtimeConfig.realityServer, runtimeConfig.tcpBrutal)

	for {
		c, err := listener.Accept()
		if err != nil {
			logrus.Fatalln("accept:", err)
		}
		go handleTcpConnection(ctx, c, server)
	}
}

type serverRuntimeConfig struct {
	listen        string
	password      string
	paddingScheme string
	tlsConfig     *tls.Config
	realityServer reality.Server
	tcpBrutal     *tcpbrutal.Config
	tcpFastOpen   *tcpfastopen.Config
}

type serverFlagConfig struct {
	listen             string
	password           string
	paddingScheme      string
	configPath         string
	security           string
	tlsCertPath        string
	tlsKeyPath         string
	realityDest        string
	realityServerNames string
	realityPrivateKey  string
	realityShortIDs    string
	realityFingerprint string
	tcpBrutalRate      uint64
	tcpBrutalCwndGain  uint32
	tcpFastOpen        bool
	tcpFastOpenQueue   int
}

func buildServerRuntimeConfig(ctx context.Context, flags serverFlagConfig) (*serverRuntimeConfig, error) {
	if flags.configPath != "" {
		return buildServerRuntimeConfigFromFile(ctx, flags.configPath)
	}

	tcpBrutal, err := tcpBrutalFromFlags(flags.tcpBrutalRate, flags.tcpBrutalCwndGain)
	if err != nil {
		return nil, err
	}
	config := &ServerFileConfig{
		Listen:   flags.listen,
		Password: flags.password,
		Security: flags.security,
		TCPFastOpen: ServerTCPFastOpenConfig{
			Enabled:     &flags.tcpFastOpen,
			QueueLength: flags.tcpFastOpenQueue,
		},
	}
	if flags.paddingScheme != "" {
		config.PaddingScheme = &flags.paddingScheme
	}
	if flags.tlsCertPath != "" || flags.tlsKeyPath != "" {
		config.TLS = &TLSFileConfig{
			CertificatePath: flags.tlsCertPath,
			KeyPath:         flags.tlsKeyPath,
		}
	}
	if strings.EqualFold(flags.security, "reality") {
		config.Reality = &RealityFileConfig{
			Dest:        flags.realityDest,
			ServerNames: splitCommaList(flags.realityServerNames),
			PrivateKey:  flags.realityPrivateKey,
			ShortIDs:    splitCommaList(flags.realityShortIDs),
			Fingerprint: flags.realityFingerprint,
		}
	}
	config.setDefaults()
	tcpFastOpen, err := config.TCPFastOpen.ToServerTCPFastOpen()
	if err != nil {
		return nil, err
	}
	return buildServerRuntimeConfigFromParsed(ctx, config, tcpBrutal, tcpFastOpen)
}

func buildServerRuntimeConfigFromFile(ctx context.Context, path string) (*serverRuntimeConfig, error) {
	config, err := LoadServerFileConfig(path)
	if err != nil {
		return nil, err
	}
	tcpBrutal, err := config.TCPBrutal.ToServerTCPBrutal()
	if err != nil {
		return nil, err
	}
	tcpFastOpen, err := config.TCPFastOpen.ToServerTCPFastOpen()
	if err != nil {
		return nil, err
	}
	return buildServerRuntimeConfigFromParsed(ctx, config, tcpBrutal, tcpFastOpen)
}

func buildServerRuntimeConfigFromParsed(ctx context.Context, config *ServerFileConfig, tcpBrutal *tcpbrutal.Config, tcpFastOpen *tcpfastopen.Config) (*serverRuntimeConfig, error) {
	runtimeConfig := &serverRuntimeConfig{
		listen:      config.Listen,
		password:    config.Password,
		tcpBrutal:   tcpBrutal,
		tcpFastOpen: tcpFastOpen,
	}
	if config.PaddingScheme != nil {
		runtimeConfig.paddingScheme = *config.PaddingScheme
	}

	if strings.EqualFold(config.Security, "reality") {
		realityServer, err := buildRealityServer(ctx, config.Reality)
		if err != nil {
			return nil, err
		}
		runtimeConfig.realityServer = realityServer
		return runtimeConfig, nil
	}

	tlsConfig, err := buildTLSServerConfig(config.TLS)
	if err != nil {
		return nil, err
	}
	runtimeConfig.tlsConfig = tlsConfig
	return runtimeConfig, nil
}

func buildTLSServerConfig(config *TLSFileConfig) (*tls.Config, error) {
	if config != nil && (config.CertificatePath != "" || config.KeyPath != "") {
		if config.CertificatePath == "" || config.KeyPath == "" {
			return nil, fmt.Errorf("tls certificate_path and key_path must be set together")
		}
		cert, err := tls.LoadX509KeyPair(config.CertificatePath, config.KeyPath)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			ServerName:   config.ServerName,
			Certificates: []tls.Certificate{cert},
		}, nil
	}

	tlsCert, _ := util.GenerateKeyPair(time.Now, "")
	return &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return tlsCert, nil
		},
	}, nil
}

func buildRealityServer(ctx context.Context, config *RealityFileConfig) (reality.Server, error) {
	if config == nil {
		return nil, fmt.Errorf("reality server config is required")
	}
	if config.Dest == "" || config.PrivateKey == "" || len(config.ServerNames) == 0 {
		return nil, fmt.Errorf("reality server config requires dest, server_names, and private_key")
	}
	return reality.NewServer(ctx, reality.ServerConfig{
		Dest:        config.Dest,
		ServerNames: config.ServerNames,
		PrivateKey:  config.PrivateKey,
		ShortIDs:    config.ShortIDs,
		Fingerprint: config.Fingerprint,
	})
}

func tcpBrutalFromFlags(rate uint64, cwndGain uint32) (*tcpbrutal.Config, error) {
	if rate == 0 {
		return nil, nil
	}
	return tcpbrutal.NewConfig(rate, cwndGain)
}

func loadPaddingScheme(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		logrus.Fatalln(err)
	}
	if padding.UpdatePaddingScheme(b) {
		logrus.Infoln("loaded padding scheme file:", path)
	} else {
		logrus.Fatalln("wrong format padding scheme file:", path)
	}
}

func splitCommaList(value string) []string {
	var values []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		values = append(values, part)
	}
	return values
}
