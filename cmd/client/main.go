package main

import (
	"anytls/proxy"
	"anytls/proxy/reality"
	"anytls/proxy/tcpbrutal"
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

var passwordSha256 []byte

func main() {
	listen := flag.String("l", "127.0.0.1:1080", "socks5 listen port")
	serverAddr := flag.String("s", "", "Server address or anytls:// link")
	sni := flag.String("sni", "", "Server Name Indication")
	password := flag.String("p", "", "Password")
	minIdleSession := flag.Int("m", 5, "Reserved min idle session")
	security := flag.String("security", "tls", "server security: tls or reality")
	realityPublicKey := flag.String("pbk", "", "Reality public key")
	realityShortID := flag.String("sid", "", "Reality short ID")
	realityFingerprint := flag.String("fp", "chrome", "Reality client fingerprint")
	tcpBrutalRate := flag.Uint64("tcp-brutal-rate", 0, "enable tcp brutal with send rate in bytes/s")
	tcpBrutalCwndGain := flag.Uint("tcp-brutal-cwnd-gain", uint(tcpbrutal.DefaultCwndGain), "tcp brutal cwnd gain")
	flag.Parse()

	if serverURL, err := url.Parse(*serverAddr); err == nil {
		if serverURL.Scheme == "anytls" {
			*serverAddr = serverURL.Host
			if serverURL.User != nil {
				*password = serverURL.User.String()
			}
			query := serverURL.Query()
			*sni = query.Get("sni")
			if value := query.Get("security"); value != "" {
				*security = value
			}
			if value := query.Get("pbk"); value != "" {
				*realityPublicKey = value
			}
			if value := query.Get("sid"); value != "" {
				*realityShortID = value
			}
			if value := query.Get("fp"); value != "" {
				*realityFingerprint = value
			}
		}
	}

	if *serverAddr == "" {
		logrus.Fatalln("please set -s server adreess")
	}

	if *password == "" {
		logrus.Fatalln("please set -p password")
	}

	if _, _, err := net.SplitHostPort(*serverAddr); err != nil {
		logrus.Fatalln("error server address:", *serverAddr, err)
	}

	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	var sum = sha256.Sum256([]byte(*password))
	passwordSha256 = sum[:]

	logrus.Infoln("[Client]", util.ProgramVersionName)
	logrus.Infoln("[Client] socks5/http", *listen, "=>", *serverAddr)

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logrus.Fatalln("listen socks5 tcp:", err)
	}

	// You can only use `InsecureSkipVerify` by default in the sample client; it is not recommended for use in production code.
	tlsConfig := &tls.Config{
		ServerName:         *sni,
		InsecureSkipVerify: true,
	}
	if tlsConfig.ServerName == "" {
		// disable the SNI
		tlsConfig.ServerName = "127.0.0.1"
	}

	path := strings.TrimSpace(os.Getenv("TLS_KEY_LOG"))
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if err == nil {
			tlsConfig.KeyLogWriter = f
		}
	}

	ctx := context.Background()
	tcpBrutal, err := tcpBrutalConfig(*tcpBrutalRate, uint32(*tcpBrutalCwndGain))
	if err != nil {
		logrus.Fatalln(err)
	}
	var realityClient reality.Client
	if strings.EqualFold(*security, "reality") {
		if *sni == "" {
			logrus.Fatalln("reality requires -sni or sni= in anytls URI")
		}
		if *realityPublicKey == "" {
			logrus.Fatalln("reality requires -pbk or pbk= in anytls URI")
		}
		realityClient, err = reality.NewClient(ctx, reality.ClientConfig{
			ServerAddress: *serverAddr,
			ServerName:    *sni,
			PublicKey:     *realityPublicKey,
			ShortID:       *realityShortID,
			Fingerprint:   *realityFingerprint,
		})
		if err != nil {
			logrus.Fatalln(err)
		}
	}
	client := NewMyClient(ctx, func(ctx context.Context) (net.Conn, error) {
		conn, err := proxy.SystemDialer.DialContext(ctx, "tcp", *serverAddr)
		if err != nil {
			return nil, err
		}
		if err := tcpbrutal.Apply(conn, tcpBrutal); err != nil {
			conn.Close()
			return nil, err
		}
		if realityClient != nil {
			realityConn, err := realityClient.ClientHandshake(conn)
			if err != nil {
				conn.Close()
				return nil, err
			}
			return realityConn, nil
		}
		conn = tls.Client(conn, tlsConfig)
		return conn, nil
	}, *minIdleSession)

	for {
		c, err := listener.Accept()
		if err != nil {
			logrus.Fatalln("accept:", err)
		}
		go handleTcpConnection(ctx, c, client)
	}
}

func tcpBrutalConfig(rate uint64, cwndGain uint32) (*tcpbrutal.Config, error) {
	if rate == 0 {
		return nil, nil
	}
	return tcpbrutal.NewConfig(rate, cwndGain)
}
