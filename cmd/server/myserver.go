package main

import (
	"anytls/proxy/reality"
	"anytls/proxy/tcpbrutal"
	"crypto/tls"
)

type myServer struct {
	tlsConfig     *tls.Config
	realityServer reality.Server
	tcpBrutal     *tcpbrutal.Config
}

func NewMyServer(tlsConfig *tls.Config, realityServer reality.Server, tcpBrutal *tcpbrutal.Config) *myServer {
	s := &myServer{
		tlsConfig:     tlsConfig,
		realityServer: realityServer,
		tcpBrutal:     tcpBrutal,
	}
	return s
}
