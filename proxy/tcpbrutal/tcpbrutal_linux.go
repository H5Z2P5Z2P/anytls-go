//go:build linux

package tcpbrutal

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

const tcpBrutalParams = 23301

func apply(conn net.Conn, config Config) error {
	rawConn, ok := conn.(syscall.Conn)
	if !ok {
		return errors.New("tcp brutal requires a syscall-capable TCP connection")
	}
	syscallConn, err := rawConn.SyscallConn()
	if err != nil {
		return err
	}
	var sockoptErr error
	err = syscallConn.Control(func(fd uintptr) {
		if err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal"); err != nil {
			sockoptErr = err
			return
		}

		var params [12]byte
		binary.NativeEndian.PutUint64(params[:8], config.Rate)
		binary.NativeEndian.PutUint32(params[8:], config.CwndGain)
		sockoptErr = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, tcpBrutalParams, string(params[:]))
	})
	if err != nil {
		return err
	}
	return sockoptErr
}

func brutalParamsBytes(config Config) [12]byte {
	var params [12]byte
	binary.NativeEndian.PutUint64(params[:8], config.Rate)
	binary.NativeEndian.PutUint32(params[8:], config.CwndGain)
	return params
}
