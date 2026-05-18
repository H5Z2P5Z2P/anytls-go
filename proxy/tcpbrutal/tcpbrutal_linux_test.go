//go:build linux

package tcpbrutal

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBrutalParamsMatchExpectedLayout(t *testing.T) {
	config := Config{Rate: 0x0102030405060708, CwndGain: 0x11121314}
	params := brutalParamsBytes(config)

	var expectedRate [8]byte
	binary.NativeEndian.PutUint64(expectedRate[:], config.Rate)
	if !bytes.Equal(params[:8], expectedRate[:]) {
		t.Fatalf("unexpected rate bytes: %x", params[:8])
	}

	var expectedGain [4]byte
	binary.NativeEndian.PutUint32(expectedGain[:], config.CwndGain)
	if !bytes.Equal(params[8:], expectedGain[:]) {
		t.Fatalf("unexpected cwnd gain bytes: %x", params[8:])
	}
}
