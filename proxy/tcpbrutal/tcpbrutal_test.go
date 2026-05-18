package tcpbrutal

import "testing"

func TestConfigRejectsZeroRate(t *testing.T) {
	if _, err := NewConfig(0, DefaultCwndGain); err == nil {
		t.Fatal("expected zero rate to be rejected")
	}
}

func TestConfigRejectsZeroCwndGain(t *testing.T) {
	if _, err := NewConfig(1, 0); err == nil {
		t.Fatal("expected zero cwnd gain to be rejected")
	}
}

func TestMbpsConversionMatchesDecimalNetworkUnits(t *testing.T) {
	rate, err := MbpsToBytesPerSecond(1)
	if err != nil {
		t.Fatal(err)
	}
	if rate != 125000 {
		t.Fatalf("expected 125000 bytes/s, got %d", rate)
	}
}
