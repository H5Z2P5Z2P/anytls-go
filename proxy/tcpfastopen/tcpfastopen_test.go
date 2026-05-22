package tcpfastopen

import "testing"

func TestNewConfigUsesDefaultQueueLength(t *testing.T) {
	config, err := NewConfig(0)
	if err != nil {
		t.Fatal(err)
	}
	if config.QueueLength != DefaultQueueLength {
		t.Fatalf("unexpected queue length: %d", config.QueueLength)
	}
}

func TestNewConfigRejectsNegativeQueueLength(t *testing.T) {
	if _, err := NewConfig(-1); err == nil {
		t.Fatal("expected negative queue length to be rejected")
	}
}
