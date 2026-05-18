//go:build with_utls

package reality

import "testing"

func TestDecodeKeyAcceptsStandardBase64(t *testing.T) {
	key, err := decodeKey("QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=")
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
}

func TestDecodeShortIDsDefaultsToEmptyShortID(t *testing.T) {
	shortIDs, err := decodeShortIDs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !shortIDs[[8]byte{}] {
		t.Fatal("expected empty short ID to be accepted by default")
	}
}
