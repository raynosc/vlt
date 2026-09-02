package crypto

import (
	"bytes"
	"testing"
)

func TestComputeNameLookup(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)

	// Same name + same key = same HMAC
	a := ComputeNameLookup(key, "github")
	b := ComputeNameLookup(key, "github")
	if !bytes.Equal(a, b) {
		t.Error("ComputeNameLookup is not deterministic")
	}

	// Different name = different HMAC
	c := ComputeNameLookup(key, "gitlab")
	if bytes.Equal(a, c) {
		t.Error("different names produced identical HMAC")
	}

	// Different key = different HMAC
	key2 := bytes.Repeat([]byte{0xCD}, 32)
	d := ComputeNameLookup(key2, "github")
	if bytes.Equal(a, d) {
		t.Error("different keys produced identical HMAC")
	}

	// Length is always 32 bytes (SHA-256)
	if len(a) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(a))
	}
}
