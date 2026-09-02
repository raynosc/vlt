package crypto

import (
	"bytes"
	"testing"
)

func TestPackUnpackEnvelope_RoundTrip(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xAB}, NonceSize)
	ciphertext := []byte("some-ciphertext-bytes")

	blob := PackEnvelope(nonce, ciphertext)
	if len(blob) != NonceSize+len(ciphertext) {
		t.Fatalf("blob length: got %d, want %d", len(blob), NonceSize+len(ciphertext))
	}

	gotNonce, gotCT, err := UnpackEnvelope(blob)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if !bytes.Equal(gotNonce, nonce) {
		t.Errorf("nonce: got %x, want %x", gotNonce, nonce)
	}
	if !bytes.Equal(gotCT, ciphertext) {
		t.Errorf("ciphertext: got %q, want %q", gotCT, ciphertext)
	}
}

func TestUnpackEnvelope_TooShort(t *testing.T) {
	if _, _, err := UnpackEnvelope(make([]byte, NonceSize-1)); err == nil {
		t.Fatal("expected error for blob shorter than a nonce")
	}
}

// TestEncryptPackRoundTrip ties the envelope helpers to the real Engine so the
// NonceSize constant can never silently drift from the GCM nonce length.
func TestEncryptPackRoundTrip(t *testing.T) {
	eng := NewEngine(nil)
	key := bytes.Repeat([]byte{0x01}, 32)
	plaintext := []byte("top-secret")

	ct, nonce, err := eng.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(nonce) != NonceSize {
		t.Fatalf("NonceSize=%d but Engine produced a %d-byte nonce", NonceSize, len(nonce))
	}

	blob := PackEnvelope(nonce, ct)
	gotNonce, gotCT, err := UnpackEnvelope(blob)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	got, err := eng.Decrypt(gotCT, key, gotNonce)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip: got %q, want %q", got, plaintext)
	}
}
