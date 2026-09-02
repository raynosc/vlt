package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestZeroizePrivateKey_Nil(t *testing.T) {
	// Must not panic.
	ZeroizePrivateKey(nil)
}

func TestZeroizePrivateKey_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	ZeroizePrivateKey(key)

	if key.D.Sign() != 0 {
		t.Error("RSA key.D was not zeroed")
	}
	if key.Precomputed.Dp != nil && key.Precomputed.Dp.Sign() != 0 {
		t.Error("RSA key.Precomputed.Dp was not zeroed")
	}
	if key.Precomputed.Dq != nil && key.Precomputed.Dq.Sign() != 0 {
		t.Error("RSA key.Precomputed.Dq was not zeroed")
	}
	if key.Precomputed.Qinv != nil && key.Precomputed.Qinv.Sign() != 0 {
		t.Error("RSA key.Precomputed.Qinv was not zeroed")
	}

	// Primes (P and Q) must also be zeroed — the whole key is trivially
	// reconstructable from them.
	for i, p := range key.Primes {
		if p != nil && p.Sign() != 0 {
			t.Errorf("RSA key.Primes[%d] was not zeroed", i)
		}
	}

	// CRTValues (used for multi-prime RSA) — Exp and Coeff must be cleared.
	//nolint:staticcheck // intentional: testing zeroization of deprecated CRTValues field
	for i, crt := range key.Precomputed.CRTValues {
		if crt.Exp != nil && crt.Exp.Sign() != 0 {
			t.Errorf("RSA key.Precomputed.CRTValues[%d].Exp was not zeroed", i)
		}
		if crt.Coeff != nil && crt.Coeff.Sign() != 0 {
			t.Errorf("RSA key.Precomputed.CRTValues[%d].Coeff was not zeroed", i)
		}
	}
}

func TestZeroizePrivateKey_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	ZeroizePrivateKey(key)

	if key.D.Sign() != 0 { //nolint:staticcheck // intentional: testing zeroization of deprecated field
		t.Error("ECDSA key.D was not zeroed")
	}
}

func TestZeroizePrivateKey_Ed25519(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	ZeroizePrivateKey(privKey)

	for i, b := range privKey {
		if b != 0 {
			t.Errorf("Ed25519 key byte[%d] = 0x%02x, want 0x00", i, b)
			break
		}
	}
}

func TestZeroizePrivateKey_UnknownType(t *testing.T) {
	// A string is not a recognized private key type — must be silently ignored.
	ZeroizePrivateKey("not-a-key")
}
