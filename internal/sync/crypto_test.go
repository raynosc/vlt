package sync

import (
	"crypto/rand"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	plaintext := []byte("this is the secret data to encrypt and decrypt")
	aad := []byte("associated-data-binding-context")

	ciphertext, err := EncryptBlob(plaintext, key, aad)
	if err != nil {
		t.Fatalf("EncryptBlob failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}

	// Ciphertext should be longer than plaintext (includes nonce + tag)
	minExpected := len(plaintext) + 12 + 16 // nonce + GCM tag
	if len(ciphertext) < minExpected {
		t.Errorf("ciphertext too short: got %d, want at least %d", len(ciphertext), minExpected)
	}

	decrypted, err := DecryptBlob(ciphertext, key, aad)
	if err != nil {
		t.Fatalf("DecryptBlob failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted text mismatch:\ngot:  %q\nwant: %q", string(decrypted), string(plaintext))
	}
}

func TestDecrypt_WrongKey_Fails(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	plaintext := []byte("sensitive-data-to-protect")
	aad := []byte("test-context")

	ciphertext, err := EncryptBlob(plaintext, key, aad)
	if err != nil {
		t.Fatalf("EncryptBlob failed: %v", err)
	}

	_, err = DecryptBlob(ciphertext, wrongKey, aad)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key, got nil")
	}
}

func TestDecrypt_TamperedCiphertext_Fails(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	plaintext := []byte("data-to-protect-from-tampering")
	aad := []byte("test-context")

	ciphertext, err := EncryptBlob(plaintext, key, aad)
	if err != nil {
		t.Fatalf("EncryptBlob failed: %v", err)
	}

	// Tamper with the ciphertext portion (after the 12-byte nonce)
	if len(ciphertext) > 12+1 {
		ciphertext[12] ^= 0xff // flip all bits in first byte of actual ciphertext
	}

	_, err = DecryptBlob(ciphertext, key, aad)
	if err == nil {
		t.Fatal("expected error when decrypting tampered ciphertext, got nil")
	}
}

func TestDecrypt_WrongAAD_Fails(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	plaintext := []byte("secret-vault-data")
	aad1 := []byte("vault-A|seq-1")
	aad2 := []byte("vault-B|seq-1") // different vault
	aad3 := []byte("vault-A|seq-2") // different sequence

	ciphertext, err := EncryptBlob(plaintext, key, aad1)
	if err != nil {
		t.Fatalf("EncryptBlob failed: %v", err)
	}

	// Decrypt with correct AAD succeeds
	decrypted, err := DecryptBlob(ciphertext, key, aad1)
	if err != nil {
		t.Fatalf("DecryptBlob with correct AAD failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted text mismatch")
	}

	// Decrypt with wrong vault UUID in AAD fails
	_, err = DecryptBlob(ciphertext, key, aad2)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong vault UUID in AAD, but it succeeded")
	}

	// Decrypt with wrong sequence number in AAD fails
	_, err = DecryptBlob(ciphertext, key, aad3)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong sequence in AAD, but it succeeded")
	}
}

func TestDecrypt_TooShortBlob_Fails(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Blob must be at least 12 (nonce) + 16 (GCM tag) = 28 bytes
	tooShort := []byte("short")
	_, err := DecryptBlob(tooShort, key, nil)
	if err == nil {
		t.Fatal("expected error for too-short blob, got nil")
	}
}

func TestEncryptBlob_KeySizeValidation(t *testing.T) {
	// Key must be exactly 32 bytes
	shortKey := make([]byte, 16)
	if _, err := rand.Read(shortKey); err != nil {
		t.Fatalf("generate short key: %v", err)
	}

	_, err := EncryptBlob([]byte("data"), shortKey, nil)
	if err == nil {
		t.Fatal("expected error for 16-byte key, got nil")
	}

	longKey := make([]byte, 64)
	if _, err := rand.Read(longKey); err != nil {
		t.Fatalf("generate long key: %v", err)
	}

	_, err = EncryptBlob([]byte("data"), longKey, nil)
	if err == nil {
		t.Fatal("expected error for 64-byte key, got nil")
	}
}

func TestDecryptBlob_KeySizeValidation(t *testing.T) {
	shortKey := make([]byte, 16)
	if _, err := rand.Read(shortKey); err != nil {
		t.Fatalf("generate short key: %v", err)
	}

	_, err := DecryptBlob([]byte("some-valid-looking-blob"), shortKey, nil)
	if err == nil {
		t.Fatal("expected error for 16-byte key on decrypt, got nil")
	}
}
