package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// ComputeNameLookup returns the HMAC-SHA256 of "passwd.name."+name under the
// given master key. The result is a 32-byte BLOB used as the store's
// name_lookup column (with a UNIQUE constraint) for O(1) exact-match lookup
// without leaking plaintext names to a DB thief.
func ComputeNameLookup(masterKey []byte, name string) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("passwd.name." + name))
	return mac.Sum(nil)
}
