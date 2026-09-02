package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
)

// Zeroize securely overwrites a byte slice with zeros.
// Uses Go 1.21+ built-in clear to ensure the compiler does not optimize away the write.
//
// SECURITY NOTE: Go's garbage collector may copy heap objects during compaction,
// leaving copies of sensitive data in freed memory pages. Zeroize is therefore
// best-effort — it clears the current backing array but cannot guarantee that
// prior copies made by the GC are also cleared.
//
// For stronger guarantees, callers should consider:
//   - unix.Mlock() to prevent pages from being swapped to disk.
//   - unix.Madvise(buf, unix.MADV_DONTDUMP) to exclude from core dumps.
//   - Allocating sensitive buffers with a fixed size to reduce GC moves.
func Zeroize(buf []byte) {
	clear(buf)
}

// ZeroizePrivateKey attempts to overwrite sensitive key material in a private key.
// Supported types: RSA, ECDSA, and Ed25519 private keys.
// Unsupported or nil values are silently ignored.
//
// SECURITY NOTE: For RSA keys this clears D, Primes (P, Q, and any additional
// primes for multi-prime RSA), and all Precomputed fields (Dp, Dq, Qinv,
// CRTValues). Leaving any one of these intact would allow trivial key
// reconstruction, so all are zeroed.
//
// ECDSA: only the exported D big.Int is cleared; Go's internal FIPS key cache
// retains a copy until GC. RSA/ed25519 are best-effort too (the big.Int
// backing array may be relocated by the GC before this call). Zeroization is
// therefore best-effort, consistent with the caveat documented for Zeroize above.
//
//nolint:staticcheck // intentional best-effort zeroization of deprecated ecdsa.D; no safe alternative exposes the backing array
func ZeroizePrivateKey(key any) {
	if key == nil {
		return
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k == nil {
			return
		}
		zeroizeBigInt(k.D)
		for i := range k.Primes {
			zeroizeBigInt(k.Primes[i])
		}
		if k.Precomputed.Dp != nil {
			zeroizeBigInt(k.Precomputed.Dp)
		}
		if k.Precomputed.Dq != nil {
			zeroizeBigInt(k.Precomputed.Dq)
		}
		if k.Precomputed.Qinv != nil {
			zeroizeBigInt(k.Precomputed.Qinv)
		}
		for i := range k.Precomputed.CRTValues {
			zeroizeBigInt(k.Precomputed.CRTValues[i].Exp)
			zeroizeBigInt(k.Precomputed.CRTValues[i].Coeff)
		}
	case *ecdsa.PrivateKey:
		if k == nil {
			return
		}
		zeroizeBigInt(k.D)
	case ed25519.PrivateKey:
		clear(k) // ed25519.PrivateKey is []byte — clear uses Go 1.21 built-in
	}
}

// zeroizeBigInt overwrites the backing bytes of b in place.
// b must not be nil.
func zeroizeBigInt(b *big.Int) {
	if b == nil {
		return
	}
	n := (b.BitLen() + 7) / 8
	if n == 0 {
		return
	}
	b.SetBytes(make([]byte, n))
}
