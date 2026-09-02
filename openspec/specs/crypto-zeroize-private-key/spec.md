# crypto-zeroize-private-key Specification

## Purpose

Extends the existing zeroize API to cover asymmetric private keys (RSA, ECDSA, ed25519).
Best-effort only: `big.Int` fields are zeroed by overwriting the backing integer, but the Go
runtime may retain a reallocated backing array after GC. This is a known limitation documented
in `zeroize.go` and accepted per the project's existing best-effort zeroize caveat.

## Requirements

### Requirement: ZeroizePrivateKey — RSA

`ZeroizePrivateKey` MUST zero the private exponent `D` and the precomputed fields `Dp`, `Dq`,
and `Qinv` of an `*rsa.PrivateKey` using `SetBytes(make([]byte, N))` (best-effort;
`big.Int` backing array may persist until GC).

#### Scenario: RSA key D is zeroed

- GIVEN an `*rsa.PrivateKey` with a non-zero `D`
- WHEN `ZeroizePrivateKey(key)` is called
- THEN `key.D.Sign()` returns 0 (or the integer compares equal to zero)
- AND `key.Precomputed.Dp.Sign()`, `Dq.Sign()`, `Qinv.Sign()` each return 0

#### Scenario: RSA zero is best-effort (documented caveat)

- GIVEN an `*rsa.PrivateKey` after `ZeroizePrivateKey` is called
- WHEN the `D` field is inspected
- THEN its big.Int value represents zero (best-effort; backing array may differ)

---

### Requirement: ZeroizePrivateKey — ECDSA

`ZeroizePrivateKey` MUST zero the private scalar `D` of an `*ecdsa.PrivateKey` using
`SetBytes(make([]byte, N))` (best-effort).

#### Scenario: ECDSA key D is zeroed

- GIVEN an `*ecdsa.PrivateKey` with a non-zero `D`
- WHEN `ZeroizePrivateKey(key)` is called
- THEN `key.D.Sign()` returns 0

---

### Requirement: ZeroizePrivateKey — ed25519

`ZeroizePrivateKey` MUST zero an `ed25519.PrivateKey` (which is `[]byte`) by overwriting
every byte with `0x00`.

#### Scenario: Ed25519 key bytes are zeroed

- GIVEN an `ed25519.PrivateKey` with non-zero bytes
- WHEN `ZeroizePrivateKey(key)` is called
- THEN every byte in the slice is `0x00`

---

### Requirement: ZeroizePrivateKey — nil and unknown types

`ZeroizePrivateKey` MUST be a no-op (no panic, no error) when called with `nil` or an
unrecognized type.

#### Scenario: Nil input is safe

- GIVEN a nil value passed to `ZeroizePrivateKey`
- WHEN the function is called
- THEN it returns without panicking

#### Scenario: Unknown type is ignored

- GIVEN an arbitrary non-key value (e.g. a plain `string`)
- WHEN `ZeroizePrivateKey(value)` is called
- THEN the function returns without panicking and without modifying the value

---

### Requirement: ParsePKCS12 zeroizes the discarded private key

`ParsePKCS12` MUST capture the private key returned by `pkcs12.DecodeChain` and defer a call
to `crypto.ZeroizePrivateKey` before the function returns, regardless of the return path
(success or error). The existing public signature and return values of `ParsePKCS12` MUST NOT
change.

> NOTE: This zeroes only the key discarded internally. Keys returned to callers are out of scope.

#### Scenario: M6 — ParsePKCS12 regression — metadata still correct

- GIVEN a valid PKCS#12 bundle containing 2 certificates (CA + leaf) with friendly names
- WHEN `ParsePKCS12(p12Data, password)` is called
- THEN certificate count is 2 and friendly names match embedded values (no regression)

#### Scenario: M6 — private key is zeroized before return

- GIVEN a valid PKCS#12 bundle with a known RSA private key
- WHEN `ParsePKCS12(p12Data, password)` is called and returns
- THEN the private key captured internally has D equal to zero (best-effort)
- AND the returned certificate metadata is unaffected
