package secret

import (
	"strings"
	"testing"
)

// TestMarshalPasswordMetadata_RedactsOTPSecret guards against S-02 regressions:
// the on-disk metadata column must never contain a TOTP/HOTP `secret=` value.
func TestMarshalPasswordMetadata_RedactsOTPSecret(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{
			name: "totp with secret",
			in:   "otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&issuer=Example",
		},
		{
			name: "hotp with secret first",
			in:   "otpauth://hotp/User?secret=NBSWY3DPEHPK3PXP&counter=0",
		},
		{
			name: "secret at end of query",
			in:   "otpauth://totp/User?issuer=Example&secret=ONSWG4TFOQ",
		},
		{
			name: "uppercase SECRET parameter",
			in:   "otpauth://totp/User?SECRET=JBSWY3DPEHPK3PXP&issuer=Example",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta := &PasswordMetadata{OTPAuth: tc.in}
			out := MarshalPasswordMetadata(meta)
			if strings.Contains(out, "JBSWY3DPEHPK3PXP") ||
				strings.Contains(out, "NBSWY3DPEHPK3PXP") ||
				strings.Contains(out, "ONSWG4TFOQ") {
				t.Fatalf("metadata still contains the plaintext seed: %s", out)
			}
			if !strings.Contains(out, OTPAuthRedactedMarker) {
				t.Fatalf("expected REDACTED marker in metadata, got: %s", out)
			}
		})
	}
}

func TestMarshalPasswordMetadata_LeavesAlreadyRedactedAlone(t *testing.T) {
	meta := &PasswordMetadata{
		OTPAuth: "otpauth://totp/User?secret=REDACTED&issuer=Example",
	}
	out := MarshalPasswordMetadata(meta)
	// Should still be exactly one REDACTED occurrence (no double-substitution).
	if got := strings.Count(out, "REDACTED"); got != 1 {
		t.Fatalf("expected 1 REDACTED marker, got %d in %s", got, out)
	}
}

func TestMarshalPasswordMetadata_DoesNotMutateInput(t *testing.T) {
	originalURI := "otpauth://totp/User?secret=JBSWY3DPEHPK3PXP"
	meta := &PasswordMetadata{OTPAuth: originalURI}
	_ = MarshalPasswordMetadata(meta)
	if meta.OTPAuth != originalURI {
		t.Fatalf("Marshal mutated caller's struct: %q", meta.OTPAuth)
	}
}

func TestMarshalPasswordMetadata_PreservesOtherFields(t *testing.T) {
	meta := &PasswordMetadata{
		URL:         "https://example.com",
		Username:    "alice",
		OTPAuth:     "otpauth://totp/User?secret=JBSWY3DPEHPK3PXP",
		HOTPCounter: 7,
	}
	out := MarshalPasswordMetadata(meta)
	for _, want := range []string{"example.com", "alice", "\"hotp_counter\":7"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing field %q in %s", want, out)
		}
	}
}
