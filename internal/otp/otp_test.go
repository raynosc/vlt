package otp

import (
	"strings"
	"testing"
	"time"
)

// RFC 4226 Appendix D / RFC 6238 test secrets.
// SHA1 uses 20-byte key "12345678901234567890".
// SHA256 uses 32-byte key "12345678901234567890123456789012".
// SHA512 uses 64-byte key "1234567890123456789012345678901234567890123456789012345678901234".
const (
	rfcSecret    = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"                                                                        // 20 bytes
	rfcSecret256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"                                                    // 32 bytes
	rfcSecret512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA" // 64 bytes
)

// RFC 4226 Appendix D test vectors — 6-digit HOTP with SHA1.
func TestGenerateHOTP_RFC4226Vectors(t *testing.T) {
	expected := []struct {
		counter uint64
		code    string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}

	for _, tc := range expected {
		got, err := GenerateHOTP(rfcSecret, tc.counter, 6)
		if err != nil {
			t.Fatalf("counter=%d: unexpected error: %v", tc.counter, err)
		}
		if got != tc.code {
			t.Errorf("counter=%d: got %q, want %q", tc.counter, got, tc.code)
		}
	}
}

// RFC 6238 Appendix B test vectors — 8-digit TOTP with SHA1.
// Uses key = hex("3132333435363738393031323334353637383930")
// which is ASCII "12345678901234567890" (20 bytes).
func TestGenerateTOTP_SHA1_RFC6238Vectors(t *testing.T) {
	cases := []struct {
		t    int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
	}

	for _, tc := range cases {
		got, err := GenerateTOTP(rfcSecret, time.Unix(tc.t, 0).UTC(), 8, "SHA1")
		if err != nil {
			t.Fatalf("t=%d: unexpected error: %v", tc.t, err)
		}
		if got != tc.want {
			t.Errorf("t=%d (SHA1): got %q, want %q", tc.t, got, tc.want)
		}
	}
}

// SHA256 test vectors use a 32-byte key (rfcSecret256).
func TestGenerateTOTP_SHA256_RFC6238Vectors(t *testing.T) {
	cases := []struct {
		t    int64
		want string
	}{
		{59, "46119246"},
		{1111111109, "68084774"},
		{1111111111, "67062674"},
		{1234567890, "91819424"},
		{2000000000, "90698825"},
	}

	for _, tc := range cases {
		got, err := GenerateTOTP(rfcSecret256, time.Unix(tc.t, 0).UTC(), 8, "SHA256")
		if err != nil {
			t.Fatalf("t=%d: unexpected error: %v", tc.t, err)
		}
		if got != tc.want {
			t.Errorf("t=%d (SHA256): got %q, want %q", tc.t, got, tc.want)
		}
	}
}

// SHA512 test vectors use a 64-byte key (rfcSecret512).
func TestGenerateTOTP_SHA512_RFC6238Vectors(t *testing.T) {
	cases := []struct {
		t    int64
		want string
	}{
		{59, "90693936"},
		{1111111109, "25091201"},
		{1111111111, "99943326"},
		{1234567890, "93441116"},
		{2000000000, "38618901"},
	}

	for _, tc := range cases {
		got, err := GenerateTOTP(rfcSecret512, time.Unix(tc.t, 0).UTC(), 8, "SHA512")
		if err != nil {
			t.Fatalf("t=%d: unexpected error: %v", tc.t, err)
		}
		if got != tc.want {
			t.Errorf("t=%d (SHA512): got %q, want %q", tc.t, got, tc.want)
		}
	}
}

// Steam alphabet validation — generated code uses only custom chars.
func TestGenerateSteamCode_Alphabet(t *testing.T) {
	expectedChars := "23456789BCDFGHJKMNPQRTVWXY"
	code, err := GenerateSteamCode(rfcSecret)
	if err != nil {
		t.Fatalf("GenerateSteamCode: %v", err)
	}
	if len(code) != 5 {
		t.Errorf("expected 5 chars, got %d: %q", len(code), code)
	}
	for _, ch := range code {
		if !strings.ContainsRune(expectedChars, ch) {
			t.Errorf("char %c not in Steam alphabet", ch)
		}
	}
}

// Invalid base32 secret returns error.
func TestGenerateHOTP_InvalidSecret(t *testing.T) {
	_, err := GenerateHOTP("!!!invalid-base32!!!", 0, 6)
	if err == nil {
		t.Fatal("expected error for invalid base32 secret")
	}
}

// Empty secret returns error.
func TestGenerateHOTP_EmptySecret(t *testing.T) {
	_, err := GenerateHOTP("", 0, 6)
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

// Custom digits — 8-digit HOTP.
func TestGenerateHOTP_CustomDigits(t *testing.T) {
	got, err := GenerateHOTP(rfcSecret, 0, 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 8 {
		t.Errorf("expected 8 digits, got %d: %q", len(got), got)
	}
}

// TOTP default algorithm is SHA1.
func TestGenerateTOTP_DefaultAlgorithm(t *testing.T) {
	got1, err := GenerateTOTP(rfcSecret, time.Unix(59, 0).UTC(), 8, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got2, err := GenerateTOTP(rfcSecret, time.Unix(59, 0).UTC(), 8, "SHA1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got1 != got2 {
		t.Errorf("empty algo should default to SHA1, got %q vs %q", got1, got2)
	}
}

// Different time step produces different TOTP code.
func TestGenerateTOTP_TimeStepAdvances(t *testing.T) {
	code1, err := GenerateTOTP(rfcSecret, time.Unix(0, 0).UTC(), 6, "SHA1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	code2, err := GenerateTOTP(rfcSecret, time.Unix(30, 0).UTC(), 6, "SHA1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code1 == code2 {
		t.Error("codes at T=0 and T=30 should differ")
	}
}

// Invalid algorithm returns error.
func TestGenerateTOTP_InvalidAlgorithm(t *testing.T) {
	_, err := GenerateTOTP(rfcSecret, time.Now(), 6, "SHA999")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

// --- digits validation (M7) ---

func TestGenerateHOTP_InvalidDigits_Zero(t *testing.T) {
	_, err := GenerateHOTP(rfcSecret, 0, 0)
	if err == nil {
		t.Fatal("expected error for digits=0")
	}
}

func TestGenerateHOTP_InvalidDigits_Negative(t *testing.T) {
	_, err := GenerateHOTP(rfcSecret, 0, -1)
	if err == nil {
		t.Fatal("expected error for digits=-1")
	}
}

func TestGenerateHOTP_InvalidDigits_TooHigh(t *testing.T) {
	_, err := GenerateHOTP(rfcSecret, 0, 9)
	if err == nil {
		t.Fatal("expected error for digits=9")
	}
}

func TestGenerateHOTP_ValidDigits_Five(t *testing.T) {
	got, err := GenerateHOTP(rfcSecret, 0, 5)
	if err != nil {
		t.Fatalf("unexpected error for digits=5: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("expected 5-character code, got %d: %q", len(got), got)
	}
}

func TestGenerateTOTP_InvalidDigits_Zero(t *testing.T) {
	_, err := GenerateTOTP(rfcSecret, time.Unix(59, 0).UTC(), 0, "SHA1")
	if err == nil {
		t.Fatal("expected error for digits=0")
	}
}

func TestGenerateTOTP_InvalidDigits_Negative(t *testing.T) {
	_, err := GenerateTOTP(rfcSecret, time.Unix(59, 0).UTC(), -1, "SHA1")
	if err == nil {
		t.Fatal("expected error for digits=-1")
	}
}

func TestGenerateTOTP_InvalidDigits_TooHigh(t *testing.T) {
	_, err := GenerateTOTP(rfcSecret, time.Unix(59, 0).UTC(), 9, "SHA1")
	if err == nil {
		t.Fatal("expected error for digits=9")
	}
}

func TestGenerateTOTP_ValidDigits_Five(t *testing.T) {
	got, err := GenerateTOTP(rfcSecret, time.Unix(59, 0).UTC(), 5, "SHA1")
	if err != nil {
		t.Fatalf("unexpected error for digits=5: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("expected 5-character code, got %d: %q", len(got), got)
	}
}

// TestTruncate_EmptyHMAC verifies that truncate does not panic on an empty
// or nil HMAC slice and returns a zero-padded fallback of the correct width.
func TestTruncate_EmptyHMAC(t *testing.T) {
	cases := []struct {
		name   string
		hs     []byte
		digits int
		want   string
	}{
		{"nil slice", nil, 6, "000000"},
		{"empty slice", []byte{}, 6, "000000"},
		{"nil slice 8-digit", nil, 8, "00000000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Must not panic.
			got := truncate(tc.hs, tc.digits)
			if got != tc.want {
				t.Errorf("truncate(%v, %d): got %q, want %q", tc.hs, tc.digits, got, tc.want)
			}
		})
	}
}

// TestTruncate_ShortHMAC verifies the defensive bounds guard in truncate.
// A synthetic HMAC slice is constructed where len(hs) < offset+4, which
// would cause an out-of-bounds panic without the guard. The function must
// return a zero-padded string of the correct width.
func TestTruncate_ShortHMAC(t *testing.T) {
	// offset = hs[last] & 0x0F. Set last byte to 0x0F → offset = 15.
	// len(hs) = 4, so len(hs) < 15+4 → triggers guard.
	hs := []byte{0x00, 0x01, 0x02, 0x0F}
	digits := 6
	got := truncate(hs, digits)
	want := "000000"
	if got != want {
		t.Errorf("truncate short HMAC: got %q, want %q", got, want)
	}
}
