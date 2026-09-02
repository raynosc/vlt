package otp

import (
	"testing"
	"time"
)

func TestParseOTPURI_TOTP(t *testing.T) {
	raw := "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
	uri, err := ParseOTPURI(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri.Type != "totp" {
		t.Errorf("Type = %q, want %q", uri.Type, "totp")
	}
	if uri.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Secret = %q, want %q", uri.Secret, "JBSWY3DPEHPK3PXP")
	}
	if uri.Issuer != "Example" {
		t.Errorf("Issuer = %q, want %q", uri.Issuer, "Example")
	}
	if uri.Account != "alice@google.com" {
		t.Errorf("Account = %q, want %q", uri.Account, "alice@google.com")
	}
	if uri.Digits != 6 {
		t.Errorf("Digits = %d, want %d", uri.Digits, 6)
	}
	if uri.Period != 30 {
		t.Errorf("Period = %d, want %d", uri.Period, 30)
	}
	if uri.Algorithm != "SHA1" {
		t.Errorf("Algorithm = %q, want %q", uri.Algorithm, "SHA1")
	}
	if uri.IsSteam {
		t.Error("IsSteam should be false for otpauth://totp")
	}
}

func TestParseOTPURI_HOTP(t *testing.T) {
	raw := "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=42"
	uri, err := ParseOTPURI(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri.Type != "hotp" {
		t.Errorf("Type = %q, want %q", uri.Type, "hotp")
	}
	if uri.Counter != 42 {
		t.Errorf("Counter = %d, want %d", uri.Counter, 42)
	}
}

func TestParseOTPURI_CustomDigits(t *testing.T) {
	raw := "otpauth://totp/Label?secret=JBSWY3DPEHPK3PXP&digits=8"
	uri, err := ParseOTPURI(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri.Digits != 8 {
		t.Errorf("Digits = %d, want %d", uri.Digits, 8)
	}
}

func TestParseOTPURI_CustomAlgorithm(t *testing.T) {
	raw := "otpauth://totp/Label?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256"
	uri, err := ParseOTPURI(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri.Algorithm != "SHA256" {
		t.Errorf("Algorithm = %q, want %q", uri.Algorithm, "SHA256")
	}
}

func TestParseOTPURI_CustomPeriod(t *testing.T) {
	raw := "otpauth://totp/Label?secret=JBSWY3DPEHPK3PXP&period=60"
	uri, err := ParseOTPURI(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri.Period != 60 {
		t.Errorf("Period = %d, want %d", uri.Period, 60)
	}
}

func TestParseOTPURI_Duo(t *testing.T) {
	raw := "duo://otp/Example?secret=JBSWY3DPEHPK3PXP"
	uri, err := ParseOTPURI(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri.Type != "totp" {
		t.Errorf("Type = %q, want %q", uri.Type, "totp")
	}
	if uri.IsDuo != true {
		t.Error("IsDuo should be true for duo:// URI")
	}
}

func TestParseOTPURI_Steam(t *testing.T) {
	raw := "steam://Example?secret=JBSWY3DPEHPK3PXP"
	uri, err := ParseOTPURI(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri.Type != "totp" {
		t.Errorf("Type = %q, want %q", uri.Type, "totp")
	}
	if !uri.IsSteam {
		t.Error("IsSteam should be true for steam:// URI")
	}
	if uri.Digits != 5 {
		t.Errorf("Digits = %d, want %d for Steam", uri.Digits, 5)
	}
}

func TestParseOTPURI_MissingSecret(t *testing.T) {
	raw := "otpauth://totp/Label?issuer=Example"
	_, err := ParseOTPURI(raw)
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestParseOTPURI_InvalidScheme(t *testing.T) {
	raw := "unknown://totp/Label?secret=JBSWY3DPEHPK3PXP"
	_, err := ParseOTPURI(raw)
	if err == nil {
		t.Fatal("expected error for unknown scheme")
	}
}

func TestParseOTPURI_InvalidURI(t *testing.T) {
	_, err := ParseOTPURI("not-a-uri-at-all")
	if err == nil {
		t.Fatal("expected error for invalid URI")
	}
}

func TestParseOTPURI_LabelParsing(t *testing.T) {
	tests := []struct {
		raw     string
		issuer  string
		account string
	}{
		{
			raw:     "otpauth://totp/GitHub:alice@github.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
			issuer:  "GitHub",
			account: "alice@github.com",
		},
		{
			raw:     "otpauth://totp/alice@github.com?secret=JBSWY3DPEHPK3PXP",
			issuer:  "",
			account: "alice@github.com",
		},
	}
	for _, tc := range tests {
		uri, err := ParseOTPURI(tc.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.raw, err)
		}
		if uri.Issuer != tc.issuer {
			t.Errorf("Issuer = %q, want %q for %q", uri.Issuer, tc.issuer, tc.raw)
		}
		if uri.Account != tc.account {
			t.Errorf("Account = %q, want %q for %q", uri.Account, tc.account, tc.raw)
		}
	}
}

func TestParseOTPURI_EscapedLabel(t *testing.T) {
	raw := "otpauth://totp/Issuer%3AUser?secret=JBSWY3DPEHPK3PXP&issuer=Issuer"
	uri, err := ParseOTPURI(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri.Issuer != "Issuer" {
		t.Errorf("Issuer = %q, want %q", uri.Issuer, "Issuer")
	}
	if uri.Account != "User" {
		t.Errorf("Account = %q, want %q", uri.Account, "User")
	}
}

func TestParseOTPURI_RoundTripWithGenerate(t *testing.T) {
	raw := "otpauth://totp/Example:alice@google.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example"
	uri, err := ParseOTPURI(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	code, err := GenerateTOTP(uri.Secret, time.Unix(0, 0).UTC(), 6, uri.Algorithm)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %q", code)
	}
}
