package otp

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// OTPURI represents a parsed OTP URI from any supported scheme
// (otpauth://, duo://, steam://).
type OTPURI struct {
	Type      string // "totp" or "hotp"
	Secret    string // base32-encoded secret
	Issuer    string
	Account   string
	Digits    int    // 6 or 8 (default 6)
	Period    int    // seconds, default 30 (TOTP only)
	Algorithm string // "SHA1", "SHA256", "SHA512" (default "SHA1")
	Counter   uint64 // HOTP counter (default 0)
	IsSteam   bool   // parsed from steam://
	IsDuo     bool   // parsed from duo://
}

// otpauthRegex matches otpauth://totp/... and otpauth://hotp/... URIs.
var otpauthRegex = regexp.MustCompile(`^otpauth://(totp|hotp)/([^?]+)\?(.+)$`)

// duoRegex matches duo:// URIs.
var duoRegex = regexp.MustCompile(`^duo://([^?]+)\?(.+)$`)

// steamRegex matches steam:// URIs.
var steamRegex = regexp.MustCompile(`^steam://([^?]+)\?(.+)$`)

// ParseOTPURI parses an OTP URI from any supported scheme and returns
// an OTPURI struct with decoded parameters.
//
// Supported schemes:
//   - otpauth://totp/LABEL?params
//   - otpauth://hotp/LABEL?params
//   - duo://LABEL?params (treated as TOTP)
//   - steam://LABEL?params (treated as TOTP, digits=5, Steam alphabet)
func ParseOTPURI(raw string) (*OTPURI, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty URI")
	}

	uri := &OTPURI{
		Digits:    6,
		Period:    30,
		Algorithm: "SHA1",
	}

	var label, queryStr string

	if matches := otpauthRegex.FindStringSubmatch(raw); matches != nil {
		uri.Type = matches[1]
		label = matches[2]
		queryStr = matches[3]
	} else if matches := duoRegex.FindStringSubmatch(raw); matches != nil {
		uri.Type = "totp"
		uri.IsDuo = true
		label = matches[1]
		queryStr = matches[2]
	} else if matches := steamRegex.FindStringSubmatch(raw); matches != nil {
		uri.Type = "totp"
		uri.IsSteam = true
		uri.Digits = 5
		label = matches[1]
		queryStr = matches[2]
	} else {
		return nil, fmt.Errorf("unsupported OTP URI scheme")
	}

	// Parse label: "Issuer:Account" or just "Account"
	label, _ = url.PathUnescape(label)
	label, _ = url.QueryUnescape(label)
	if colonIdx := strings.Index(label, ":"); colonIdx != -1 {
		uri.Issuer = label[:colonIdx]
		uri.Account = label[colonIdx+1:]
	} else {
		uri.Account = label
	}

	// Parse query parameters
	params, err := url.ParseQuery(queryStr)
	if err != nil {
		return nil, fmt.Errorf("parse query: %w", err)
	}

	if secret := params.Get("secret"); secret != "" {
		uri.Secret = secret
	} else {
		return nil, fmt.Errorf("missing secret parameter")
	}

	if issuer := params.Get("issuer"); issuer != "" {
		uri.Issuer = issuer
	}

	if digitsStr := params.Get("digits"); digitsStr != "" {
		d, err := strconv.Atoi(digitsStr)
		if err == nil && (d == 6 || d == 8) {
			uri.Digits = d
		}
	}

	if periodStr := params.Get("period"); periodStr != "" {
		p, err := strconv.Atoi(periodStr)
		if err == nil && p > 0 {
			uri.Period = p
		}
	}

	if algo := params.Get("algorithm"); algo != "" {
		uri.Algorithm = strings.ToUpper(algo)
	}

	if counterStr := params.Get("counter"); counterStr != "" {
		c, err := strconv.ParseUint(counterStr, 10, 64)
		if err == nil {
			uri.Counter = c
		}
	}

	return uri, nil
}

// RedactOTPAuth removes the secret parameter from an OTP URI.
// Returns the URI with "secret=REDACTED" for safe plaintext storage.
// The actual secret should be stored only in the encrypted value.
func RedactOTPAuth(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// Find and replace the secret parameter value
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	if q.Get("secret") != "" {
		q.Set("secret", "REDACTED")
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// InjectOTPSecret replaces the secret parameter in a (potentially redacted)
// OTP URI with the provided secret value.
func InjectOTPSecret(raw, secret string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || secret == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set("secret", secret)
	u.RawQuery = q.Encode()
	return u.String()
}
