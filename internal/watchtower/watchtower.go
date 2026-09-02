// Package watchtower provides password security analysis for the passwd vault.
//
// It is a shared package used by both the GUI and CLI. All plaintext buffers
// are zeroized before the function returns, but Go's garbage collector may
// retain copies — this is best-effort memory safety.
package watchtower

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/parse"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
)

// PasswordStrength rates a password's resistance to cracking.
type PasswordStrength int

const (
	StrengthVeryWeak PasswordStrength = iota
	StrengthWeak
	StrengthFair
	StrengthStrong
	StrengthVeryStrong
)

func (s PasswordStrength) String() string {
	switch s {
	case StrengthVeryWeak:
		return "Very Weak"
	case StrengthWeak:
		return "Weak"
	case StrengthFair:
		return "Fair"
	case StrengthStrong:
		return "Strong"
	case StrengthVeryStrong:
		return "Very Strong"
	default:
		return "Unknown"
	}
}

// ColorHex returns a hex color string for GUI rendering.
func (s PasswordStrength) ColorHex() string {
	switch s {
	case StrengthVeryWeak:
		return "#EF4444"
	case StrengthWeak:
		return "#F59E0B"
	case StrengthFair:
		return "#F59E0B"
	case StrengthStrong:
		return "#10B981"
	case StrengthVeryStrong:
		return "#10B981"
	default:
		return "#888888"
	}
}

// CompromisedPasswordFinding represents a password found in known data breaches (HIBP).
type CompromisedPasswordFinding struct {
	SecretName  string
	Username    string
	URL         string
	BreachCount int
}

// WeakPasswordFinding represents a password that fails strength checks.
type WeakPasswordFinding struct {
	SecretName string
	Username   string
	URL        string
	Score      PasswordStrength
	Reason     string
}

// DuplicatePasswordFinding represents a password reused across multiple secrets.
type DuplicatePasswordFinding struct {
	PasswordHash string
	SecretNames  []string
}

// Missing2FAFinding represents a login with a URL but no 2FA configured.
type Missing2FAFinding struct {
	SecretName string
	Username   string
	URL        string
}

// WatchtowerResult holds all security analysis findings.
type WatchtowerResult struct {
	TotalSecrets           int
	WeakPasswords          []WeakPasswordFinding
	CompromisedPasswords   []CompromisedPasswordFinding
	DuplicatePasswords     []DuplicatePasswordFinding
	Missing2FA             []Missing2FAFinding
	ExpiringCertificates   int
	PasswordReuseCount     int
	SecretsWithWeakPass    int
	SecretsWithCompromised int
	SecretsWithNoOTP       int
	AnalyzedPasswordCount  int
	IsOfflineMode          bool
	OfflineReason          string
}

// Analyze decrypts all password-type secrets and runs security analysis with default local & online checks.
func Analyze(s store.Store, engine *crypto.Engine, key []byte) (*WatchtowerResult, error) {
	return AnalyzeWithPwned(s, engine, key, NewPwnedManager(DefaultPwnedCooldown))
}

// AnalyzeWithPwned runs security analysis including Pwned Passwords verification via the provided manager.
func AnalyzeWithPwned(s store.Store, engine *crypto.Engine, key []byte, pwnedMgr *PwnedManager) (*WatchtowerResult, error) {
	allSecrets, err := s.ListWithEncryptedAll()
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	result := &WatchtowerResult{
		TotalSecrets: len(allSecrets),
	}

	// Decrypt and analyze password-type secrets
	var decryptedPasswords []struct {
		name     string
		username string
		url      string
		value    string
	}

	for _, sec := range allSecrets {
		if sec.Kind != secret.KindPassword {
			continue
		}

		// Decrypt metadata so Name and Metadata fields are usable.
		if err := decryptSecretMetadata(&sec, engine, key); err != nil {
			continue
		}

		result.AnalyzedPasswordCount++

		nonce, ciphertext, err := unpackEnvelope(sec.EncryptedValue)
		if err != nil {
			continue
		}

		plaintext, err := engine.Decrypt(ciphertext, key, nonce)
		if err != nil {
			continue
		}

		pwValue := string(plaintext)
		crypto.Zeroize(plaintext)

		meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
		username := ""
		url := ""
		if meta != nil {
			username = meta.Username
			url = meta.URL
		}

		decryptedPasswords = append(decryptedPasswords, struct {
			name     string
			username string
			url      string
			value    string
		}{sec.Name, username, url, pwValue})

		// Check for missing 2FA: logins with a URL but no OTP configured
		if url != "" && (meta == nil || (meta.OTPAuth == "" && len(sec.EncryptedOTPSeed) == 0)) {
			result.Missing2FA = append(result.Missing2FA, Missing2FAFinding{
				SecretName: sec.Name,
				Username:   username,
				URL:        url,
			})
			result.SecretsWithNoOTP++
		}

		// Check password strength
		strength, reason := AssessPasswordStrength(pwValue)
		if strength < StrengthFair {
			result.WeakPasswords = append(result.WeakPasswords, WeakPasswordFinding{
				SecretName: sec.Name,
				Username:   username,
				URL:        url,
				Score:      strength,
				Reason:     reason,
			})
			result.SecretsWithWeakPass++
		}
	}

	// Detect duplicate passwords
	passwordMap := make(map[string][]string)
	for _, dp := range decryptedPasswords {
		if dp.value == "" {
			continue
		}
		passwordMap[dp.value] = append(passwordMap[dp.value], dp.name)
	}

	for pw, names := range passwordMap {
		if len(names) > 1 {
			hash := sha256Sum([]byte(pw))
			result.DuplicatePasswords = append(result.DuplicatePasswords, DuplicatePasswordFinding{
				PasswordHash: hash[:16],
				SecretNames:  names,
			})
			result.PasswordReuseCount += len(names) - 1
		}
	}

	// Pwned Passwords verification with Persistent Metadata Cache and Offline Backoff
	// Passwords audited in the last 14 days use their cached PwnedCount directly.
	const cacheValidity = 14 * 24 * time.Hour
	now := time.Now().UTC()

	var passwordsToQuery []string
	pwToSecretIndices := make(map[string][]int)

	for i, sec := range allSecrets {
		if sec.Kind != secret.KindPassword || i >= len(decryptedPasswords) {
			continue
		}
		dp := decryptedPasswords[i]
		if dp.value == "" {
			continue
		}

		meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
		// Check if cache is fresh
		if meta != nil && meta.LastAudited != nil && !meta.LastAudited.IsZero() && now.Sub(*meta.LastAudited) < cacheValidity {
			if meta.PwnedCount > 0 {
				result.CompromisedPasswords = append(result.CompromisedPasswords, CompromisedPasswordFinding{
					SecretName:  dp.name,
					Username:    dp.username,
					URL:         dp.url,
					BreachCount: meta.PwnedCount,
				})
				result.SecretsWithCompromised++
			}
		} else {
			passwordsToQuery = append(passwordsToQuery, dp.value)
			pwToSecretIndices[dp.value] = append(pwToSecretIndices[dp.value], i)
		}
	}

	if len(passwordsToQuery) > 0 && pwnedMgr != nil {
		if pwnedMgr.ShouldAttempt() {
			pwnedResults, err := pwnedMgr.CheckBatch(passwordsToQuery)
			if err != nil {
				result.IsOfflineMode = true
				result.OfflineReason = err.Error()
			} else {
				for pw, indices := range pwToSecretIndices {
					count := pwnedResults[pw]
					for _, idx := range indices {
						sec := allSecrets[idx]
						dp := decryptedPasswords[idx]
						if count > 0 {
							result.CompromisedPasswords = append(result.CompromisedPasswords, CompromisedPasswordFinding{
								SecretName:  dp.name,
								Username:    dp.username,
								URL:         dp.url,
								BreachCount: count,
							})
							result.SecretsWithCompromised++
						}
						// Update persistent cache in DB metadata
						meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
						if meta == nil {
							meta = &secret.PasswordMetadata{Username: dp.username, URL: dp.url}
						}
						meta.PwnedCount = count
						meta.LastAudited = &now
						updatedJSON := secret.MarshalPasswordMetadata(meta)

						// Encrypt and persist updated metadata
						if encMeta, nonce, err := engine.Encrypt([]byte(updatedJSON), key); err == nil {
							_ = s.UpdateOTPSeedAndMetadata(sec.NameLookup, sec.EncryptedOTPSeed, crypto.PackEnvelope(nonce, encMeta))
						}
					}
				}
			}
		} else {
			result.IsOfflineMode = true
			if pwnedMgr.disabled {
				result.OfflineReason = "Pwned passwords check is disabled"
			} else {
				result.OfflineReason = fmt.Sprintf("Offline backoff active (%v remaining)", pwnedMgr.RemainingCooldown().Round(time.Second))
			}
		}
	}

	// Expiring certificates check
	for _, sec := range allSecrets {
		if sec.Kind == secret.KindCertificate {
			_ = decryptSecretMetadata(&sec, engine, key)
			if sec.Metadata != "" {
				var meta parse.Metadata
				if err := json.Unmarshal([]byte(sec.Metadata), &meta); err == nil && meta.NotAfter != "" {
					if meta.DaysUntilExpiry() <= 30 {
						result.ExpiringCertificates++
					}
				}
			}
		}
	}

	// Zeroize decrypted passwords
	for i := range decryptedPasswords {
		decryptedPasswords[i].value = ""
	}

	return result, nil
}

// decryptSecretMetadata decrypts the EncryptedName and EncryptedMetadata fields
// of a secret in-place. Empty BLOBs are skipped.
func decryptSecretMetadata(sec *secret.Secret, engine *crypto.Engine, key []byte) error {
	if len(sec.EncryptedName) > 0 {
		nonce, ct, err := unpackEnvelope(sec.EncryptedName)
		if err != nil {
			return err
		}
		pt, err := engine.Decrypt(ct, key, nonce)
		if err != nil {
			return err
		}
		sec.Name = string(pt)
		crypto.Zeroize(pt)
	}
	if len(sec.EncryptedMetadata) > 0 {
		nonce, ct, err := unpackEnvelope(sec.EncryptedMetadata)
		if err != nil {
			return err
		}
		pt, err := engine.Decrypt(ct, key, nonce)
		if err != nil {
			return err
		}
		sec.Metadata = string(pt)
		crypto.Zeroize(pt)
	}
	return nil
}

// unpackEnvelope splits an encrypted blob into nonce and ciphertext.
// The blob format is: nonce || ciphertext.
func unpackEnvelope(blob []byte) (nonce, ciphertext []byte, err error) {
	return crypto.UnpackEnvelope(blob)
}

// sha256Sum returns the SHA-256 hash of data as a hex string.
func sha256Sum(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

// AssessPasswordStrength evaluates a password and returns its strength and a reason.
func AssessPasswordStrength(password string) (PasswordStrength, string) {
	if len(password) == 0 {
		return StrengthVeryWeak, "Empty password"
	}

	score := 0

	// Length scoring
	length := len(password)
	switch {
	case length < 8:
		score += 0
	case length < 12:
		score += 1
	case length < 16:
		score += 2
	case length < 20:
		score += 3
	default:
		score += 4
	}

	// Character set diversity
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, c := range password {
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	charsetDiversity := 0
	if hasLower {
		charsetDiversity++
	}
	if hasUpper {
		charsetDiversity++
	}
	if hasDigit {
		charsetDiversity++
	}
	if hasSymbol {
		charsetDiversity++
	}
	score += charsetDiversity

	// Deductions for common patterns
	// Repeated character check
	repeatedCount := 0
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			repeatedCount++
		}
	}
	if repeatedCount >= 4 {
		score -= 2
	} else if repeatedCount >= 2 {
		score -= 1
	}

	// Sequential character check
	sequentialCount := 0
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1]+1 {
			sequentialCount++
		}
	}
	if sequentialCount >= 4 {
		score -= 2
	} else if sequentialCount >= 3 {
		score -= 1
	}

	// Common passwords check
	commonPasswords := []string{
		"password", "123456", "12345678", "qwerty", "abc123",
		"monkey", "letmein", "dragon", "111111", "baseball",
		"iloveyou", "trustno1", "sunshine", "master", "welcome",
		"shadow", "ashley", "football", "jesus", "michael",
		"ninja", "mustang", "password1", "admin",
	}
	for _, common := range commonPasswords {
		if strings.ToLower(password) == common || strings.ToLower(password) == common+"123" {
			return StrengthVeryWeak, "Common password"
		}
	}

	// Determine strength
	switch {
	case score <= 1:
		return StrengthVeryWeak, "Too short and simple"
	case score <= 3:
		return StrengthWeak, "Add more variety (uppercase, digits, symbols)"
	case score <= 5:
		return StrengthFair, "Could be stronger with more length and symbols"
	case score <= 7:
		return StrengthStrong, ""
	default:
		return StrengthVeryStrong, ""
	}
}
