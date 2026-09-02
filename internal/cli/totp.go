package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/otp"
	"github.com/raynosc/vlt/internal/secret"
)

func newTotpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "totp <name>",
		Short: "Generate a TOTP code for a secret with OTPAuth URI",
		Long: `Generate a time-based one-time password (TOTP) code for a secret
that has an otpauth:// URI stored in its metadata.

Displays the current code, algorithm, remaining seconds, and a
countdown progress bar. Use --clipboard to copy the code.`,
		Args: cobra.ExactArgs(1),
		RunE: runTotp,
	}

	cmd.Flags().Bool("clipboard", false, "copy the TOTP code to clipboard")
	cmd.Flags().Bool("qr", false, "show QR terminal art for the OTP URI")
	return cmd
}

func runTotp(cmd *cobra.Command, args []string) error {
	name := args[0]
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	clipboardFlag, _ := cmd.Flags().GetBool("clipboard")
	qrFlag, _ := cmd.Flags().GetBool("qr")

	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	defer crypto.Zeroize(key)

	// Get the secret
	sec, err := getByName(s, key, name)
	if err != nil {
		return fmt.Errorf("error: secret not found: %s", name)
	}

	// Extract OTPAuth from metadata (may be redacted — secret=REDACTED)
	meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
	if meta == nil || meta.OTPAuth == "" {
		return fmt.Errorf("error: no OTP URI found for secret: %s", name)
	}

	// S-02: prefer the dedicated encrypted_otp_seed column. If it's set, the
	// `secret=` parameter is reconstructed from that decrypted value, and the
	// (redacted) URI in metadata supplies only the label/algorithm/digits.
	var otpURIStr string
	if len(sec.EncryptedOTPSeed) > 0 {
		nonce, ciphertext, err := unpackEnvelope(sec.EncryptedOTPSeed)
		if err != nil {
			return fmt.Errorf("error: %w", err)
		}
		seedBytes, err := engine.Decrypt(ciphertext, key, nonce)
		if err != nil {
			return fmt.Errorf("error: decryption failed")
		}
		defer crypto.Zeroize(seedBytes)
		otpURIStr = otp.InjectOTPSecret(meta.OTPAuth, string(seedBytes))
	} else if len(sec.EncryptedValue) > 0 {
		// Backward compatibility path (HIGH-01 / pre-S-02 vaults).
		nonce, ciphertext, err := unpackEnvelope(sec.EncryptedValue)
		if err != nil {
			return fmt.Errorf("error: %w", err)
		}
		plaintext, err := engine.Decrypt(ciphertext, key, nonce)
		if err != nil {
			return fmt.Errorf("error: decryption failed")
		}
		defer crypto.Zeroize(plaintext)

		ptStr := string(plaintext)
		if strings.HasPrefix(ptStr, "otpauth://") || strings.HasPrefix(ptStr, "steam://") || strings.HasPrefix(ptStr, "duo://") {
			otpURIStr = ptStr
		} else if strings.Contains(meta.OTPAuth, "secret=REDACTED") {
			otpURIStr = otp.InjectOTPSecret(meta.OTPAuth, ptStr)
		} else {
			otpURIStr = meta.OTPAuth
		}
	} else {
		otpURIStr = meta.OTPAuth
	}

	// Parse the OTP URI
	uri, err := otp.ParseOTPURI(otpURIStr)
	if err != nil {
		return fmt.Errorf("error: invalid OTP URI: %w", err)
	}

	if qrFlag {
		qrArt, err := otp.QRTerminal(otpURIStr)
		if err != nil {
			return fmt.Errorf("error: generate QR: %w", err)
		}
		fmt.Fprintln(os.Stderr, qrArt)
	}

	var code string
	switch {
	case uri.IsSteam:
		code, err = otp.GenerateSteamCode(uri.Secret)
		if err != nil {
			return fmt.Errorf("error: generate Steam code: %w", err)
		}
	case uri.Type == "hotp":
		// For HOTP, use the counter from metadata (or URI as fallback)
		counter := meta.HOTPCounter
		if counter == 0 && uri.Counter > 0 {
			counter = uri.Counter
		}
		code, err = otp.GenerateHOTP(uri.Secret, counter, uri.Digits)
		if err != nil {
			return fmt.Errorf("error: generate HOTP: %w", err)
		}
		// Atomically increment and persist counter
		newCounter, err := incrementHOTPCounter(s, engine, key, name)
		if err != nil {
			return fmt.Errorf("error: update counter: %w", err)
		}
		meta.HOTPCounter = newCounter
	default:
		code, err = otp.GenerateTOTP(uri.Secret, time.Now().UTC(), uri.Digits, uri.Algorithm)
		if err != nil {
			return fmt.Errorf("error: generate TOTP: %w", err)
		}
	}

	if clipboardFlag {
		if err := clipboard.WriteAll(code); err != nil {
			return fmt.Errorf("error: clipboard: %w", err)
		}
		StartClipboardAutoClear(code)
		fmt.Fprintf(os.Stderr, "✓ Copied to clipboard\n")
	}

	// Display the code
	currentTime := time.Now().UTC()
	remaining := uri.Period - int(currentTime.Unix()%int64(uri.Period))
	bar := renderCountdownBar(remaining, uri.Period)

	algoLabel := uri.Algorithm
	if algoLabel == "" {
		algoLabel = "SHA1"
	}

	if uri.IsSteam {
		fmt.Println(code)
		fmt.Fprintf(os.Stderr, "Steam  |  %s\n", bar)
	} else if uri.Type == "hotp" {
		fmt.Println(code)
		fmt.Fprintf(os.Stderr, "HOTP  |  counter: %d\n", meta.HOTPCounter)
	} else {
		fmt.Println(code)
		fmt.Fprintf(os.Stderr, "%s  |  %ds remaining  %s\n", algoLabel, remaining, bar)
	}

	// Log audit
	_ = s.LogAction("totp_generate", name, "")

	return nil
}

// renderCountdownBar creates a visual countdown progress bar using block chars.
func renderCountdownBar(remaining, period int) string {
	const barWidth = 30
	filled := (barWidth * (period - remaining)) / period
	if filled < 0 {
		filled = 0
	}
	if filled > barWidth {
		filled = barWidth
	}

	bar := "["
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	bar += "]"
	return bar
}
