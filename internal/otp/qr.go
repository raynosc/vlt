package otp

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"strings"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	qrcodegen "github.com/skip2/go-qrcode"
)

const (
	maxQRBytes     = 5 * 1024 * 1024 // 5 MB
	maxQRDimension = 4096            // pixels per side
)

// DecodeQR decodes a QR code image from raw bytes and returns the decoded
// URI string. Supports PNG and JPEG images containing QR codes.
func DecodeQR(data []byte) (string, error) {
	if len(data) > maxQRBytes {
		return "", fmt.Errorf("image too large: %d bytes (max %d)", len(data), maxQRBytes)
	}

	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("unable to read image header: %w", err)
	}
	if cfg.Width > maxQRDimension || cfg.Height > maxQRDimension {
		return "", fmt.Errorf("image dimensions %dx%d exceed maximum %dx%d",
			cfg.Width, cfg.Height, maxQRDimension, maxQRDimension)
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("unable to decode image: %w", err)
	}

	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("create bitmap: %w", err)
	}

	reader := qrcode.NewQRCodeReader()
	result, err := reader.Decode(bmp, nil)
	if err != nil {
		return "", fmt.Errorf("no QR code found: %w", err)
	}

	return result.GetText(), nil
}

// QRTerminal generates a terminal-friendly block-character QR art string
// from the given URI. The output can be scanned by a phone authenticator app.
func QRTerminal(uri string) (string, error) {
	if strings.TrimSpace(uri) == "" {
		return "", fmt.Errorf("empty URI")
	}

	qr, err := qrcodegen.New(uri, qrcodegen.Medium)
	if err != nil {
		return "", fmt.Errorf("create QR: %w", err)
	}

	// Render as ASCII art using ToSmallString.
	// This produces block-character QR art scannable by phone apps.
	art := qr.ToSmallString(false)
	return art, nil
}
