package otp

import (
	"hash/crc32"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	qrcode "github.com/skip2/go-qrcode"
)

// generateQRPNG creates a PNG file containing a QR code with the given content.
func generateQRPNG(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "qr.png")
	qr, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		t.Fatalf("create QR: %v", err)
	}
	img := qr.Image(256)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("encode PNG: %v", err)
	}
	return path
}

// generateBlankPNG creates a PNG file with no QR code (solid color).
func generateBlankPNG(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "blank.png")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()

	img := image.NewNRGBA(image.Rect(0, 0, 100, 100))
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("encode blank PNG: %v", err)
	}
	return path
}

func TestDecodeQR_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	uri := "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP"
	pngPath := generateQRPNG(t, tmpDir, uri)

	data, err := os.ReadFile(pngPath)
	if err != nil {
		t.Fatalf("read PNG: %v", err)
	}

	decoded, err := DecodeQR(data)
	if err != nil {
		t.Fatalf("DecodeQR: %v", err)
	}
	if decoded != uri {
		t.Errorf("got %q, want %q", decoded, uri)
	}
}

func TestDecodeQR_NoQR(t *testing.T) {
	tmpDir := t.TempDir()
	pngPath := generateBlankPNG(t, tmpDir)

	data, err := os.ReadFile(pngPath)
	if err != nil {
		t.Fatalf("read PNG: %v", err)
	}

	_, err = DecodeQR(data)
	if err == nil {
		t.Fatal("expected error for blank image with no QR code")
	}
	if !strings.Contains(err.Error(), "no QR code") && !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'no QR code' error, got: %v", err)
	}
}

func TestDecodeQR_CorruptImage(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03} // not a valid image
	_, err := DecodeQR(data)
	if err == nil {
		t.Fatal("expected error for corrupt image")
	}
}

func TestQRTerminal_Valid(t *testing.T) {
	uri := "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP"
	out, err := QRTerminal(uri)
	if err != nil {
		t.Fatalf("QRTerminal: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty QR terminal output")
	}
	// Should contain block characters
	if !strings.Contains(out, "█") && !strings.Contains(out, "▀") && !strings.Contains(out, "▄") {
		t.Log("QR output may not contain block chars:", out[:min(len(out), 50)])
	}
}

func TestQRTerminal_EmptyURI(t *testing.T) {
	_, err := QRTerminal("")
	if err == nil {
		t.Fatal("expected error for empty URI")
	}
}

// --- decompression-bomb guards (M5) ---

func TestDecodeQR_OversizedBytes(t *testing.T) {
	data := make([]byte, 6*1024*1024) // 6 MB — exceeds maxQRBytes (5 MB)
	_, err := DecodeQR(data)
	if err == nil {
		t.Fatal("expected error for oversized byte slice")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected error containing 'too large', got: %v", err)
	}
}

// TestDecodeQR_OversizedDimensions encodes a real 1×1 PNG, then patches the
// IHDR width/height fields to 10000 and recomputes the IHDR CRC so that
// image.DecodeConfig reads the forged dimensions without a "corrupt PNG" error.
//
// PNG stream layout:
//
//	bytes  0–7:  PNG signature
//	bytes  8–11: IHDR chunk length = 13 (big-endian)
//	bytes 12–15: chunk type "IHDR"
//	bytes 16–19: width  (big-endian uint32)
//	bytes 20–23: height (big-endian uint32)
//	bytes 24–28: bit-depth, colour-type, compression, filter, interlace
//	bytes 29–32: CRC-32 (IEEE, covers bytes 12–28)
func TestDecodeQR_OversizedDimensions(t *testing.T) {
	// Encode a real 1×1 gray PNG into memory.
	var buf bytebuf
	img1 := image.NewGray(image.Rect(0, 0, 1, 1))
	if err := png.Encode(&buf, img1); err != nil {
		t.Fatalf("encode: %v", err)
	}
	data := buf.Bytes()

	// Patch width (16–19) and height (20–23) to 10000 (0x00002710).
	patchedDim := uint32(10000)
	data[16] = byte(patchedDim >> 24)
	data[17] = byte(patchedDim >> 16)
	data[18] = byte(patchedDim >> 8)
	data[19] = byte(patchedDim)
	data[20] = byte(patchedDim >> 24)
	data[21] = byte(patchedDim >> 16)
	data[22] = byte(patchedDim >> 8)
	data[23] = byte(patchedDim)

	// Recompute IHDR CRC: covers bytes 12–28 (type "IHDR" + 13 data bytes = 17 bytes).
	// CRC field is at bytes 29–32.
	newCRC := crc32.ChecksumIEEE(data[12:29])
	data[29] = byte(newCRC >> 24)
	data[30] = byte(newCRC >> 16)
	data[31] = byte(newCRC >> 8)
	data[32] = byte(newCRC)

	_, err := DecodeQR(data)
	if err == nil {
		t.Fatal("expected error for oversized image dimensions")
	}
	if !strings.Contains(err.Error(), "dimensions") {
		t.Errorf("expected error containing 'dimensions', got: %v", err)
	}
}

// bytebuf is a minimal bytes.Buffer wrapper that satisfies io.Writer for png.Encode.
type bytebuf struct {
	b []byte
}

func (bb *bytebuf) Write(p []byte) (int, error) {
	bb.b = append(bb.b, p...)
	return len(p), nil
}

func (bb *bytebuf) Bytes() []byte { return bb.b }
