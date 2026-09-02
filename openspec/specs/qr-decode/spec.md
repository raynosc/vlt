# Delta for qr-decode

## MODIFIED Requirements

### Requirement: QR Image Decode

The system MUST decode a QR code from a PNG image and extract the contained URI string.
The system MUST enforce input-size and dimension guards BEFORE invoking full image decoding,
so that crafted images cannot exhaust process memory.

(Previously: no size or dimension check; full decode was attempted on any input.)

#### Scenario: Decode — normal small QR (unchanged, regression guard)

- GIVEN a valid PNG file under 5 MB with dimensions ≤ 4096×4096 containing an `otpauth://totp/` QR code
- WHEN `DecodeQR(data)` is called
- THEN the URI string is returned without error

#### Scenario: No QR — (unchanged)

- GIVEN a valid PNG with no QR code, under size and dimension limits
- WHEN decode is attempted
- THEN an error "No QR code found" is returned

#### Scenario: Corrupted image — (unchanged)

- GIVEN a corrupted image file
- WHEN decode is attempted
- THEN an error is returned (image decode failure)

#### Scenario: M5 — byte-size cap rejects oversized payload

- GIVEN a byte slice whose length exceeds 5,242,880 bytes (5 MB)
- WHEN `DecodeQR(data)` is called
- THEN an error is returned before any image decoding begins
- AND the returned error message indicates the payload is too large

#### Scenario: M5 — dimension cap rejects decompression bomb via DecodeConfig

- GIVEN a syntactically valid image whose IHDR header declares dimensions greater than 4096×4096 (e.g. 10000×10000)
- WHEN `DecodeQR(data)` is called
- THEN `image.DecodeConfig` is used to inspect the header first
- AND an error is returned before `image.Decode` is called
- AND the returned error message indicates dimensions are out of range

#### Scenario: M5 — exactly-at-limit image is accepted

- GIVEN a valid image whose byte length is exactly 5,242,880 bytes and whose dimensions are exactly 4096×4096
- WHEN `DecodeQR(data)` is called
- THEN the function proceeds to decode (no size/dimension error is returned at this boundary)
