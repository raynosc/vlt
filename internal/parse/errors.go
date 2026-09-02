// Package parse provides pure certificate/key format detection and metadata extraction.
//
// The package has ZERO I/O, ZERO store dependencies, and ZERO crypto dependencies beyond
// the Go standard library and golang.org/x/crypto/ssh. All functions accept []byte input
// and return structured Metadata or an error.
package parse

import "errors"

// Sentinel errors returned by parse operations.
var (
	// ErrEmptyInput is returned when the input data is empty.
	ErrEmptyInput = errors.New("empty input")

	// ErrInvalidPEM is returned when the input is not valid PEM data.
	ErrInvalidPEM = errors.New("invalid PEM data")

	// ErrNotX509 is returned when the input is not an X.509 certificate.
	ErrNotX509 = errors.New("not an X.509 certificate")

	// ErrNotSSH is returned when the input is not an SSH key.
	ErrNotSSH = errors.New("not an SSH key")

	// ErrWrongPassword is returned when a PKCS#12 bundle has the wrong password.
	ErrWrongPassword = errors.New("wrong password for PKCS12 bundle")

	// ErrUnsupportedKeyType is returned when an SSH key type is not supported.
	ErrUnsupportedKeyType = errors.New("unsupported SSH key type")
)
