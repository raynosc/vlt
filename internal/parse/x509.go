package parse

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"time"
)

// ParseX509 parses a PEM- or DER-encoded X.509 certificate.
//
// For PEM input, only the first certificate block is parsed (certificate
// chains are handled by extracting the leaf cert).
//
// Returns ErrEmptyInput for empty data, ErrInvalidPEM for non-PEM/non-DER data,
// and ErrNotX509 for PEM blocks that are not certificates.
func ParseX509(data []byte) (*Metadata, error) {
	if len(data) == 0 {
		return nil, ErrEmptyInput
	}

	var cert *x509.Certificate
	var err error

	// Try PEM first
	block, rest := pem.Decode(data)
	if block == nil {
		// No PEM block — try DER directly
		cert, err = x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidPEM, err)
		}
	} else if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: expected CERTIFICATE, got %s", ErrNotX509, block.Type)
	} else {
		cert, err = x509.ParseCertificate(block.Bytes)
		_ = rest // parse first cert only; rest is the chain
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotX509, err)
		}
	}

	return buildX509Metadata(cert), nil
}

func buildX509Metadata(cert *x509.Certificate) *Metadata {
	m := &Metadata{
		Format:             FormatX509PEM.String(),
		SubjectCN:          cert.Subject.CommonName,
		IssuerCN:           cert.Issuer.CommonName,
		NotBefore:          cert.NotBefore.Format(time.RFC3339),
		NotAfter:           cert.NotAfter.Format(time.RFC3339),
		SerialNumber:       cert.SerialNumber.String(),
		FingerprintSHA1:    fingerprint(cert.Raw, sha1.New),
		FingerprintSHA256:  fingerprint(cert.Raw, sha256.New),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
	}

	// SANs: DNS names, IP addresses, email addresses, URIs
	m.SANs = append(m.SANs, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		m.SANs = append(m.SANs, ip.String())
	}
	m.SANs = append(m.SANs, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		m.SANs = append(m.SANs, uri.String())
	}

	m.KeyUsage = formatKeyUsage(cert.KeyUsage)
	m.ExtKeyUsage = formatExtKeyUsage(cert.ExtKeyUsage)

	return m
}

// fingerprint computes the hex-encoded hash of raw certificate bytes.
func fingerprint(raw []byte, h func() hash.Hash) string {
	hasher := h()
	hasher.Write(raw)
	return hex.EncodeToString(hasher.Sum(nil))
}

func formatKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "digital_signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "content_commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "key_encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "data_encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "key_agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "cert_sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "crl_sign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "encipher_only")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "decipher_only")
	}
	return usages
}

func formatExtKeyUsage(eku []x509.ExtKeyUsage) []string {
	names := make([]string, len(eku))
	for i, u := range eku {
		switch u {
		case x509.ExtKeyUsageAny:
			names[i] = "any"
		case x509.ExtKeyUsageServerAuth:
			names[i] = "server_auth"
		case x509.ExtKeyUsageClientAuth:
			names[i] = "client_auth"
		case x509.ExtKeyUsageCodeSigning:
			names[i] = "code_signing"
		case x509.ExtKeyUsageEmailProtection:
			names[i] = "email_protection"
		case x509.ExtKeyUsageIPSECEndSystem:
			names[i] = "ipsec_end_system"
		case x509.ExtKeyUsageIPSECTunnel:
			names[i] = "ipsec_tunnel"
		case x509.ExtKeyUsageIPSECUser:
			names[i] = "ipsec_user"
		case x509.ExtKeyUsageTimeStamping:
			names[i] = "time_stamping"
		case x509.ExtKeyUsageOCSPSigning:
			names[i] = "ocsp_signing"
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			names[i] = "microsoft_server_gated_crypto"
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			names[i] = "netscape_server_gated_crypto"
		default:
			names[i] = fmt.Sprintf("unknown(%d)", u)
		}
	}
	return names
}
