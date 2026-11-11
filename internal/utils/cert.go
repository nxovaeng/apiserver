package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

// ParseCertificateExpiry reads and parses certificate info from a PEM file to get expiration date.
func ParseCertificateExpiry(certPath string) (time.Time, error) {
	_, expiry, _, _, err := ParseCertificateDetails(certPath)
	return expiry, err
}

// ParseCertificateDetails reads and parses detailed certificate info from a PEM file.
// Returns issuer, expiry, SANs, whether it is a wildcard certificate, and any error.
func ParseCertificateDetails(certPath string) (issuer string, expiry time.Time, sans []string, isWildcard bool, err error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return
	}
	return ParseCertificateDetailsFromBytes(data, certPath)
}

// ParseCertificateDetailsFromBytes parses detailed certificate info from raw PEM bytes.
func ParseCertificateDetailsFromBytes(data []byte, sourceLabel string) (issuer string, expiry time.Time, sans []string, isWildcard bool, err error) {
	block, _ := pem.Decode(data)
	if block == nil {
		err = fmt.Errorf("failed to decode PEM block from %s", sourceLabel)
		return
	}

	cert, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		err = parseErr
		return
	}

	issuer = cert.Issuer.CommonName
	expiry = cert.NotAfter

	seen := make(map[string]bool)
	if cert.Subject.CommonName != "" {
		sans = append(sans, cert.Subject.CommonName)
		seen[cert.Subject.CommonName] = true
	}
	for _, name := range cert.DNSNames {
		if !seen[name] {
			sans = append(sans, name)
			seen[name] = true
		}
	}

	for _, name := range sans {
		if strings.HasPrefix(name, "*.") {
			isWildcard = true
			break
		}
	}

	return
}
