package proton

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// GenerateVPNKeys generates a WireGuard-compatible private key and Ed25519 SubjectPublicKeyInfo PEM.
// 1. 32-byte CSPRNG seed.
// 2. WireGuard private key: SHA-512(seed), clamped (h[0] &= 248, h[31] &= 127, h[31] |= 64), first 32 bytes base64.
// 3. Ed25519 public key derived from seed.
// 4. PEM SubjectPublicKeyInfo (DER prefix 302a300506032b6570032100 + 32 bytes pubkey).
func GenerateVPNKeys() (string, string, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return "", "", fmt.Errorf("crypto rand failed: %w", err)
	}

	// WireGuard private key from Ed25519 seed
	h512 := sha512.Sum512(seed)
	var wgBytes [32]byte
	copy(wgBytes[:], h512[:32])
	wgBytes[0] &= 248
	wgBytes[31] &= 127
	wgBytes[31] |= 64
	wgPrivKeyB64 := base64.StdEncoding.EncodeToString(wgBytes[:])

	// Ed25519 public key
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey, ok := privKey.Public().(ed25519.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("failed to derive Ed25519 public key")
	}

	// DER SubjectPublicKeyInfo prefix for Ed25519 (RFC 8410)
	derPrefix := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	spki := append(derPrefix, pubKey...)
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: spki,
	}
	pemStr := string(pem.EncodeToMemory(pemBlock))

	return wgPrivKeyB64, pemStr, nil
}
