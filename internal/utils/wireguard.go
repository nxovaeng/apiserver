package utils

import "xray-panel-server/internal/models"

// DeriveWGPublicKey derives the WireGuard (Curve25519) public key from a base64-encoded private key.
func DeriveWGPublicKey(privKeyB64 string) (string, error) {
	return models.DeriveWGPublicKey(privKeyB64)
}

// GenerateWGKeyPair generates a Curve25519 key pair (privateKey, publicKey).
func GenerateWGKeyPair() (string, string, error) {
	return models.GenerateWGKeyPair()
}
