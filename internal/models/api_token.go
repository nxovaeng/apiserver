package models

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	// APITokenPrefix is the standard prefix for all generated API tokens.
	APITokenPrefix = "xrp_"
	// APITokenRandomBytes is 36 CSPRNG bytes -> 48 base64url chars (no padding).
	APITokenRandomBytes = 36
	// APITokenSaltBytes is the per-token random salt length (32 bytes, hex-encoded for storage).
	APITokenSaltBytes = 32
)

// APIToken represents a revocable static Bearer API token.
// Plaintext tokens are never stored; only a salted SHA-256 hash (see
// HashAPITokenWithSalt), the hex-encoded per-token salt, and a display prefix
// are persisted. Rows created before salting have an empty Salt and are
// verified once against the legacy unsalted hash, then upgraded in place
// (see TokenService.Authenticate).
type APIToken struct {
	ID          string     `json:"id" gorm:"primaryKey"`
	Name        string     `json:"name" gorm:"not null;index"`
	TokenPrefix string     `json:"token_prefix" gorm:"not null"`
	TokenHash   string     `json:"-" gorm:"uniqueIndex;not null"`
	Salt        string     `json:"-" gorm:"not null;default:''"`
	ExpiresAt   *time.Time `json:"expires_at" gorm:"index"`
	Revoked     bool       `json:"revoked" gorm:"default:false;index"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	LastIP      string     `json:"last_ip"`
	CreatedAt   time.Time  `json:"created_at" gorm:"index"`
}

// BeforeCreate ensures a UUID primary key is set.
func (t *APIToken) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return nil
}

// IsValid reports whether the token is not revoked and not expired at now.
func (t *APIToken) IsValid(now time.Time) bool {
	if t.Revoked {
		return false
	}
	if t.ExpiresAt != nil && now.After(*t.ExpiresAt) {
		return false
	}
	return true
}

// GenerateAPIToken creates a CSPRNG token formatted as "xrp_<48 chars>",
// along with its display prefix, salted SHA-256 hex digest, and the
// hex-encoded per-token salt.
func GenerateAPIToken() (raw string, prefix string, hash string, salt string, err error) {
	buf := make([]byte, APITokenRandomBytes)
	if _, err = rand.Read(buf); err != nil {
		return "", "", "", "", fmt.Errorf("failed to read CSPRNG: %w", err)
	}
	saltBuf := make([]byte, APITokenSaltBytes)
	if _, err = rand.Read(saltBuf); err != nil {
		return "", "", "", "", fmt.Errorf("failed to read CSPRNG: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(buf)
	raw = APITokenPrefix + encoded
	prefix = TokenDisplayPrefix(raw)
	salt = hex.EncodeToString(saltBuf)
	hash, err = HashAPITokenWithSalt(raw, salt)
	if err != nil {
		return "", "", "", "", err
	}
	return raw, prefix, hash, salt, nil
}

// TokenDisplayPrefix extracts a non-sensitive display prefix like "xrp_9a3f1b2c...".
func TokenDisplayPrefix(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) <= 12 {
		return trimmed
	}
	return trimmed[:12] + "..."
}

// HashAPIToken computes the lowercase SHA-256 hex digest of a raw token.
func HashAPIToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// HashAPITokenWithSalt computes hex(SHA-256(saltBytes || rawToken)), where
// saltHex is the hex-encoded per-token salt stored in APIToken.Salt.
func HashAPITokenWithSalt(raw, saltHex string) (string, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", fmt.Errorf("invalid token salt: %w", err)
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(raw))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// NewSalt generates a fresh hex-encoded random salt of APITokenSaltBytes.
func NewSalt() (string, error) {
	buf := make([]byte, APITokenSaltBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to read CSPRNG: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
