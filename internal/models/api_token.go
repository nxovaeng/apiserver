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
)

// APIToken represents a revocable static Bearer API token.
// Plaintext tokens are never stored; only a SHA-256 hash and a display prefix are persisted.
type APIToken struct {
	ID          string     `json:"id" gorm:"primaryKey"`
	Name        string     `json:"name" gorm:"not null;index"`
	TokenPrefix string     `json:"token_prefix" gorm:"not null"`
	TokenHash   string     `json:"-" gorm:"uniqueIndex;not null"`
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
// along with its display prefix and SHA-256 hex digest.
func GenerateAPIToken() (raw string, prefix string, hash string, err error) {
	buf := make([]byte, APITokenRandomBytes)
	if _, err = rand.Read(buf); err != nil {
		return "", "", "", fmt.Errorf("failed to read CSPRNG: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(buf)
	raw = APITokenPrefix + encoded
	prefix = TokenDisplayPrefix(raw)
	hash = HashAPIToken(raw)
	return raw, prefix, hash, nil
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
