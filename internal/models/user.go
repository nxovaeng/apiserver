package models

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a proxy user with traffic and time limits.
type User struct {
	ID           string     `json:"id" gorm:"primaryKey"`
	UUID         string     `json:"uuid" gorm:"uniqueIndex;not null"`
	Name         string     `json:"name" gorm:"not null"`
	Email        string     `json:"email" gorm:"index"`
	TrafficLimit int64      `json:"traffic_limit"`
	TrafficUsed  int64      `json:"traffic_used"`
	TrafficReset *time.Time `json:"traffic_reset"`
	ExpiryDate   *time.Time `json:"expiry_date" gorm:"index"`
	Enabled      bool       `json:"enabled" gorm:"index"`
	SubPath      string     `json:"sub_path" gorm:"uniqueIndex;not null"`
	Note         string     `json:"note"`
	WGPubKey     string     `json:"wg_pub_key"`
	CreatedAt    time.Time  `json:"created_at" gorm:"index"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// BeforeCreate generates ID, UUID, and subscription path for new users.
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	if u.UUID == "" {
		u.UUID = uuid.New().String()
	}
	if u.SubPath == "" {
		u.SubPath = generateSubPath(12)
	}
	return nil
}

// generateSubPath generates a random unambiguous subscription path token.
func generateSubPath(length int) string {
	const charset = "abcdefghjkmnpqrstuvwxyz23456789"
	maxIdx := big.NewInt(int64(len(charset)))
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, maxIdx)
		if err != nil {
			b[i] = charset[int(uuid.New()[0])%len(charset)]
			continue
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

// StatsKey returns the stable identifier used as Xray stats email key.
func (u *User) StatsKey() string {
	return u.ID
}

// IsActive checks if user is enabled, not expired, and within traffic quota.
func (u *User) IsActive() bool {
	if !u.Enabled {
		return false
	}
	if u.ExpiryDate != nil && !u.ExpiryDate.IsZero() && time.Now().After(*u.ExpiryDate) {
		return false
	}
	if u.TrafficLimit > 0 && u.TrafficUsed >= u.TrafficLimit {
		return false
	}
	return true
}

// RemainingTraffic returns remaining traffic in bytes, or -1 if unlimited.
func (u *User) RemainingTraffic() int64 {
	if u.TrafficLimit == 0 {
		return -1
	}
	remaining := u.TrafficLimit - u.TrafficUsed
	if remaining < 0 {
		return 0
	}
	return remaining
}

// RemainingDays returns days until expiry, or -1 if never expires.
func (u *User) RemainingDays() int {
	if u.ExpiryDate == nil || u.ExpiryDate.IsZero() {
		return -1
	}
	days := int(time.Until(*u.ExpiryDate).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}
