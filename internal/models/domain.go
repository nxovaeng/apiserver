package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DomainType represents the type of domain usage.
type DomainType string

const (
	DomainTypeDirect DomainType = "direct"
	DomainTypeCDN    DomainType = "cdn"
)

// Domain represents a domain used for proxy connections.
type Domain struct {
	ID         string     `json:"id" gorm:"primaryKey"`
	Domain     string     `json:"domain" gorm:"uniqueIndex;not null"`
	Type       DomainType `json:"type" gorm:"default:direct"`
	IsWildcard bool       `json:"is_wildcard" gorm:"default:false"`
	CertPath   string     `json:"cert_path"`
	KeyPath    string     `json:"key_path"`
	Enabled    bool       `json:"enabled"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// BeforeCreate generates UUID for new domain.
func (d *Domain) BeforeCreate(tx *gorm.DB) error {
	if d.ID == "" {
		d.ID = uuid.New().String()
	}
	return nil
}

// NeedsCert returns true if this domain type requires a TLS certificate.
func (d *Domain) NeedsCert() bool {
	return d.Type == DomainTypeDirect || d.Type == DomainTypeCDN
}
