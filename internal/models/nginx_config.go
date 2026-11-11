package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// NginxConfig represents a generated Nginx configuration file tracked in SQLite.
type NginxConfig struct {
	ID         string    `json:"id" gorm:"primaryKey"`
	InboundID  string    `json:"inbound_id" gorm:"index"`
	Inbound    *Inbound  `json:"inbound,omitempty" gorm:"foreignKey:InboundID"`
	Domain     string    `json:"domain"`
	ConfigPath string    `json:"config_path"`
	ConfigType string    `json:"config_type" gorm:"default:http"`
	IsManaged  bool      `json:"is_managed" gorm:"default:true"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// BeforeCreate generates UUID for new nginx config.
func (n *NginxConfig) BeforeCreate(tx *gorm.DB) error {
	if n.ID == "" {
		n.ID = uuid.New().String()
	}
	return nil
}
