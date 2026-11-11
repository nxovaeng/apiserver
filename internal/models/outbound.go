package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// OutboundType represents the type of outbound connection.
type OutboundType string

const (
	OutboundDirect    OutboundType = "direct"
	OutboundSOCKS5    OutboundType = "socks5"
	OutboundWireGuard OutboundType = "wireguard"
	OutboundTrojan    OutboundType = "trojan"
	OutboundBlackhole OutboundType = "blackhole"
	OutboundVLESS     OutboundType = "vless"
	OutboundVMess     OutboundType = "vmess"
)

// Outbound represents an Xray outbound configuration.
type Outbound struct {
	ID   string       `json:"id" gorm:"primaryKey"`
	Tag  string       `json:"tag" gorm:"uniqueIndex;not null"`
	Type OutboundType `json:"type" gorm:"not null"`

	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"-"`

	WGSecretKey    string `json:"-"`
	WGClientPubKey string `json:"wg_client_pub_key" gorm:"column:wg_client_pub_key"`
	WGPublicKey    string `json:"wg_public_key"`
	WGReserved     string `json:"wg_reserved"`
	WGLocalIPv4    string `json:"wg_local_ipv4"`
	WGLocalIPv6    string `json:"wg_local_ipv6"`
	WGMTU          int    `json:"wg_mtu"`
	WGDNS          string `json:"wg_dns"`

	TrojanPassword string `json:"-"`
	TrojanSNI      string `json:"trojan_sni"`
	TrojanNetwork  string `json:"trojan_network"`

	UUID     string `json:"uuid"`
	Flow     string `json:"flow"`
	Security string `json:"security"`

	Network     string `json:"network"`
	HeaderType  string `json:"header_type"`
	RequestHost string `json:"request_host"`
	Path        string `json:"path"`
	ServiceName string `json:"service_name"`

	TLS            bool   `json:"tls"`
	TLSServerName  string `json:"tls_server_name"`
	TLSALPN        string `json:"tls_alpn"`
	Reality        bool   `json:"reality"`
	RealityPubKey  string `json:"reality_pubkey"`
	RealityShortID string `json:"reality_short_id"`
	RealitySNI     string `json:"reality_sni"`

	Enabled   bool      `json:"enabled"`
	Priority  int       `json:"priority" gorm:"default:0"`
	Remark    string    `json:"remark"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BeforeCreate generates ID and default Tag for new outbound.
func (o *Outbound) BeforeCreate(tx *gorm.DB) error {
	if o.ID == "" {
		o.ID = uuid.New().String()
	}
	if o.Tag == "" {
		o.Tag = string(o.Type) + "-" + o.ID[:8]
	}
	return nil
}

func (o *Outbound) IsDirect() bool    { return o.Type == OutboundDirect }
func (o *Outbound) IsWireGuard() bool { return o.Type == OutboundWireGuard }
func (o *Outbound) IsTrojan() bool    { return o.Type == OutboundTrojan }
func (o *Outbound) IsSOCKS5() bool    { return o.Type == OutboundSOCKS5 }
func (o *Outbound) IsBlackhole() bool { return o.Type == OutboundBlackhole }
func (o *Outbound) IsVLESS() bool     { return o.Type == OutboundVLESS }
func (o *Outbound) IsVMess() bool     { return o.Type == OutboundVMess }
