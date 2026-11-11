package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Protocol represents the proxy protocol type.
type Protocol string

const (
	ProtocolVLESS     Protocol = "vless"
	ProtocolTrojan    Protocol = "trojan"
	ProtocolWireGuard Protocol = "wireguard"
)

// Transport represents the transport layer type.
type Transport string

const (
	TransportWS    Transport = "ws"
	TransportGRPC  Transport = "grpc"
	TransportXHTTP Transport = "xhttp"
	TransportRAW   Transport = "raw"
)

// Security represents the TLS/security type.
type Security string

const (
	SecurityNone Security = "none"
)

// Inbound represents an Xray inbound configuration.
type Inbound struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	Tag       string    `json:"tag" gorm:"uniqueIndex;not null"`
	Protocol  Protocol  `json:"protocol" gorm:"default:vless"`
	Transport Transport `json:"transport" gorm:"not null"`
	Port      int       `json:"port" gorm:"not null"`
	Listen    string    `json:"listen" gorm:"default:127.0.0.1"`

	DomainID string  `json:"domain_id"`
	Domain   *Domain `json:"domain,omitempty" gorm:"foreignKey:DomainID"`

	Path        string `json:"path"`
	ServiceName string `json:"service_name"`
	Host        string `json:"host"`
	Mode        string `json:"mode"`

	ActualDomain  string `json:"actual_domain"`
	CustomSNI     string `json:"custom_sni"`
	ConnectDomain string `json:"connect_domain"`

	WGSecretKey  string `json:"-"`
	WGPublicKey  string `json:"wg_public_key"`
	WGPeerPubKey string `json:"wg_peer_pub_key"`
	WGMTU        int    `json:"wg_mtu"`
	WGLocalIP    string `json:"wg_local_ip"`

	ExcludeFromSub bool `json:"exclude_from_sub" gorm:"default:false"`

	Enabled   bool      `json:"enabled" gorm:"index"`
	UseUDS    bool      `json:"use_uds"`
	Remark    string    `json:"remark"`
	CreatedAt time.Time `json:"created_at" gorm:"index"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BeforeCreate generates ID and default Tag for new inbound.
func (i *Inbound) BeforeCreate(tx *gorm.DB) error {
	if i.ID == "" {
		i.ID = uuid.New().String()
	}
	if i.Tag == "" {
		i.Tag = "inbound-" + i.ID[:8]
	}
	return nil
}

func (i *Inbound) IsGRPC() bool      { return i.Transport == TransportGRPC }
func (i *Inbound) IsXHTTP() bool     { return i.Transport == TransportXHTTP }
func (i *Inbound) IsWS() bool        { return i.Transport == TransportWS }
func (i *Inbound) IsTrojan() bool    { return i.Protocol == ProtocolTrojan }
func (i *Inbound) IsVLESS() bool     { return i.Protocol == ProtocolVLESS }
func (i *Inbound) IsWireGuard() bool { return i.Protocol == ProtocolWireGuard }

// SocketPath returns the Unix Domain Socket path for this inbound.
func (i *Inbound) SocketPath(socketDir string) string {
	if socketDir == "" {
		socketDir = "/dev/shm"
	}
	return fmt.Sprintf("%s/xray-%s.sock", socketDir, i.Tag)
}
