package models

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

// WGServerConfig represents the Linux kernel WireGuard server configuration.
type WGServerConfig struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	InterfaceName string    `json:"interface_name" gorm:"default:wg0"`
	PrivateKey    string    `json:"-"`
	PublicKey     string    `json:"public_key"`
	ListenPort    int       `json:"listen_port" gorm:"default:51820"`
	Address       string    `json:"address" gorm:"default:10.0.0.1/24"`
	MTU           int       `json:"mtu" gorm:"default:1420"`
	EnableNAT     bool      `json:"enable_nat" gorm:"default:false"`
	PostUp        string    `json:"post_up"`
	PostDown      string    `json:"post_down"`
	Enabled       bool      `json:"enabled"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// WGPeer represents a connected client/peer in WireGuard.
type WGPeer struct {
	ID                  uint      `json:"id" gorm:"primaryKey"`
	Name                string    `json:"name" gorm:"not null"`
	PublicKey           string    `json:"public_key" gorm:"not null"`
	PrivateKey          string    `json:"-"`
	PresharedKey        string    `json:"-"`
	AllowedIPs          string    `json:"allowed_ips" gorm:"not null"`
	Endpoint            string    `json:"endpoint,omitempty"`
	PersistentKeepalive int       `json:"persistent_keepalive" gorm:"default:25"`
	Enabled             bool      `json:"enabled"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// DefaultPostUp returns default iptables rules for NAT forwarding and TCP MSS clamping.
func DefaultPostUp(iface string) string {
	if iface == "" {
		iface = "%i"
	}
	return fmt.Sprintf("iptables -I FORWARD 1 -i %s -j ACCEPT; iptables -I FORWARD 1 -o %s -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.0.0.0/8 ! -o %s -j MASQUERADE; iptables -t nat -A POSTROUTING -s 172.16.0.0/12 ! -o %s -j MASQUERADE; iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", iface, iface, iface, iface)
}

// DefaultPostDown returns default teardown iptables rules.
func DefaultPostDown(iface string) string {
	if iface == "" {
		iface = "%i"
	}
	return fmt.Sprintf("iptables -D FORWARD -i %s -j ACCEPT; iptables -D FORWARD -o %s -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.0.0.0/8 ! -o %s -j MASQUERADE; iptables -t nat -D POSTROUTING -s 172.16.0.0/12 ! -o %s -j MASQUERADE; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", iface, iface, iface, iface)
}

// DeriveWGPublicKey derives the WireGuard (Curve25519) public key from base64 private key.
func DeriveWGPublicKey(privKeyB64 string) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privKeyB64))
	if err != nil {
		return "", fmt.Errorf("invalid base64 private key: %w", err)
	}
	privKey, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return "", fmt.Errorf("invalid Curve25519 private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes()), nil
}

// GenerateWGKeyPair generates a Curve25519 keypair and returns (privateKey, publicKey, error).
func GenerateWGKeyPair() (string, string, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}
	privB64 := base64.StdEncoding.EncodeToString(privKey.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes())
	return privB64, pubB64, nil
}

// GetWGServerConfig loads or initializes the singleton server configuration.
func GetWGServerConfig(db *gorm.DB) (*WGServerConfig, error) {
	var cfg WGServerConfig
	err := db.First(&cfg).Error
	if err == nil {
		if strings.Contains(cfg.PostUp, "ip route show default") {
			cfg.PostUp = DefaultPostUp("%i")
			cfg.PostDown = DefaultPostDown("%i")
			_ = db.Save(&cfg)
		}
		return &cfg, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, err
	}

	privKey, pubKey, err := GenerateWGKeyPair()
	if err != nil {
		return nil, err
	}

	cfg = WGServerConfig{
		InterfaceName: "wg0",
		PrivateKey:    privKey,
		PublicKey:     pubKey,
		ListenPort:    51820,
		Address:       "10.0.0.1/24",
		MTU:           1420,
		EnableNAT:     false,
		PostUp:        DefaultPostUp("%i"),
		PostDown:      DefaultPostDown("%i"),
		Enabled:       true,
		UpdatedAt:     time.Now(),
	}

	if err := db.Create(&cfg).Error; err != nil {
		return nil, err
	}
	return &cfg, nil
}

// GetNextAvailableIP scans existing peers and returns the next unused IP (/32) in the subnet.
func GetNextAvailableIP(db *gorm.DB, serverAddress string) string {
	ipStr := serverAddress
	if idx := strings.Index(ipStr, "/"); idx != -1 {
		ipStr = ipStr[:idx]
	}
	serverIP := net.ParseIP(ipStr).To4()
	if serverIP == nil {
		return "10.0.0.2/32"
	}

	var peers []WGPeer
	db.Select("allowed_ips").Find(&peers)

	usedLastOctets := make(map[byte]bool)
	usedLastOctets[serverIP[3]] = true

	for _, p := range peers {
		for _, rawIP := range strings.Split(p.AllowedIPs, ",") {
			rawIP = strings.TrimSpace(rawIP)
			if idx := strings.Index(rawIP, "/"); idx != -1 {
				rawIP = rawIP[:idx]
			}
			pip := net.ParseIP(rawIP).To4()
			if pip != nil && pip[0] == serverIP[0] && pip[1] == serverIP[1] && pip[2] == serverIP[2] {
				usedLastOctets[pip[3]] = true
			}
		}
	}

	for octet := 2; octet <= 254; octet++ {
		if !usedLastOctets[byte(octet)] {
			return fmt.Sprintf("%d.%d.%d.%d/32", serverIP[0], serverIP[1], serverIP[2], octet)
		}
	}

	return fmt.Sprintf("%d.%d.%d.2/32", serverIP[0], serverIP[1], serverIP[2])
}

// ParsePort parses port string safely with fallback.
func ParsePort(portStr string, defaultPort int) int {
	p, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil || p <= 0 || p > 65535 {
		return defaultPort
	}
	return p
}
