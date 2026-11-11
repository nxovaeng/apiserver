package xray

import (
	"fmt"
	"strings"

	"xray-panel-server/internal/models"
)

// InboundConfig represents an Xray inbound configuration.
type InboundConfig struct {
	Tag            string                 `json:"tag"`
	Listen         string                 `json:"listen,omitempty"`
	Port           interface{}            `json:"port"`
	Protocol       string                 `json:"protocol"`
	Settings       map[string]interface{} `json:"settings,omitempty"`
	StreamSettings *StreamSettings        `json:"streamSettings,omitempty"`
	Sniffing       *SniffingConfig        `json:"sniffing,omitempty"`
}

// StreamSettings represents stream settings.
type StreamSettings struct {
	Network         string           `json:"network"`
	Security        string           `json:"security,omitempty"`
	TLSSettings     *TLSSettings     `json:"tlsSettings,omitempty"`
	RealitySettings *RealitySettings `json:"realitySettings,omitempty"`
	XHTTPSettings   *XHTTPSettings   `json:"xhttpSettings,omitempty"`
	GRPCSettings    *GRPCSettings    `json:"grpcSettings,omitempty"`
	TCPSettings     *TCPSettings     `json:"tcpSettings,omitempty"`
	WSSettings      *WSSettings      `json:"wsSettings,omitempty"`
}

// TLSSettings represents TLS configuration.
type TLSSettings struct {
	ServerName   string    `json:"serverName,omitempty"`
	ALPN         []string  `json:"alpn,omitempty"`
	Certificates []TLSCert `json:"certificates,omitempty"`
}

// TLSCert represents a TLS certificate.
type TLSCert struct {
	CertificateFile string `json:"certificateFile,omitempty"`
	KeyFile         string `json:"keyFile,omitempty"`
}

// RealitySettings represents Reality protocol settings.
type RealitySettings struct {
	Show        bool     `json:"show,omitempty"`
	Dest        string   `json:"dest,omitempty"`
	Xver        int      `json:"xver,omitempty"`
	ServerNames []string `json:"serverNames,omitempty"`
	ServerName  string   `json:"serverName,omitempty"`
	PrivateKey  string   `json:"privateKey,omitempty"`
	PublicKey   string   `json:"publicKey,omitempty"`
	ShortIds    []string `json:"shortIds,omitempty"`
	ShortId     string   `json:"shortId,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	SpiderX     string   `json:"spiderX,omitempty"`
}

// XHTTPSettings represents XHTTP transport settings.
type XHTTPSettings struct {
	Path  string            `json:"path,omitempty"`
	Host  string            `json:"host,omitempty"`
	Mode  string            `json:"mode,omitempty"`
	Extra map[string]string `json:"extra,omitempty"`
}

// GRPCSettings represents gRPC transport settings.
type GRPCSettings struct {
	ServiceName        string `json:"serviceName"`
	MultiMode          bool   `json:"multiMode,omitempty"`
	IdleTimeout        int    `json:"idle_timeout,omitempty"`
	HealthCheckTimeout int    `json:"health_check_timeout,omitempty"`
}

// TCPSettings represents TCP transport settings.
type TCPSettings struct {
	AcceptProxyProtocol bool `json:"acceptProxyProtocol,omitempty"`
}

// WSSettings represents WebSocket transport settings.
type WSSettings struct {
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// SniffingConfig represents sniffing configuration.
type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride,omitempty"`
	RouteOnly    bool     `json:"routeOnly,omitempty"`
}

func (g *Generator) generateInbound(inbound models.Inbound) (*InboundConfig, error) {
	if inbound.Protocol == models.ProtocolWireGuard {
		return g.generateWireGuardInbound(inbound)
	}

	listen := inbound.Listen
	if listen == "" {
		listen = "127.0.0.1"
	}
	var port interface{} = inbound.Port
	if inbound.UseUDS {
		listen = inbound.SocketPath(g.socketDir) + ",0666"
		port = 0
	}

	config := &InboundConfig{
		Tag:      inbound.Tag,
		Listen:   listen,
		Port:     port,
		Protocol: string(inbound.Protocol),
	}

	if g.enableSniffing {
		config.Sniffing = &SniffingConfig{
			Enabled:      true,
			DestOverride: []string{"http", "tls", "quic", "fakedns"},
			RouteOnly:    true,
		}
	}

	switch inbound.Protocol {
	case models.ProtocolVLESS:
		config.Settings = g.generateVLESSSettings()
	case models.ProtocolTrojan:
		config.Settings = g.generateTrojanSettings()
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", inbound.Protocol)
	}

	streamSettings := &StreamSettings{
		Security: "none",
	}

	switch inbound.Transport {
	case models.TransportXHTTP:
		streamSettings.Network = "xhttp"
		streamSettings.XHTTPSettings = &XHTTPSettings{
			Path: inbound.Path,
			Host: inbound.Host,
			Mode: "auto",
		}
	case models.TransportGRPC:
		streamSettings.Network = "grpc"
		streamSettings.GRPCSettings = &GRPCSettings{
			ServiceName: inbound.ServiceName,
			MultiMode:   true,
		}
	case models.TransportWS:
		streamSettings.Network = "ws"
		streamSettings.WSSettings = &WSSettings{
			Path: inbound.Path,
		}
		if inbound.Host != "" {
			streamSettings.WSSettings.Headers = map[string]string{
				"Host": inbound.Host,
			}
		}
	default:
		return nil, fmt.Errorf("unsupported transport: %s", inbound.Transport)
	}

	config.StreamSettings = streamSettings
	return config, nil
}

func (g *Generator) generateVLESSSettings() map[string]interface{} {
	clients := make([]map[string]interface{}, 0)
	for _, user := range g.getActiveUsers() {
		clients = append(clients, map[string]interface{}{
			"id":    user.UUID,
			"flow":  "",
			"email": user.StatsKey(),
			"level": 0,
		})
	}
	return map[string]interface{}{
		"clients":    clients,
		"decryption": "none",
	}
}

func (g *Generator) generateTrojanSettings() map[string]interface{} {
	clients := make([]map[string]interface{}, 0)
	for _, user := range g.getActiveUsers() {
		clients = append(clients, map[string]interface{}{
			"password": user.UUID,
			"email":    user.StatsKey(),
			"level":    0,
		})
	}
	return map[string]interface{}{
		"clients": clients,
	}
}

func (g *Generator) generateWireGuardInbound(inbound models.Inbound) (*InboundConfig, error) {
	if inbound.WGSecretKey == "" {
		return nil, fmt.Errorf("wireguard inbound %q: secret key is required", inbound.Tag)
	}

	mtu := inbound.WGMTU
	if mtu == 0 {
		mtu = 1420
	}

	localIP := inbound.WGLocalIP
	if localIP == "" {
		localIP = "10.0.0.1"
	}
	if idx := strings.Index(localIP, "/"); idx != -1 {
		localIP = localIP[:idx]
	}
	if strings.Contains(localIP, ":") {
		localIP += "/128"
	} else {
		localIP += "/32"
	}

	peers := make([]map[string]interface{}, 0)
	seen := make(map[string]bool)
	for _, user := range g.getActiveUsers() {
		if user.WGPubKey != "" && !seen[user.WGPubKey] {
			seen[user.WGPubKey] = true
			peers = append(peers, map[string]interface{}{
				"publicKey":  user.WGPubKey,
				"allowedIPs": []string{"0.0.0.0/0", "::/0"},
			})
		}
	}
	if inbound.WGPeerPubKey != "" && !seen[inbound.WGPeerPubKey] {
		seen[inbound.WGPeerPubKey] = true
		peers = append(peers, map[string]interface{}{
			"publicKey":  inbound.WGPeerPubKey,
			"allowedIPs": []string{"0.0.0.0/0", "::/0"},
		})
	}

	listen := inbound.Listen
	if listen == "" || listen == "127.0.0.1" {
		listen = "0.0.0.0"
	}

	return &InboundConfig{
		Tag:      inbound.Tag,
		Listen:   listen,
		Port:     inbound.Port,
		Protocol: "wireguard",
		Settings: map[string]interface{}{
			"secretKey": inbound.WGSecretKey,
			"address":   []string{localIP},
			"peers":     peers,
			"mtu":       mtu,
		},
	}, nil
}
