package xray

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"xray-panel-server/internal/models"
)

// OutboundConfig represents an Xray outbound configuration.
type OutboundConfig struct {
	Tag            string                 `json:"tag"`
	Protocol       string                 `json:"protocol"`
	Settings       map[string]interface{} `json:"settings,omitempty"`
	StreamSettings *StreamSettings        `json:"streamSettings,omitempty"`
}

func (g *Generator) generateOutbounds() []OutboundConfig {
	outbounds := make([]OutboundConfig, 0)

	strategy := g.directDomainStrategy
	if strategy == "" {
		strategy = "UseIPv4"
	}

	outbounds = append(outbounds, OutboundConfig{
		Tag:      "direct",
		Protocol: "freedom",
		Settings: map[string]interface{}{
			"domainStrategy": strategy,
		},
	})

	outbounds = append(outbounds, OutboundConfig{
		Tag:      "block",
		Protocol: "blackhole",
		Settings: map[string]interface{}{
			"response": map[string]interface{}{
				"type": "http",
			},
		},
	})

	for _, outbound := range g.outbounds {
		if !outbound.Enabled {
			continue
		}
		switch outbound.Type {
		case models.OutboundWireGuard:
			outbounds = append(outbounds, g.generateWireGuardOutbound(outbound))
		case models.OutboundSOCKS5:
			outbounds = append(outbounds, g.generateSOCKS5Outbound(outbound))
		case models.OutboundTrojan:
			outbounds = append(outbounds, g.generateTrojanOutbound(outbound))
		case models.OutboundVLESS:
			outbounds = append(outbounds, g.generateVLESSOutbound(outbound))
		case models.OutboundVMess:
			outbounds = append(outbounds, g.generateVMessOutbound(outbound))
		}
	}

	return outbounds
}

func (g *Generator) generateWireGuardOutbound(outbound models.Outbound) OutboundConfig {
	reserved := []int{0, 0, 0}
	if outbound.WGReserved != "" {
		var parsedReserved []int
		if err := json.Unmarshal([]byte(outbound.WGReserved), &parsedReserved); err == nil && len(parsedReserved) == 3 {
			reserved = parsedReserved
		} else {
			parts := strings.Split(strings.Trim(outbound.WGReserved, "[] "), ",")
			if len(parts) == 3 {
				for i, part := range parts {
					if val, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
						reserved[i] = val
					}
				}
			}
		}
	}

	endpoint := outbound.Server
	if outbound.Port > 0 {
		endpoint = fmt.Sprintf("%s:%d", outbound.Server, outbound.Port)
	}

	addresses := []string{}
	if outbound.WGLocalIPv4 != "" {
		addresses = append(addresses, outbound.WGLocalIPv4)
	}
	if outbound.WGLocalIPv6 != "" {
		addresses = append(addresses, outbound.WGLocalIPv6)
	}

	mtu := outbound.WGMTU
	if mtu == 0 {
		mtu = 1420
	}

	return OutboundConfig{
		Tag:      outbound.Tag,
		Protocol: "wireguard",
		Settings: map[string]interface{}{
			"secretKey": outbound.WGSecretKey,
			"address":   addresses,
			"peers": []map[string]interface{}{
				{
					"publicKey": outbound.WGPublicKey,
					"endpoint":  endpoint,
				},
			},
			"reserved": reserved,
			"mtu":      mtu,
		},
	}
}

func (g *Generator) generateSOCKS5Outbound(outbound models.Outbound) OutboundConfig {
	servers := []map[string]interface{}{
		{
			"address": outbound.Server,
			"port":    outbound.Port,
		},
	}
	if outbound.Username != "" {
		servers[0]["users"] = []map[string]interface{}{
			{
				"user": outbound.Username,
				"pass": outbound.Password,
			},
		}
	}
	return OutboundConfig{
		Tag:      outbound.Tag,
		Protocol: "socks",
		Settings: map[string]interface{}{
			"servers": servers,
		},
	}
}

func (g *Generator) generateTrojanOutbound(outbound models.Outbound) OutboundConfig {
	return OutboundConfig{
		Tag:      outbound.Tag,
		Protocol: "trojan",
		Settings: map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  outbound.Server,
					"port":     outbound.Port,
					"password": outbound.TrojanPassword,
				},
			},
		},
		StreamSettings: g.generateOutboundStreamSettings(outbound),
	}
}

func (g *Generator) generateVLESSOutbound(outbound models.Outbound) OutboundConfig {
	return OutboundConfig{
		Tag:      outbound.Tag,
		Protocol: "vless",
		Settings: map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": outbound.Server,
					"port":    outbound.Port,
					"users": []map[string]interface{}{
						{
							"id":         outbound.UUID,
							"encryption": "none",
							"flow":       outbound.Flow,
						},
					},
				},
			},
		},
		StreamSettings: g.generateOutboundStreamSettings(outbound),
	}
}

func (g *Generator) generateVMessOutbound(outbound models.Outbound) OutboundConfig {
	return OutboundConfig{
		Tag:      outbound.Tag,
		Protocol: "vmess",
		Settings: map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": outbound.Server,
					"port":    outbound.Port,
					"users": []map[string]interface{}{
						{
							"id":       outbound.UUID,
							"security": outbound.Security,
						},
					},
				},
			},
		},
		StreamSettings: g.generateOutboundStreamSettings(outbound),
	}
}

func (g *Generator) generateOutboundStreamSettings(outbound models.Outbound) *StreamSettings {
	if outbound.Network == "" && !outbound.TLS && !outbound.Reality && outbound.TrojanNetwork == "" && outbound.TrojanSNI == "" {
		return nil
	}

	streamSettings := &StreamSettings{Network: "tcp"}

	network := outbound.Network
	if network == "" && outbound.Type == models.OutboundTrojan {
		network = outbound.TrojanNetwork
	}
	if network != "" {
		streamSettings.Network = network
	}

	switch streamSettings.Network {
	case "ws":
		streamSettings.WSSettings = &WSSettings{Path: outbound.Path}
		if outbound.RequestHost != "" {
			streamSettings.WSSettings.Headers = map[string]string{"Host": outbound.RequestHost}
		}
	case "grpc":
		streamSettings.GRPCSettings = &GRPCSettings{
			ServiceName: outbound.ServiceName,
			MultiMode:   true,
		}
	case "xhttp":
		streamSettings.XHTTPSettings = &XHTTPSettings{
			Path: outbound.Path,
			Host: outbound.RequestHost,
			Mode: "auto",
		}
	}

	if outbound.Reality {
		streamSettings.Security = "reality"
		streamSettings.RealitySettings = &RealitySettings{
			Show:        false,
			Fingerprint: "chrome",
			ServerName:  outbound.RealitySNI,
			PublicKey:   outbound.RealityPubKey,
			ShortId:     outbound.RealityShortID,
			SpiderX:     "/",
		}
	} else if outbound.TLS || outbound.Type == models.OutboundTrojan {
		streamSettings.Security = "tls"
		sni := outbound.TLSServerName
		if sni == "" && outbound.Type == models.OutboundTrojan {
			sni = outbound.TrojanSNI
		}
		streamSettings.TLSSettings = &TLSSettings{ServerName: sni}
		if outbound.TLSALPN != "" {
			streamSettings.TLSSettings.ALPN = strings.Split(outbound.TLSALPN, ",")
		}
	}

	return streamSettings
}
