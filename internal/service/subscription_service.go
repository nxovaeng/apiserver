package service

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"gorm.io/gorm"

	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
)

// SubscriptionOutput encapsulates formatted subscription payload and metadata headers.
type SubscriptionOutput struct {
	StatusCode  int
	ContentType string
	Disposition string
	UserInfo    string
	ProfileName string
	TextBody    string
	JSONBody    *dto.SubscriptionJSONResponse
}

// SubscriptionService generates aggregated subscriptions for active users.
type SubscriptionService struct {
	db *gorm.DB
}

func NewSubscriptionService(db *gorm.DB) *SubscriptionService {
	return &SubscriptionService{db: db}
}

func (s *SubscriptionService) Generate(subPath, format string) (*SubscriptionOutput, error) {
	if format == "" {
		format = "base64"
	}

	var user models.User
	if err := s.db.Where("sub_path = ?", subPath).First(&user).Error; err != nil {
		return nil, NewNotFoundError("Subscription not found")
	}

	if !user.IsActive() {
		return nil, NewForbiddenError("Subscription expired or disabled")
	}

	var inbounds []models.Inbound
	if err := s.db.Preload("Domain").Where("enabled = ?", true).Find(&inbounds).Error; err != nil {
		return nil, NewInternalError("Failed to generate subscription", err)
	}

	links := make([]string, 0, len(inbounds))
	for _, inbound := range inbounds {
		if inbound.ExcludeFromSub {
			continue
		}
		var link string
		switch inbound.Protocol {
		case models.ProtocolTrojan:
			link = generateTrojanLink(user, inbound)
		case models.ProtocolVLESS:
			link = generateVLESSLink(user, inbound)
		}
		if link != "" {
			links = append(links, link)
		}
	}

	uploadBytes := int64(0)
	downloadBytes := user.TrafficUsed
	totalBytes := user.TrafficLimit
	expireTime := int64(0)
	if user.ExpiryDate != nil && !user.ExpiryDate.IsZero() {
		expireTime = user.ExpiryDate.Unix()
	}

	subInfo := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d",
		uploadBytes, downloadBytes, totalBytes, expireTime)
	filename := sanitizeSubFilename(user)
	joined := strings.Join(links, "\n")

	out := &SubscriptionOutput{
		StatusCode:  http.StatusOK,
		UserInfo:    subInfo,
		ProfileName: fmt.Sprintf("Xray - %s", user.Name),
	}

	switch format {
	case "base64":
		out.ContentType = "text/plain; charset=utf-8"
		out.Disposition = fmt.Sprintf("attachment; filename=%s.txt", filename)
		out.TextBody = base64.StdEncoding.EncodeToString([]byte(joined))
	case "plain", "txt", "t":
		out.ContentType = "text/plain; charset=utf-8"
		out.Disposition = fmt.Sprintf("attachment; filename=%s.txt", filename)
		out.TextBody = joined
	case "json", "j":
		out.ContentType = "application/json; charset=utf-8"
		out.JSONBody = &dto.SubscriptionJSONResponse{
			Links: links,
			Count: len(links),
			User: dto.SubscriptionUserSummary{
				Name:             user.Name,
				Email:            user.Email,
				UUID:             user.UUID,
				Upload:           uploadBytes,
				Download:         downloadBytes,
				Total:            totalBytes,
				Expire:           expireTime,
				TrafficUsed:      user.TrafficUsed,
				TrafficLimit:     user.TrafficLimit,
				RemainingDays:    user.RemainingDays(),
				RemainingTraffic: user.RemainingTraffic(),
				IsActive:         user.IsActive(),
			},
		}
	case "yaml", "y", "clash":
		out.ContentType = "text/yaml; charset=utf-8"
		out.Disposition = fmt.Sprintf("attachment; filename=%s.yaml", filename)
		out.TextBody = generateClashConfig(user, inbounds)
	default:
		return nil, NewValidationError("Unknown format. Supported: base64, txt, json, yaml")
	}

	return out, nil
}

func sanitizeSubFilename(user models.User) string {
	filename := user.Name
	if filename == "" {
		filename = user.Email
	}
	if filename == "" {
		filename = "subscription"
	}
	res := strings.Map(func(r rune) rune {
		if r == ' ' {
			return '_'
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return -1
	}, filename)
	if res == "" {
		return "subscription"
	}
	return res
}

func resolveInboundDomains(inbound models.Inbound) (sniDomain, connectDomain string, ok bool) {
	if inbound.Domain != nil {
		sniDomain = inbound.Domain.Domain
		if inbound.ActualDomain != "" {
			sniDomain = inbound.ActualDomain
		}
	} else if inbound.CustomSNI != "" {
		sniDomain = inbound.CustomSNI
	} else {
		return "", "", false
	}

	connectDomain = sniDomain
	if inbound.ConnectDomain != "" {
		connectDomain = inbound.ConnectDomain
	}
	return sniDomain, connectDomain, true
}

func generateVLESSLink(user models.User, inbound models.Inbound) string {
	sniDomain, connectDomain, ok := resolveInboundDomains(inbound)
	if !ok {
		return ""
	}

	params := url.Values{}
	params.Set("type", string(inbound.Transport))
	params.Set("encryption", "none")
	params.Set("security", "tls")
	params.Set("sni", sniDomain)
	params.Set("fp", "chrome")

	applyTransportParams(params, inbound)

	remark := inbound.Remark
	if remark == "" {
		remark = fmt.Sprintf("%s-%s-%s", sniDomain, inbound.Protocol, inbound.Transport)
	}

	return fmt.Sprintf("vless://%s@%s:443?%s#%s",
		user.UUID, connectDomain, params.Encode(), url.PathEscape(remark))
}

func generateTrojanLink(user models.User, inbound models.Inbound) string {
	sniDomain, connectDomain, ok := resolveInboundDomains(inbound)
	if !ok {
		return ""
	}

	params := url.Values{}
	params.Set("type", string(inbound.Transport))
	params.Set("security", "tls")
	params.Set("sni", sniDomain)
	params.Set("fp", "chrome")

	applyTransportParams(params, inbound)

	remark := inbound.Remark
	if remark == "" {
		remark = fmt.Sprintf("%s-%s-%s", sniDomain, inbound.Protocol, inbound.Transport)
	}

	return fmt.Sprintf("trojan://%s@%s:443?%s#%s",
		user.UUID, connectDomain, params.Encode(), url.PathEscape(remark))
}

func applyTransportParams(params url.Values, inbound models.Inbound) {
	switch inbound.Transport {
	case models.TransportXHTTP:
		params.Set("alpn", "h2")
		params.Set("path", inbound.Path)
		if inbound.Host != "" {
			params.Set("host", inbound.Host)
		}
		params.Set("mode", "auto")
	case models.TransportGRPC:
		params.Set("alpn", "h2")
		params.Set("serviceName", inbound.ServiceName)
		params.Set("mode", "multi")
	case models.TransportWS:
		params.Set("alpn", "http/1.1")
		params.Set("path", inbound.Path)
		if inbound.Host != "" {
			params.Set("host", inbound.Host)
		}
	}
}

func generateClashConfig(user models.User, inbounds []models.Inbound) string {
	var sb strings.Builder

	sb.WriteString("# Clash Configuration\n")
	sb.WriteString(fmt.Sprintf("# User: %s\n", user.Name))
	sb.WriteString("# Generated by Xray Panel\n\n")
	sb.WriteString("proxies:\n")

	for _, inbound := range inbounds {
		if inbound.ExcludeFromSub || inbound.Protocol == models.ProtocolWireGuard {
			continue
		}
		sniDomain, connectDomain, ok := resolveInboundDomains(inbound)
		if !ok {
			continue
		}

		name := inbound.Remark
		if name == "" {
			name = fmt.Sprintf("%s-%s", sniDomain, inbound.Transport)
		}

		sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n", name))
		if inbound.Protocol == models.ProtocolTrojan {
			sb.WriteString("    type: trojan\n")
		} else {
			sb.WriteString("    type: vless\n")
		}
		sb.WriteString(fmt.Sprintf("    server: %s\n", connectDomain))
		sb.WriteString("    port: 443\n")
		if inbound.Protocol == models.ProtocolTrojan {
			sb.WriteString(fmt.Sprintf("    password: %s\n", user.UUID))
		} else {
			sb.WriteString(fmt.Sprintf("    uuid: %s\n", user.UUID))
			sb.WriteString("    cipher: none\n")
		}

		sb.WriteString(fmt.Sprintf("    network: %s\n", inbound.Transport))
		sb.WriteString("    tls: true\n")
		sb.WriteString(fmt.Sprintf("    servername: %s\n", sniDomain))
		sb.WriteString("    client-fingerprint: chrome\n")
		sb.WriteString("    alpn:\n      - h2\n      - http/1.1\n")

		switch inbound.Transport {
		case models.TransportXHTTP:
			sb.WriteString("    xhttp-opts:\n")
			sb.WriteString(fmt.Sprintf("      path: %s\n", inbound.Path))
			if inbound.Host != "" {
				sb.WriteString(fmt.Sprintf("      host: %s\n", inbound.Host))
			}
		case models.TransportWS:
			sb.WriteString("    ws-opts:\n")
			sb.WriteString(fmt.Sprintf("      path: %s\n", inbound.Path))
			if inbound.Host != "" {
				sb.WriteString("      headers:\n")
				sb.WriteString(fmt.Sprintf("        Host: %s\n", inbound.Host))
			}
		case models.TransportGRPC:
			sb.WriteString("    grpc-opts:\n")
			sb.WriteString(fmt.Sprintf("      grpc-service-name: %s\n", inbound.ServiceName))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
