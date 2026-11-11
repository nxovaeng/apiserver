package xray

import (
	"sort"

	"xray-panel-server/internal/models"
)

// RoutingConfig represents Xray routing configuration.
type RoutingConfig struct {
	DomainStrategy string        `json:"domainStrategy"`
	DomainMatcher  string        `json:"domainMatcher,omitempty"`
	Rules          []RoutingRule `json:"rules"`
}

// RoutingRule represents a single Xray routing rule.
type RoutingRule struct {
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
	Protocol    []string `json:"protocol,omitempty"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

// generateRouting generates clean Server-mode routing rules (no legacy client-mode branches).
func (g *Generator) generateRouting() *RoutingConfig {
	routing := &RoutingConfig{
		DomainStrategy: "IPIfNonMatch",
		DomainMatcher:  "hybrid",
		Rules:          make([]RoutingRule, 0),
	}

	routing.Rules = append(routing.Rules, RoutingRule{
		Type:        "field",
		InboundTag:  []string{"api"},
		OutboundTag: "api",
	})

	sortedRules := make([]models.RoutingRule, len(g.rules))
	copy(sortedRules, g.rules)
	sort.Slice(sortedRules, func(i, j int) bool {
		return sortedRules[i].Priority < sortedRules[j].Priority
	})

	for _, rule := range sortedRules {
		if !rule.Enabled {
			continue
		}

		xrayRule := RoutingRule{
			Type:        "field",
			OutboundTag: rule.OutboundTag,
		}

		switch rule.Type {
		case models.RuleTypeInbound:
			if rule.InboundTag == "" {
				continue
			}
			xrayRule.InboundTag = []string{rule.InboundTag}
		case models.RuleTypeDomain:
			domains := splitCSV(rule.Domains)
			if len(domains) == 0 {
				continue
			}
			xrayRule.Domain = domains
		case models.RuleTypeIP:
			ips := splitCSV(rule.IPs)
			if len(ips) == 0 {
				continue
			}
			xrayRule.IP = ips
		case models.RuleTypeGeoSite:
			tags := splitCSV(rule.GeoSiteTags)
			if len(tags) == 0 {
				continue
			}
			domains := make([]string, len(tags))
			for i, tag := range tags {
				domains[i] = "geosite:" + tag
			}
			xrayRule.Domain = domains
		case models.RuleTypeGeoIP:
			codes := splitCSV(rule.GeoIPCodes)
			if len(codes) == 0 {
				continue
			}
			ips := make([]string, len(codes))
			for i, code := range codes {
				ips[i] = "geoip:" + code
			}
			xrayRule.IP = ips
		case models.RuleTypeProtocol:
			protocols := splitCSV(rule.Protocols)
			if len(protocols) == 0 {
				continue
			}
			xrayRule.Protocol = protocols
		default:
			continue
		}

		routing.Rules = append(routing.Rules, xrayRule)
	}

	return routing
}
