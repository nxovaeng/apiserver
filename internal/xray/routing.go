package xray

import (
	"sort"
	"strings"

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

	// Built-in safety net: any CN IP not matched by a user rule goes to the
	// configured fallback instead of falling through to `direct` (freedom,
	// the first outbound and xray's default for unmatched traffic, which
	// would expose the VPS's own IP). User rules always sort before this
	// catch-all, so an explicit direct rule for a CN domain/IP that
	// genuinely needs a Chinese IP still wins.
	//
	// The fallback is manual configuration, not auto-detection:
	//   - "proton" (default): an enabled outbound with that tag, typically
	//     the socks5 outbound to wireproxy on 127.0.0.1:1080;
	//   - "block" / "direct": built-in outbounds (blackhole / freedom),
	//     always available, so CN IPs can be intercepted even when no
	//     Proton outbound exists;
	//   - any other tag: an enabled outbound with that tag;
	//   - empty: the catch-all is disabled.
	// A named outbound that is missing or disabled emits no rule, so CN
	// traffic fails closed rather than leaking via direct.
	if tag := strings.TrimSpace(g.cnIPFallback); tag != "" {
		target := ""
		switch tag {
		case "block", "direct":
			target = tag
		default:
			for _, ob := range g.outbounds {
				if ob.Enabled && ob.Tag == tag {
					target = tag
					break
				}
			}
		}
		if target != "" {
			routing.Rules = append(routing.Rules, RoutingRule{
				Type:        "field",
				IP:          []string{"geoip:cn"},
				OutboundTag: target,
			})
		}
	}

	return routing
}
