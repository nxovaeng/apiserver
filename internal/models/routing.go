package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RuleType represents the type of routing rule.
type RuleType string

const (
	RuleTypeInbound  RuleType = "inbound"
	RuleTypeDomain   RuleType = "domain"
	RuleTypeIP       RuleType = "ip"
	RuleTypeGeoSite  RuleType = "geosite"
	RuleTypeGeoIP    RuleType = "geoip"
	RuleTypeProtocol RuleType = "protocol"
)

// RoutingRule represents a routing rule for Xray.
type RoutingRule struct {
	ID   string   `json:"id" gorm:"primaryKey"`
	Name string   `json:"name" gorm:"not null"`
	Type RuleType `json:"type" gorm:"not null"`

	InboundTag  string `json:"inbound_tag"`
	Domains     string `json:"domains"`
	IPs         string `json:"ips"`
	GeoSiteTags string `json:"geosite_tags"`
	GeoIPCodes  string `json:"geoip_codes"`
	Protocols   string `json:"protocols"`

	OutboundTag string `json:"outbound_tag" gorm:"not null"`
	Priority    int    `json:"priority" gorm:"default:100"`
	Enabled     bool   `json:"enabled"`
	Remark      string `json:"remark"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// BeforeCreate generates UUID for new rule.
func (r *RoutingRule) BeforeCreate(tx *gorm.DB) error {
	if r.ID == "" {
		r.ID = uuid.New().String()
	}
	return nil
}

// DefaultRoutingRules returns the default basic routing rules.
func DefaultRoutingRules() []RoutingRule {
	return []RoutingRule{
		{
			Name:        "屏蔽广告域名",
			Type:        RuleTypeGeoSite,
			GeoSiteTags: "category-ads,category-ads-all",
			OutboundTag: "block",
			Priority:    10,
			Enabled:     true,
			Remark:      "屏蔽常见广告和追踪域名",
		},
		{
			Name:        "屏蔽 BT 协议",
			Type:        RuleTypeProtocol,
			Protocols:   "bittorrent",
			OutboundTag: "block",
			Priority:    20,
			Enabled:     true,
			Remark:      "阻止 BitTorrent 流量",
		},
		{
			Name:        "私有网络直连",
			Type:        RuleTypeGeoIP,
			GeoIPCodes:  "private",
			OutboundTag: "direct",
			Priority:    5,
			Enabled:     true,
			Remark:      "局域网和私有IP地址直接连接",
		},
	}
}

// PresetRoutingRules returns preset rule templates for quick import.
func PresetRoutingRules() map[string][]RoutingRule {
	return map[string][]RoutingRule{
		"warp-china": {
			{
				Name:        "中国网站经 WARP",
				Type:        RuleTypeGeoSite,
				GeoSiteTags: "cn,geolocation-cn",
				OutboundTag: "warp",
				Priority:    50,
				Enabled:     true,
				Remark:      "中国大陆网站通过 WARP 访问（需要先创建 WARP 出站）",
			},
			{
				Name:        "中国 IP 经 WARP",
				Type:        RuleTypeGeoIP,
				GeoIPCodes:  "cn",
				OutboundTag: "warp",
				Priority:    51,
				Enabled:     true,
				Remark:      "中国大陆 IP 通过 WARP 访问（需要先创建 WARP 出站）",
			},
		},
		"warp-streaming": {
			{
				Name:        "流媒体经 WARP",
				Type:        RuleTypeGeoSite,
				GeoSiteTags: "netflix,disney,youtube,spotify,hulu,hbo,primevideo",
				OutboundTag: "warp",
				Priority:    60,
				Enabled:     true,
				Remark:      "流媒体服务通过 WARP 访问（需要先创建 WARP 出站）",
			},
		},
		"china-direct": {
			{
				Name:        "中国网站直连",
				Type:        RuleTypeGeoSite,
				GeoSiteTags: "cn,geolocation-cn",
				OutboundTag: "direct",
				Priority:    50,
				Enabled:     true,
				Remark:      "中国大陆网站直接连接",
			},
			{
				Name:        "中国 IP 直连",
				Type:        RuleTypeGeoIP,
				GeoIPCodes:  "cn",
				OutboundTag: "direct",
				Priority:    51,
				Enabled:     true,
				Remark:      "中国大陆 IP 直接连接",
			},
		},
	}
}
