package models

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// Setting represents a key-value system setting.
type Setting struct {
	Key       string    `json:"key" gorm:"primaryKey"`
	Value     string    `json:"value"`
	Type      string    `json:"type" gorm:"default:string"`
	Remark    string    `json:"remark"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BeforeSave updates the timestamp.
func (s *Setting) BeforeSave(tx *gorm.DB) error {
	s.UpdatedAt = time.Now()
	return nil
}

// DefaultSettings returns default Server-mode system settings.
// Legacy client-mode keys (panel_mode, client_routing_mode) are permanently removed.
func DefaultSettings() []Setting {
	return []Setting{
		{Key: "panel_title", Value: "Xray Panel", Type: "string", Remark: "Panel title"},
		{Key: "sub_domain", Value: "", Type: "string", Remark: "Subscription domain"},
		{Key: "sub_path", Value: "/d", Type: "string", Remark: "Subscription URL path prefix"},
		{Key: "sub_nginx_enabled", Value: "false", Type: "bool", Remark: "Expose subscription path via Nginx HTTPS reverse proxy"},
		{Key: "api_domain", Value: "", Type: "string", Remark: "Control plane API domain for HTTPS/CDN direct access"},
		{Key: "api_nginx_enabled", Value: "false", Type: "bool", Remark: "Expose /api/v1 via Nginx HTTPS reverse proxy"},
		{Key: "server_public_host", Value: "", Type: "string", Remark: "Public server IP or domain for WireGuard endpoints and fallback subscriptions"},
		{Key: "xray_log_level", Value: "warning", Type: "string", Remark: "Xray log level"},
		{Key: "enable_traffic_stats", Value: "true", Type: "bool", Remark: "Enable traffic statistics"},
		{Key: "enable_sniffing", Value: "true", Type: "bool", Remark: "Enable traffic sniffing"},
		{Key: "default_traffic_limit", Value: "0", Type: "int", Remark: "Default traffic limit in bytes (0=unlimited)"},
		{Key: "default_expire_days", Value: "30", Type: "int", Remark: "Default expiry days for new users"},
		{Key: "direct_domain_strategy", Value: "UseIPv4", Type: "string", Remark: "Domain strategy for direct outbound"},
		{Key: "cn_ip_fallback", Value: "proton", Type: "string", Remark: "Fallback outbound for unmatched CN IPs: outbound tag (default proton), block, direct, or empty to disable"},
		{Key: "speedtest_enabled", Value: "false", Type: "bool", Remark: "Speedtest origin enabled (serves the 50MB test file via nginx)"},
		{Key: "speedtest_domain", Value: "", Type: "string", Remark: "Speedtest subdomain served by nginx (e.g. jp-speed.example.com)"},
		{Key: "speedtest_subpath", Value: "/speedtest", Type: "string", Remark: "URL subpath of the test file (change it to avoid a guessable address)"},
		{Key: "pvpn_socks_port", Value: "1080", Type: "int", Remark: "Proton Wireproxy SOCKS5 listen port"},
		{Key: "monthly_net_baseline_sent", Value: "", Type: "int", Remark: "OS net bytes sent at start of current month"},
		{Key: "monthly_net_baseline_recv", Value: "", Type: "int", Remark: "OS net bytes received at start of current month"},
		{Key: "monthly_net_baseline_month", Value: "", Type: "string", Remark: "Month of the current baseline (YYYY-MM)"},
	}
}

// GetSettingValue returns a setting value or fallback if absent or empty.
func GetSettingValue(db *gorm.DB, key, fallback string) string {
	if db == nil {
		return fallback
	}
	var setting Setting
	if err := db.First(&setting, "key = ?", key).Error; err != nil || setting.Value == "" {
		return fallback
	}
	return setting.Value
}

// GetDirectDomainStrategy returns the domain strategy for direct outbound.
func GetDirectDomainStrategy(db *gorm.DB) string {
	return GetSettingValue(db, "direct_domain_strategy", "UseIPv4")
}

// GetCNIPFallback returns the fallback outbound for CN IPs not matched by
// a user rule: an outbound tag (default "proton", normally a socks5 outbound
// pointing at wireproxy), "block" or "direct" (built-in outbounds), or empty
// to disable the built-in geoip:cn catch-all rule. A named outbound only
// takes effect when an enabled outbound with that tag exists. An absent row
// falls back to "proton" (the seeded default); an explicitly empty value
// disables the rule.
func GetCNIPFallback(db *gorm.DB) string {
	if db == nil {
		return ""
	}
	var setting Setting
	if err := db.First(&setting, "key = ?", "cn_ip_fallback").Error; err != nil {
		return "proton"
	}
	return strings.TrimSpace(setting.Value)
}

// NormalizeSubPath ensures sub_path starts with "/" and has no trailing "/" (except default "/d").
func NormalizeSubPath(raw string) string {
	p := strings.TrimSpace(raw)
	if p == "" || p == "/" {
		return "/d"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "/d"
	}
	return p
}

// GetSubPath returns the normalized subscription URL path prefix (e.g. "/d").
func GetSubPath(db *gorm.DB) string {
	return NormalizeSubPath(GetSettingValue(db, "sub_path", "/d"))
}

// GetSubDomain returns the configured subscription domain.
func GetSubDomain(db *gorm.DB) string {
	return strings.TrimSpace(GetSettingValue(db, "sub_domain", ""))
}

// GetSubNginxEnabled returns whether standalone/shared Nginx subscription proxy is enabled.
func GetSubNginxEnabled(db *gorm.DB) bool {
	return GetSettingValue(db, "sub_nginx_enabled", "false") == "true"
}

// GetAPIDomain returns the configured API reverse proxy domain.
func GetAPIDomain(db *gorm.DB) string {
	return strings.TrimSpace(GetSettingValue(db, "api_domain", ""))
}

// GetAPINginxEnabled returns whether Nginx reverse proxy for /api/v1 is enabled.
func GetAPINginxEnabled(db *gorm.DB) bool {
	return GetSettingValue(db, "api_nginx_enabled", "false") == "true"
}

// GetServerPublicHost returns the configured server public host/IP.
func GetServerPublicHost(db *gorm.DB) string {
	return strings.TrimSpace(GetSettingValue(db, "server_public_host", ""))
}

// GetXrayLogLevel returns the configured Xray log level.
func GetXrayLogLevel(db *gorm.DB) string {
	return GetSettingValue(db, "xray_log_level", "warning")
}

// GetEnableTrafficStats returns whether traffic stats are enabled.
func GetEnableTrafficStats(db *gorm.DB) bool {
	return GetSettingValue(db, "enable_traffic_stats", "true") != "false"
}

// GetEnableSniffing returns whether sniffing is enabled.
func GetEnableSniffing(db *gorm.DB) bool {
	return GetSettingValue(db, "enable_sniffing", "true") != "false"
}
