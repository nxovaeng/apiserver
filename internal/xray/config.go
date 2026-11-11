package xray

import (
	"encoding/json"
	"strings"

	"xray-panel-server/internal/models"
)

// Config represents the complete Server-mode Xray configuration.
type Config struct {
	Log       *LogConfig       `json:"log,omitempty"`
	API       *APIConfig       `json:"api,omitempty"`
	DNS       *DNSConfig       `json:"dns,omitempty"`
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
	Routing   *RoutingConfig   `json:"routing,omitempty"`
	Policy    *PolicyConfig    `json:"policy,omitempty"`
	Stats     *StatsConfig     `json:"stats,omitempty"`
}

// LogConfig represents Xray logging configuration.
type LogConfig struct {
	Access   string `json:"access,omitempty"`
	Error    string `json:"error,omitempty"`
	LogLevel string `json:"loglevel,omitempty"`
}

// APIConfig represents Xray API configuration.
type APIConfig struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

// DNSConfig represents DNS configuration.
type DNSConfig struct {
	Servers       []interface{} `json:"servers,omitempty"`
	Tag           string        `json:"tag,omitempty"`
	QueryStrategy string        `json:"queryStrategy,omitempty"`
}

// StatsConfig enables statistics.
type StatsConfig struct{}

// PolicyConfig represents policy configuration.
type PolicyConfig struct {
	Levels map[string]PolicyLevel `json:"levels,omitempty"`
	System *SystemPolicy          `json:"system,omitempty"`
}

// PolicyLevel represents a policy level.
type PolicyLevel struct {
	Handshake         int  `json:"handshake,omitempty"`
	ConnIdle          int  `json:"connIdle,omitempty"`
	UplinkOnly        int  `json:"uplinkOnly,omitempty"`
	DownlinkOnly      int  `json:"downlinkOnly,omitempty"`
	StatsUserUplink   bool `json:"statsUserUplink,omitempty"`
	StatsUserDownlink bool `json:"statsUserDownlink,omitempty"`
}

// SystemPolicy represents system-wide policies.
type SystemPolicy struct {
	StatsInboundUplink    bool `json:"statsInboundUplink,omitempty"`
	StatsInboundDownlink  bool `json:"statsInboundDownlink,omitempty"`
	StatsOutboundUplink   bool `json:"statsOutboundUplink,omitempty"`
	StatsOutboundDownlink bool `json:"statsOutboundDownlink,omitempty"`
}

// Generator builds pure Server-mode Xray JSON configurations.
type Generator struct {
	users                []models.User
	inbounds             []models.Inbound
	outbounds            []models.Outbound
	rules                []models.RoutingRule
	domains              map[string]models.Domain
	apiPort              int
	logLevel             string
	socketDir            string
	directDomainStrategy string
	enableTrafficStats   bool
	enableSniffing       bool
}

// NewGenerator creates a new Server-mode Xray configuration generator.
func NewGenerator() *Generator {
	return &Generator{
		domains:              make(map[string]models.Domain),
		apiPort:              10085,
		logLevel:             "warning",
		socketDir:            "/dev/shm",
		directDomainStrategy: "UseIPv4",
		enableTrafficStats:   true,
		enableSniffing:       true,
	}
}

func (g *Generator) SetUsers(users []models.User) *Generator {
	g.users = users
	return g
}

func (g *Generator) SetInbounds(inbounds []models.Inbound) *Generator {
	g.inbounds = inbounds
	return g
}

func (g *Generator) SetOutbounds(outbounds []models.Outbound) *Generator {
	g.outbounds = outbounds
	return g
}

func (g *Generator) SetRoutingRules(rules []models.RoutingRule) *Generator {
	g.rules = rules
	return g
}

func (g *Generator) SetDomains(domains []models.Domain) *Generator {
	for _, d := range domains {
		g.domains[d.ID] = d
	}
	return g
}

func (g *Generator) SetAPIPort(port int) *Generator {
	if port > 0 {
		g.apiPort = port
	}
	return g
}

func (g *Generator) SetLogLevel(level string) *Generator {
	if level != "" {
		g.logLevel = level
	}
	return g
}

func (g *Generator) SetSocketDir(dir string) *Generator {
	if dir != "" {
		g.socketDir = dir
	}
	return g
}

func (g *Generator) SetDirectDomainStrategy(strategy string) *Generator {
	if strategy == "" {
		strategy = "UseIPv4"
	}
	g.directDomainStrategy = strategy
	return g
}

func (g *Generator) SetEnableTrafficStats(enabled bool) *Generator {
	g.enableTrafficStats = enabled
	return g
}

func (g *Generator) SetEnableSniffing(enabled bool) *Generator {
	g.enableSniffing = enabled
	return g
}

// Generate creates the complete Server-mode Xray configuration.
func (g *Generator) Generate() (*Config, error) {
	config := &Config{
		Log: &LogConfig{
			LogLevel: g.logLevel,
		},
		API: &APIConfig{
			Tag:      "api",
			Services: []string{"HandlerService", "LoggerService", "StatsService"},
		},
		DNS: &DNSConfig{
			QueryStrategy: "UseIP",
			Servers: []interface{}{
				"1.1.1.1",
				"8.8.8.8",
				"localhost",
			},
		},
	}

	if g.enableTrafficStats {
		config.Stats = &StatsConfig{}
		config.Policy = &PolicyConfig{
			Levels: map[string]PolicyLevel{
				"0": {
					Handshake:         4,
					ConnIdle:          300,
					UplinkOnly:        2,
					DownlinkOnly:      5,
					StatsUserUplink:   true,
					StatsUserDownlink: true,
				},
			},
			System: &SystemPolicy{
				StatsInboundUplink:    true,
				StatsInboundDownlink:  true,
				StatsOutboundUplink:   true,
				StatsOutboundDownlink: true,
			},
		}
	}

	config.Inbounds = append(config.Inbounds, g.generateAPIInbound())

	for _, inbound := range g.inbounds {
		if !inbound.Enabled {
			continue
		}
		inboundConfig, err := g.generateInbound(inbound)
		if err != nil {
			return nil, err
		}
		config.Inbounds = append(config.Inbounds, *inboundConfig)
	}

	config.Outbounds = g.generateOutbounds()
	config.Routing = g.generateRouting()

	return config, nil
}

// GenerateJSON generates the complete Xray configuration formatted as JSON.
func (g *Generator) GenerateJSON() ([]byte, error) {
	cfg, err := g.Generate()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// GenerateTestJSON builds a minimal Xray config for real outbound dial testing.
func (g *Generator) GenerateTestJSON(httpProxyPort int) ([]byte, error) {
	outboundTag := ""
	if len(g.outbounds) > 0 {
		outboundTag = g.outbounds[0].Tag
	}

	routingRules := []map[string]interface{}{}
	if outboundTag != "" {
		routingRules = append(routingRules, map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{"test-http-in"},
			"outboundTag": outboundTag,
		})
	}

	testConfig := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []map[string]interface{}{
			{
				"tag":      "test-http-in",
				"listen":   "127.0.0.1",
				"port":     httpProxyPort,
				"protocol": "http",
			},
		},
		"outbounds": g.generateOutbounds(),
		"routing": map[string]interface{}{
			"domainStrategy": "IPIfNonMatch",
			"rules":          routingRules,
		},
	}

	return json.MarshalIndent(testConfig, "", "  ")
}

func (g *Generator) generateAPIInbound() InboundConfig {
	return InboundConfig{
		Tag:      "api",
		Listen:   "127.0.0.1",
		Port:     g.apiPort,
		Protocol: "dokodemo-door",
		Settings: map[string]interface{}{
			"address": "127.0.0.1",
		},
	}
}

func (g *Generator) getActiveUsers() []models.User {
	var active []models.User
	for _, u := range g.users {
		if u.IsActive() {
			active = append(active, u)
		}
	}
	return active
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(c rune) bool {
		return c == ',' || c == '\n' || c == '\r'
	})
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
