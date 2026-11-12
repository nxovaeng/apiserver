package xray_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xray-panel-server/internal/models"
	"xray-panel-server/internal/xray"
)

func TestServerModeXrayConfigGeneration(t *testing.T) {
	priv, pub, err := models.GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("GenerateWGKeyPair: %v", err)
	}
	_, peerPub, err := models.GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("GenerateWGKeyPair peer: %v", err)
	}

	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-24 * time.Hour)

	users := []models.User{
		{ID: "u-active", UUID: "11111111-1111-1111-1111-111111111111", Name: "alice", Enabled: true, ExpiryDate: &future, WGPubKey: peerPub},
		{ID: "u-disabled", UUID: "22222222-2222-2222-2222-222222222222", Name: "bob", Enabled: false},
		{ID: "u-expired", UUID: "33333333-3333-3333-3333-333333333333", Name: "carol", Enabled: true, ExpiryDate: &past},
		{ID: "u-overquota", UUID: "44444444-4444-4444-4444-444444444444", Name: "dave", Enabled: true, TrafficLimit: 100, TrafficUsed: 100},
	}

	inbounds := []models.Inbound{
		{ID: "in-1", Tag: "vless-xhttp", Protocol: models.ProtocolVLESS, Transport: models.TransportXHTTP, Path: "/abc", UseUDS: true, Enabled: true},
		{ID: "in-2", Tag: "trojan-grpc", Protocol: models.ProtocolTrojan, Transport: models.TransportGRPC, ServiceName: "svc", Port: 20001, UseUDS: false, Enabled: true},
		{ID: "in-3", Tag: "wg-relay", Protocol: models.ProtocolWireGuard, Transport: models.TransportRAW, Port: 51821, WGSecretKey: priv, WGPublicKey: pub, WGLocalIP: "10.9.0.1/24", Enabled: true},
		{ID: "in-disabled", Tag: "disabled-ws", Protocol: models.ProtocolVLESS, Transport: models.TransportWS, Path: "/off", Enabled: false},
	}

	outbounds := []models.Outbound{
		{ID: "out-1", Tag: "socks-out", Type: models.OutboundSOCKS5, Server: "127.0.0.1", Port: 1080, Username: "u", Password: "p", Enabled: true},
	}

	rules := []models.RoutingRule{
		{ID: "r-2", Name: "cn", Type: models.RuleTypeGeoIP, GeoIPCodes: "cn", OutboundTag: "direct", Priority: 50, Enabled: true},
		{ID: "r-1", Name: "ads", Type: models.RuleTypeGeoSite, GeoSiteTags: "category-ads", OutboundTag: "block", Priority: 10, Enabled: true},
		{ID: "r-off", Name: "off", Type: models.RuleTypeProtocol, Protocols: "bittorrent", OutboundTag: "block", Priority: 5, Enabled: false},
	}

	gen := xray.NewGenerator().
		SetUsers(users).
		SetInbounds(inbounds).
		SetOutbounds(outbounds).
		SetRoutingRules(rules).
		SetAPIPort(10085).
		SetSocketDir("/dev/shm").
		SetLogLevel("info").
		SetDirectDomainStrategy("UseIP").
		SetEnableTrafficStats(true).
		SetEnableSniffing(true)

	raw, err := gen.GenerateJSON()
	if err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}
	rawStr := string(raw)

	// Must never contain legacy client-mode artifacts
	for _, forbidden := range []string{"dns-in", "socks-in", "http-in", "dns-out", "geolocation-!cn", "https+local://"} {
		if strings.Contains(rawStr, forbidden) {
			t.Fatalf("found legacy client-mode artifact %q in generated config", forbidden)
		}
	}

	// Only active user u-active should appear in inbound clients
	if !strings.Contains(rawStr, "u-active") {
		t.Errorf("expected active user stats key u-active")
	}
	for _, inactive := range []string{"u-disabled", "u-expired", "u-overquota"} {
		if strings.Contains(rawStr, inactive) {
			t.Errorf("inactive user %s must not be included in Xray config", inactive)
		}
	}

	cfg, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if cfg.Stats == nil || cfg.Policy == nil {
		t.Fatalf("expected Stats and Policy when enableTrafficStats=true")
	}
	// api + 3 enabled inbounds = 4
	if len(cfg.Inbounds) != 4 {
		t.Fatalf("expected 4 inbounds, got %d", len(cfg.Inbounds))
	}
	if cfg.Inbounds[1].Listen != "/dev/shm/xray-vless-xhttp.sock,0666" {
		t.Errorf("unexpected UDS listen path: %s", cfg.Inbounds[1].Listen)
	}
	if cfg.Inbounds[3].Listen != "0.0.0.0" {
		t.Errorf("expected wireguard inbound listen 0.0.0.0, got %s", cfg.Inbounds[3].Listen)
	}

	// Verify routing rule order: api -> ads (priority 10) -> cn (priority 50)
	if len(cfg.Routing.Rules) != 3 {
		t.Fatalf("expected 3 routing rules, got %d", len(cfg.Routing.Rules))
	}
	if cfg.Routing.Rules[1].OutboundTag != "block" || cfg.Routing.Rules[2].OutboundTag != "direct" {
		t.Errorf("unexpected routing rule order: %+v", cfg.Routing.Rules)
	}

	// Verify disabling stats/sniffing works
	gen.SetEnableTrafficStats(false).SetEnableSniffing(false)
	cfgNoStats, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate no stats: %v", err)
	}
	if cfgNoStats.Stats != nil || cfgNoStats.Policy != nil {
		t.Errorf("expected nil Stats/Policy when enableTrafficStats=false")
	}
	if cfgNoStats.Inbounds[1].Sniffing != nil {
		t.Errorf("expected nil Sniffing when enableSniffing=false")
	}

	// Verify test JSON generation
	testJSON, err := gen.GenerateTestJSON(18080)
	if err != nil {
		t.Fatalf("GenerateTestJSON: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(testJSON, &parsed); err != nil {
		t.Fatalf("invalid test JSON: %v", err)
	}
}

func TestCNIPFallbackRule(t *testing.T) {
	proton := models.Outbound{ID: "out-proton", Tag: "proton", Type: models.OutboundSOCKS5, Server: "127.0.0.1", Port: 1080, Enabled: true}
	userRule := models.RoutingRule{ID: "r-1", Name: "ads", Type: models.RuleTypeGeoSite, GeoSiteTags: "category-ads", OutboundTag: "block", Priority: 10, Enabled: true}

	gen := xray.NewGenerator().
		SetOutbounds([]models.Outbound{proton}).
		SetRoutingRules([]models.RoutingRule{userRule}).
		SetCNIPFallback("proton")

	cfg, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// api -> ads (user rule) -> geoip:cn catch-all
	if len(cfg.Routing.Rules) != 3 {
		t.Fatalf("expected 3 routing rules, got %d: %+v", len(cfg.Routing.Rules), cfg.Routing.Rules)
	}
	last := cfg.Routing.Rules[2]
	if last.OutboundTag != "proton" || len(last.IP) != 1 || last.IP[0] != "geoip:cn" {
		t.Errorf("catch-all rule = %+v, want geoip:cn -> proton", last)
	}
	if cfg.Routing.Rules[1].OutboundTag != "block" {
		t.Errorf("user rule must sort before the catch-all: %+v", cfg.Routing.Rules)
	}

	// An explicit user geoip:cn rule still wins (first match), the
	// catch-all stays after it and is unreachable for CN IPs.
	directCN := models.RoutingRule{ID: "r-2", Name: "cn-direct", Type: models.RuleTypeGeoIP, GeoIPCodes: "cn", OutboundTag: "direct", Priority: 20, Enabled: true}
	gen.SetRoutingRules([]models.RoutingRule{userRule, directCN})
	cfg, err = gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(cfg.Routing.Rules) != 4 {
		t.Fatalf("expected 4 routing rules, got %d", len(cfg.Routing.Rules))
	}
	if cfg.Routing.Rules[2].OutboundTag != "direct" || cfg.Routing.Rules[3].OutboundTag != "proton" {
		t.Errorf("explicit CN rule must precede the catch-all: %+v", cfg.Routing.Rules)
	}

	// No matching outbound: no rule (never emit a rule pointing at a
	// missing outbound).
	gen.SetOutbounds(nil)
	cfg, err = gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, r := range cfg.Routing.Rules {
		if r.OutboundTag == "proton" {
			t.Errorf("must not emit proton rule without a matching outbound: %+v", cfg.Routing.Rules)
		}
	}

	// Disabled outbound: no rule.
	off := proton
	off.Enabled = false
	gen.SetOutbounds([]models.Outbound{off})
	cfg, err = gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, r := range cfg.Routing.Rules {
		if r.OutboundTag == "proton" {
			t.Errorf("must not emit proton rule for a disabled outbound: %+v", cfg.Routing.Rules)
		}
	}

	// Empty tag: disabled.
	gen.SetOutbounds([]models.Outbound{proton}).SetCNIPFallback("")
	cfg, err = gen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, r := range cfg.Routing.Rules {
		if r.OutboundTag == "proton" {
			t.Errorf("empty tag must disable the proton rule: %+v", cfg.Routing.Rules)
		}
	}

	// Built-in fallbacks need no outbound at all: "block" intercepts CN
	// IPs even when no Proton outbound exists, "direct" passes them out
	// directly. Both are outbounds the generator always emits.
	gen.SetOutbounds(nil).SetRoutingRules([]models.RoutingRule{userRule})
	for _, want := range []string{"block", "direct"} {
		gen.SetCNIPFallback(want)
		cfg, err = gen.Generate()
		if err != nil {
			t.Fatalf("Generate %s: %v", want, err)
		}
		if len(cfg.Routing.Rules) != 3 {
			t.Fatalf("expected 3 routing rules for %s, got %d", want, len(cfg.Routing.Rules))
		}
		last = cfg.Routing.Rules[2]
		if last.OutboundTag != want || len(last.IP) != 1 || last.IP[0] != "geoip:cn" {
			t.Errorf("catch-all rule = %+v, want geoip:cn -> %s", last, want)
		}
	}
}
