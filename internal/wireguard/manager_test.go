package wireguard_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"xray-panel-server/internal/models"
	"xray-panel-server/internal/wireguard"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite in memory: %v", err)
	}

	if err := db.AutoMigrate(&models.Inbound{}, &models.WGServerConfig{}, &models.WGPeer{}); err != nil {
		t.Fatalf("failed to migrate tables: %v", err)
	}
	return db
}

func TestWireGuardKeyGeneration(t *testing.T) {
	privKey, pubKey, err := models.GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("GenerateWGKeyPair failed: %v", err)
	}
	derivedPub, err := models.DeriveWGPublicKey(privKey)
	if err != nil {
		t.Fatalf("DeriveWGPublicKey failed: %v", err)
	}
	if derivedPub != pubKey {
		t.Errorf("derived public key %q != %q", derivedPub, pubKey)
	}
}

func TestIPAllocation(t *testing.T) {
	db := setupTestDB(t)
	serverAddr := "10.0.0.1/24"
	if ip1 := models.GetNextAvailableIP(db, serverAddr); ip1 != "10.0.0.2/32" {
		t.Errorf("expected 10.0.0.2/32, got %s", ip1)
	}

	db.Create(&models.WGPeer{Name: "Peer 1", PublicKey: "pub1", AllowedIPs: "10.0.0.2/32", Enabled: true})
	if ip2 := models.GetNextAvailableIP(db, serverAddr); ip2 != "10.0.0.3/32" {
		t.Errorf("expected 10.0.0.3/32, got %s", ip2)
	}
}

func TestPortConflictDetection(t *testing.T) {
	db := setupTestDB(t)
	if conflict, _ := wireguard.CheckPortConflict(db, 51820); conflict {
		t.Errorf("expected no conflict")
	}

	db.Create(&models.Inbound{
		ID: "inbound-1", Tag: "vless-in", Protocol: models.ProtocolVLESS,
		Transport: models.TransportWS, Port: 51820, Enabled: true,
	})
	conflict, tag := wireguard.CheckPortConflict(db, 51820)
	if !conflict || tag != "vless-in" {
		t.Errorf("expected conflict with vless-in, got conflict=%v tag=%s", conflict, tag)
	}
}

func TestConfigGeneration(t *testing.T) {
	db := setupTestDB(t)
	serverCfg := &models.WGServerConfig{
		InterfaceName: "wg0", PrivateKey: "server_priv_key", PublicKey: "server_pub_key",
		ListenPort: 51820, Address: "10.0.0.1/24", MTU: 1420,
		PostUp: models.DefaultPostUp("%i"), PostDown: models.DefaultPostDown("%i"), Enabled: true,
	}
	peers := []models.WGPeer{
		{ID: 1, Name: "Client-Tokyo", PublicKey: "tokyo_pub_key", PrivateKey: "tokyo_priv_key", AllowedIPs: "10.0.0.2/32", PersistentKeepalive: 25, Enabled: true},
		{ID: 2, Name: "Client-Disabled", PublicKey: "disabled_pub_key", AllowedIPs: "10.0.0.3/32", Enabled: false},
	}

	mgr := wireguard.NewManager(db)
	conf := mgr.GenerateWG0Conf(serverCfg, peers)
	if !strings.Contains(conf, "ListenPort = 51820") || !strings.Contains(conf, "PublicKey = tokyo_pub_key") || strings.Contains(conf, "disabled_pub_key") {
		t.Errorf("unexpected wg0.conf output:\n%s", conf)
	}
	if strings.Contains(conf, "PostUp") {
		t.Errorf("expected no PostUp when EnableNAT=false")
	}

	serverCfg.EnableNAT = true
	confNAT := mgr.GenerateWG0Conf(serverCfg, peers)
	if !strings.Contains(confNAT, "PostUp") || !strings.Contains(confNAT, "PostDown") {
		t.Errorf("expected PostUp/PostDown when EnableNAT=true")
	}

	clientXrayJSON, err := mgr.GenerateClientXrayJSON(serverCfg, &peers[0], "1.2.3.4")
	if err != nil {
		t.Fatalf("GenerateClientXrayJSON failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(clientXrayJSON), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if parsed["protocol"] != "wireguard" {
		t.Errorf("expected wireguard protocol, got %v", parsed["protocol"])
	}
}
