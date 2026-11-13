package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/proton"
	"xray-panel-server/internal/service"
)

func TestPVPNService(t *testing.T) {
	db, cfg, _ := setupTestEnv(t)
	tempDir, err := os.MkdirTemp("", "pvpn_svc_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create a dummy wireproxy binary file so LocateWireproxy succeeds
	dummyBin := filepath.Join(tempDir, "wireproxy")
	if err := os.WriteFile(dummyBin, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	cfg.PVPN.Enabled = true
	cfg.PVPN.DataDir = tempDir
	cfg.PVPN.BinaryPath = dummyBin
	cfg.PVPN.SocksPort = 1080

	mockProtonAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/v4/sessions":
			json.NewEncoder(w).Encode(map[string]any{
				"Code":        1000,
				"AccessToken": "anon_token_123",
				"UID":         "anon_uid_456",
			})
		case "/auth/v4/credentialless":
			json.NewEncoder(w).Encode(map[string]any{
				"Code":         1000,
				"AccessToken":  "guest_token_789",
				"UID":          "guest_uid_012",
				"RefreshToken": "refresh_xyz",
				"UserID":       "user_999",
			})
		case "/vpn/v1/certificate":
			json.NewEncoder(w).Encode(map[string]any{
				"Code":           1000,
				"Certificate":    "test_cert_content",
				"ExpirationTime": time.Now().Add(7 * 24 * time.Hour).Unix(),
			})
		case "/vpn/v2/logicals":
			json.NewEncoder(w).Encode(map[string]any{
				"Code": 1000,
				"LogicalServers": []map[string]any{
					{
						"ID":          "US-FREE#1",
						"Name":        "US-FREE#1",
						"ExitCountry": "US",
						"City":        "New York",
						"Tier":        0,
						"Score":       1.5,
						"Load":        40,
						"Servers": []map[string]any{
							{
								"EntryIP":         "192.0.2.1",
								"X25519PublicKey": "test_public_key_abc=",
								"WGPorts": map[string]any{
									"UDP": []int{51820},
								},
							},
						},
					},
					{
						"ID":          "NL-FREE#1",
						"Name":        "NL-FREE#1",
						"ExitCountry": "NL",
						"City":        "Amsterdam",
						"Tier":        0,
						"Score":       1.2,
						"Load":        30,
						"Servers": []map[string]any{
							{
								"EntryIP":         "198.51.100.1",
								"X25519PublicKey": "test_public_key_def=",
								"WGPorts": map[string]any{
									"UDP": []int{51820},
								},
							},
						},
					},
				},
			})
		case "/vpn/v1/loads":
			json.NewEncoder(w).Encode(map[string]any{
				"Code": 1000,
				"LogicalServers": []map[string]any{
					{"ID": "US-FREE#1", "Load": 42},
					{"ID": "NL-FREE#1", "Load": 28},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockProtonAPI.Close()

	protonClient := proton.NewClient(mockProtonAPI.URL, 5*time.Second)
	mgr := proton.NewManager(proton.ManagerConfig{
		DataDir:    tempDir,
		BinaryPath: dummyBin,
		SocksHost:  "127.0.0.1",
		SocksPort:  1080,
	}, protonClient)

	pvpnSvc := service.NewPVPNService(db, cfg)
	pvpnSvc.SetManager(mgr)

	ctx := context.Background()

	// 1. Test GetStatus before connect
	status, err := pvpnSvc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if !status.Installed {
		t.Errorf("expected Installed = true")
	}
	if status.Port != 1080 {
		t.Errorf("expected Port = 1080, got %d", status.Port)
	}
	if status.OutboundTag != "proton" {
		t.Errorf("expected OutboundTag = proton, got %s", status.OutboundTag)
	}

	// 2. Test GetCountries
	countriesResp, err := pvpnSvc.GetCountries(ctx)
	if err != nil {
		t.Fatalf("GetCountries failed: %v", err)
	}
	if len(countriesResp.Countries) != 2 {
		t.Fatalf("expected 2 countries, got %d", len(countriesResp.Countries))
	}

	// 3. Test GetServers
	serversResp, err := pvpnSvc.GetServers(ctx, "US")
	if err != nil {
		t.Fatalf("GetServers failed: %v", err)
	}
	if len(serversResp.Servers) != 1 {
		t.Fatalf("expected 1 US server, got %d", len(serversResp.Servers))
	}
	if serversResp.Servers[0].Name != "US-FREE#1" {
		t.Errorf("expected server name US-FREE#1, got %s", serversResp.Servers[0].Name)
	}

	// 4. Test Connect (with auto-ensuring outbound)
	connResp, err := pvpnSvc.Connect(ctx, dto.PVPNConnectRequest{
		Country:        "US",
		EnsureOutbound: true,
	})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if !connResp.Success {
		t.Errorf("expected Connect success = true")
	}
	if connResp.Server != "US-FREE#1" {
		t.Errorf("expected Connect Server = US-FREE#1, got %s", connResp.Server)
	}

	// 5. Verify outbound exists in DB
	statusAfter, err := pvpnSvc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus after connect failed: %v", err)
	}
	if !statusAfter.OutboundExists {
		t.Errorf("expected OutboundExists = true after connect")
	}

	// 6. Test Disconnect
	disconnResp, err := pvpnSvc.Disconnect(ctx)
	if err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}
	if !disconnResp.Success {
		t.Errorf("expected Disconnect success = true")
	}

	// 7. Test ServiceAction
	actionResp, err := pvpnSvc.ServiceAction(ctx, "stop")
	if err != nil {
		t.Fatalf("ServiceAction failed: %v", err)
	}
	if !actionResp.Success {
		t.Errorf("expected ServiceAction success = true")
	}

	// 8. Test EnsureOutbound idempotency
	obDTO, err := pvpnSvc.EnsureOutbound(ctx)
	if err != nil {
		t.Fatalf("EnsureOutbound failed: %v", err)
	}
	if obDTO.Tag != "proton" {
		t.Errorf("expected obDTO.Tag = proton, got %s", obDTO.Tag)
	}
	if obDTO.Port != 1080 {
		t.Errorf("expected obDTO.Port = 1080, got %d", obDTO.Port)
	}

	// 9. Test GetConfig
	cfgResp, err := pvpnSvc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfgResp.SocksPort != 1080 {
		t.Errorf("expected SocksPort = 1080, got %d", cfgResp.SocksPort)
	}
	if cfgResp.SessionPath == "" {
		t.Errorf("expected non-empty SessionPath")
	}

	// 10. Test UpdateConfig (change port to 1088)
	updResp, err := pvpnSvc.UpdateConfig(ctx, dto.PVPNConfigRequest{SocksPort: 1088})
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	if updResp.SocksPort != 1088 {
		t.Errorf("expected updated SocksPort = 1088, got %d", updResp.SocksPort)
	}

	// Verify DB outbound updated
	obAfter, err := pvpnSvc.EnsureOutbound(ctx)
	if err != nil {
		t.Fatalf("EnsureOutbound after port update failed: %v", err)
	}
	if obAfter.Port != 1088 {
		t.Errorf("expected obAfter.Port = 1088, got %d", obAfter.Port)
	}

	// 11. Test Manual Login
	loginResp, err := pvpnSvc.Login(ctx, dto.PVPNLoginRequest{})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if !loginResp.Success {
		t.Errorf("expected login success = true")
	}
	if loginResp.CertExpiresAt <= 0 {
		t.Errorf("expected positive CertExpiresAt, got %d", loginResp.CertExpiresAt)
	}

	// 12. Test ImportSession
	impResp, err := pvpnSvc.ImportSession(ctx, dto.PVPNImportSessionRequest{
		AccessToken:  "imported_access_token_abc",
		UID:          "imported_uid_123",
		WGPrivateKey: "dGVzdF9wcml2YXRlX2tleQ==",
	})
	if err != nil {
		t.Fatalf("ImportSession failed: %v", err)
	}
	if !impResp.Success {
		t.Errorf("expected import success = true")
	}
	if impResp.AuthMode != "imported" {
		t.Errorf("expected AuthMode = imported, got %s", impResp.AuthMode)
	}
}
