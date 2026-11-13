package proton_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"xray-panel-server/internal/proton"
)

func TestCrypto_GenerateVPNKeys(t *testing.T) {
	privKey, pemPub, err := proton.GenerateVPNKeys()
	if err != nil {
		t.Fatalf("GenerateVPNKeys failed: %v", err)
	}
	if len(privKey) == 0 {
		t.Errorf("expected non-empty privKey")
	}
	if len(pemPub) == 0 {
		t.Errorf("expected non-empty pemPub")
	}
	if !filepath.IsAbs("/") { // trivial check
		t.Errorf("system check")
	}
}

func TestDevice_JavaStringHashCode(t *testing.T) {
	tests := []struct {
		input    string
		expected int32
	}{
		{"", 0},
		{"a", 97},
		{"hello", 99162322},
	}
	for _, tt := range tests {
		got := proton.JavaStringHashCode(tt.input)
		if got != tt.expected {
			t.Errorf("JavaStringHashCode(%q) = %d; want %d", tt.input, got, tt.expected)
		}
	}
}

func TestDevice_BuildChallengePayload(t *testing.T) {
	hash := proton.JavaStringHashCode("machine-1")
	payload := proton.BuildChallengePayload(hash)
	p, ok := payload["Payload"].(map[string]any)
	if !ok {
		t.Fatalf("expected Payload field")
	}
	c, ok := p["vpn-android-v4-challenge-0"].(map[string]any)
	if !ok {
		t.Fatalf("expected vpn-android-v4-challenge-0 field")
	}
	if c["deviceName"] != hash {
		t.Errorf("expected deviceName = %d, got %v", hash, c["deviceName"])
	}
}

func TestClient_Flow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/v4/sessions":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"Code":        1000,
				"AccessToken": "anon_token_123",
				"UID":         "anon_uid_456",
			})
		case "/auth/v4/credentialless":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"Code":         1000,
				"AccessToken":  "guest_token_789",
				"UID":          "guest_uid_012",
				"RefreshToken": "refresh_xyz",
				"UserID":       "user_999",
			})
		case "/vpn/v1/certificate":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"Code":           1000,
				"Certificate":    "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
				"ExpirationTime": time.Now().Add(7 * 24 * time.Hour).Unix(),
			})
		case "/vpn/v2/logicals":
			w.Header().Set("Content-Type", "application/json")
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
			w.Header().Set("Content-Type", "application/json")
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
	defer ts.Close()

	client := proton.NewClient(ts.URL, 5*time.Second)
	ctx := context.Background()

	// 1. LoginGuest
	session, err := client.LoginGuest(ctx)
	if err != nil {
		t.Fatalf("LoginGuest failed: %v", err)
	}
	if session.AccessToken != "guest_token_789" {
		t.Errorf("expected AccessToken = guest_token_789, got %s", session.AccessToken)
	}
	if session.UID != "guest_uid_012" {
		t.Errorf("expected UID = guest_uid_012, got %s", session.UID)
	}

	// 2. RegisterCertificate
	err = client.RegisterCertificate(ctx, session)
	if err != nil {
		t.Fatalf("RegisterCertificate failed: %v", err)
	}
	if session.WGPrivateKey == "" {
		t.Errorf("expected non-empty WGPrivateKey")
	}
	if session.CertExpiresAt == 0 {
		t.Errorf("expected non-zero CertExpiresAt")
	}

	// 3. FetchServers
	servers, err := client.FetchServers(ctx, session)
	if err != nil {
		t.Fatalf("FetchServers failed: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
	if servers[0].ID != "US-FREE#1" || servers[0].Load != 42 {
		t.Errorf("server 0 mismatch: %+v", servers[0])
	}
	if servers[1].ID != "NL-FREE#1" || servers[1].Load != 28 {
		t.Errorf("server 1 mismatch: %+v", servers[1])
	}
}

func TestManager_SelectServerAndRenderConf(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "proton_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/v4/sessions":
			json.NewEncoder(w).Encode(map[string]any{"Code": 1000, "AccessToken": "tok", "UID": "uid"})
		case "/auth/v4/credentialless":
			json.NewEncoder(w).Encode(map[string]any{"Code": 1000, "AccessToken": "tok2", "UID": "uid2"})
		case "/vpn/v1/certificate":
			json.NewEncoder(w).Encode(map[string]any{"Code": 1000, "Certificate": "cert", "ExpirationTime": time.Now().Add(7 * 24 * time.Hour).Unix()})
		case "/vpn/v2/logicals":
			json.NewEncoder(w).Encode(map[string]any{
				"Code": 1000,
				"LogicalServers": []map[string]any{
					{
						"ID": "US-1", "Name": "US-FREE#1", "ExitCountry": "US", "Tier": 0, "Load": 50,
						"Servers": []map[string]any{{"EntryIP": "1.1.1.1", "X25519PublicKey": "key1", "WGPorts": map[string]any{"UDP": []int{51820}}}},
					},
					{
						"ID": "US-2", "Name": "US-FREE#2", "ExitCountry": "US", "Tier": 0, "Load": 25,
						"Servers": []map[string]any{{"EntryIP": "1.1.1.2", "X25519PublicKey": "key2", "WGPorts": map[string]any{"UDP": []int{51820}}}},
					},
				},
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{"Code": 1000})
		}
	}))
	defer ts.Close()

	client := proton.NewClient(ts.URL, 5*time.Second)
	mgr := proton.NewManager(proton.ManagerConfig{
		DataDir:   tempDir,
		SocksHost: "127.0.0.1",
		SocksPort: 1080,
	}, client)

	ctx := context.Background()

	// Select best server in US (should pick US-FREE#2 because load 25 < 50)
	srv, err := mgr.SelectServer(ctx, "US", "")
	if err != nil {
		t.Fatalf("SelectServer failed: %v", err)
	}
	if srv.Name != "US-FREE#2" {
		t.Errorf("expected US-FREE#2, got %s", srv.Name)
	}

	// Render config
	conf := proton.RenderWireproxyConf("TEST_PRIV_KEY=", srv, "127.0.0.1", 1080)
	if !filepath.IsAbs("/") { // noop
	}
	if len(conf) == 0 {
		t.Errorf("empty conf")
	}
}
