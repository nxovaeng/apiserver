package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-panel-server/internal/api"
	"xray-panel-server/internal/config"
	"xray-panel-server/internal/database"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
)

func setupTestServer(t *testing.T) (*api.Server, string, string) {
	t.Helper()
	tmpDir := t.TempDir()

	dbPath := filepath.Join(tmpDir, "panel.db")
	db, err := database.Init(dbPath)
	if err != nil {
		t.Fatalf("database.Init: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		t.Fatalf("database.Migrate: %v", err)
	}

	cfg := config.Default()
	cfg.Database.Path = dbPath
	cfg.Auth.FailLimit = 3
	cfg.Auth.FailWindowMinutes = 5
	cfg.Nginx.ConfigDir = filepath.Join(tmpDir, "nginx", "conf.d")
	cfg.Nginx.StreamDir = filepath.Join(tmpDir, "nginx", "stream.d")
	cfg.Nginx.CertDir = filepath.Join(tmpDir, "acme")
	cfg.Nginx.ReloadCmd = "true"
	cfg.Nginx.TestCmd = "true"
	cfg.Speedtest.FileDir = filepath.Join(tmpDir, "speedtest")
	cfg.Xray.ConfigPath = filepath.Join(tmpDir, "xray", "config.json")
	cfg.Xray.TestConfigDir = filepath.Join(tmpDir, "xray-test")
	cfg.Xray.AssetsPath = filepath.Join(tmpDir, "xray-assets")
	cfg.Xray.SocketDir = tmpDir

	seedRes, err := database.Seed(db, cfg)
	if err != nil {
		t.Fatalf("database.Seed: %v", err)
	}

	srv := api.NewServer(cfg, db, "1.0.0-test")
	return srv, seedRes.InitialTokenPlaintext, tmpDir
}

func doRequest(t *testing.T, handler http.Handler, method, path, token string, body interface{}, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		bodyReader = bytes.NewReader(raw)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	} else {
		req.RemoteAddr = "198.51.100.10:12345"
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestAuthMiddlewareSecurityAndRateLimit(t *testing.T) {
	srv, token, _ := setupTestServer(t)
	h := srv.Handler()

	// 1. Health endpoint is public
	rec := doRequest(t, h, http.MethodGet, "/api/v1/health", "", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /api/v1/health, got %d", rec.Code)
	}
	var health dto.HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil || health.Status != "ok" {
		t.Fatalf("unexpected health response: %s", rec.Body.String())
	}

	// 2. Protected route without token -> 401 UNAUTHORIZED JSON (no 302 redirect!)
	rec = doRequest(t, h, http.MethodGet, "/api/v1/auth/verify", "", nil, "203.0.113.1:5000")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
	var errResp dto.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil || errResp.Success || errResp.Error.Code != dto.ErrUnauthorized {
		t.Fatalf("unexpected error payload: %s", rec.Body.String())
	}

	// 3. Query param token must be rejected even if Authorization header is also present
	rec = doRequest(t, h, http.MethodGet, "/api/v1/auth/verify?token="+token, token, nil, "203.0.113.2:5000")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when token passed in query string, got %d", rec.Code)
	}

	// 4. Sliding-window rate limit after FailLimit (3) failed attempts from same IP
	attackerIP := "203.0.113.99:4000"
	for i := 0; i < 3; i++ {
		rec = doRequest(t, h, http.MethodGet, "/api/v1/dashboard", "xrp_wrong_token", nil, attackerIP)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
	}
	rec = doRequest(t, h, http.MethodGet, "/api/v1/dashboard", token, nil, attackerIP)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 rate limit after 3 failures, got %d (%s)", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil || errResp.Error.Code != dto.ErrRateLimited {
		t.Fatalf("expected RATE_LIMITED error code, got %s", rec.Body.String())
	}

	// 5. Valid token from normal IP succeeds
	rec = doRequest(t, h, http.MethodGet, "/api/v1/auth/verify", token, nil, "198.51.100.20:1000")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /api/v1/auth/verify, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEndToEndRESTAndDynamicSubscription(t *testing.T) {
	srv, token, _ := setupTestServer(t)
	h := srv.Handler()

	// 1. Configure server_public_host & sub_domain
	pubHost := "node1.example.com"
	rec := doRequest(t, h, http.MethodPut, "/api/v1/settings", token, dto.UpdateSettingsRequest{
		ServerPublicHost: &pubHost,
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/settings: %d %s", rec.Code, rec.Body.String())
	}

	// 2. Create user
	rec = doRequest(t, h, http.MethodPost, "/api/v1/users", token, dto.CreateUserRequest{
		Name:              "TestUser",
		Email:             "test@example.com",
		TrafficLimitBytes: 10 * 1024 * 1024 * 1024,
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/users: %d %s", rec.Code, rec.Body.String())
	}
	var userEnv dto.Envelope[dto.UserDTO]
	if err := json.Unmarshal(rec.Body.Bytes(), &userEnv); err != nil {
		t.Fatal(err)
	}
	user := userEnv.Data
	if !strings.HasPrefix(user.SubURLs.Base64, "https://node1.example.com/d/") {
		t.Fatalf("unexpected user sub_url: %+v", user.SubURLs)
	}

	// 3. Create VLESS XHTTP inbound with custom_sni AND a WireGuard inbound (excluded from sub)
	rec = doRequest(t, h, http.MethodPost, "/api/v1/inbounds", token, dto.UpsertInboundRequest{
		Tag:       "edge-xhttp",
		Protocol:  "vless",
		Transport: "xhttp",
		Path:      "/xhttp-test",
		CustomSNI: "cdn.example.com",
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/inbounds (vless): %d %s", rec.Code, rec.Body.String())
	}

	priv, _, _ := models.GenerateWGKeyPair()
	rec = doRequest(t, h, http.MethodPost, "/api/v1/inbounds", token, dto.UpsertInboundRequest{
		Tag:         "wg-relay",
		Protocol:    "wireguard",
		Port:        51822,
		WGSecretKey: priv,
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/inbounds (wireguard): %d %s", rec.Code, rec.Body.String())
	}

	// 4. Create Outbound + Routing Preset
	rec = doRequest(t, h, http.MethodPost, "/api/v1/outbounds", token, dto.UpsertOutboundRequest{
		Tag:    "local-socks",
		Type:   "socks5",
		Server: "127.0.0.1",
		Port:   1080,
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/outbounds: %d %s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, h, http.MethodPost, "/api/v1/routing/preset/china-direct", token, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/routing/preset/china-direct: %d %s", rec.Code, rec.Body.String())
	}

	// 5. Check Dashboard & Xray Config preview
	rec = doRequest(t, h, http.MethodGet, "/api/v1/dashboard", token, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/dashboard: %d %s", rec.Code, rec.Body.String())
	}
	var dashEnv dto.Envelope[dto.DashboardResponse]
	if err := json.Unmarshal(rec.Body.Bytes(), &dashEnv); err != nil {
		t.Fatal(err)
	}
	if dashEnv.Data.Users.Total != 1 || dashEnv.Data.Inbounds.Total != 2 || dashEnv.Data.Outbounds.Total != 1 {
		t.Fatalf("unexpected dashboard counts: %+v", dashEnv.Data)
	}

	rec = doRequest(t, h, http.MethodGet, "/api/v1/xray/config", token, nil, "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "socks-in") {
		t.Fatalf("GET /api/v1/xray/config unexpected: %d %s", rec.Code, rec.Body.String())
	}
	var cfgEnv dto.Envelope[dto.XrayConfigResponse]
	if err := json.Unmarshal(rec.Body.Bytes(), &cfgEnv); err != nil {
		t.Fatal(err)
	}
	// Preview is redacted: no full user UUID, no WireGuard private key.
	if strings.Contains(cfgEnv.Data.Raw, user.UUID) {
		t.Fatalf("GET /api/v1/xray/config leaks full user UUID")
	}
	if !strings.Contains(cfgEnv.Data.Raw, user.UUID[:8]+"****") {
		t.Fatalf("GET /api/v1/xray/config does not mask client id")
	}
	if strings.Contains(cfgEnv.Data.Raw, priv) {
		t.Fatalf("GET /api/v1/xray/config leaks WireGuard secretKey")
	}
	// Nothing applied yet: dirty with empty applied hash.
	if !cfgEnv.Data.Dirty || cfgEnv.Data.AppliedHash != "" || cfgEnv.Data.CurrentHash == "" {
		t.Fatalf("unexpected xray config dirty state: %+v", cfgEnv.Data)
	}

	// 6. Test public subscription formats under default /d/{sub_path}
	rec = doRequest(t, h, http.MethodGet, "/d/"+user.SubPath, "", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /d/%s: %d %s", user.SubPath, rec.Code, rec.Body.String())
	}
	decoded, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatalf("invalid base64 subscription: %v", err)
	}
	if !strings.Contains(string(decoded), "vless://"+user.UUID+"@cdn.example.com:443") || strings.Contains(string(decoded), "wg-relay") {
		t.Fatalf("unexpected decoded subscription links: %s", string(decoded))
	}
	if rec.Header().Get("Subscription-Userinfo") == "" {
		t.Errorf("expected Subscription-Userinfo header")
	}

	// JSON and YAML formats
	rec = doRequest(t, h, http.MethodGet, "/d/"+user.SubPath+"/json", "", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"count":1`) {
		t.Fatalf("unexpected JSON subscription: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRequest(t, h, http.MethodGet, "/d/"+user.SubPath+"/yaml", "", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "type: vless") {
		t.Fatalf("unexpected YAML subscription: %d %s", rec.Code, rec.Body.String())
	}

	// 7. Dynamic sub_path change takes effect IMMEDIATELY without restarting server
	newPrefix := "/vip-feed"
	rec = doRequest(t, h, http.MethodPut, "/api/v1/settings", token, dto.UpdateSettingsRequest{SubPath: &newPrefix}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/settings sub_path: %d %s", rec.Code, rec.Body.String())
	}

	// Old prefix must return 404 now
	rec = doRequest(t, h, http.MethodGet, "/d/"+user.SubPath, "", nil, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on old sub_path /d, got %d", rec.Code)
	}

	// New prefix must return 200 immediately
	rec = doRequest(t, h, http.MethodGet, "/vip-feed/"+user.SubPath+"/txt", "", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "vless://") {
		t.Fatalf("expected 200 on new sub_path /vip-feed, got %d %s", rec.Code, rec.Body.String())
	}

	// 8. Disabled user receives 403 Forbidden
	rec = doRequest(t, h, http.MethodPost, "/api/v1/users/"+user.ID+"/toggle", token, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle user failed: %d", rec.Code)
	}
	rec = doRequest(t, h, http.MethodGet, "/vip-feed/"+user.SubPath, "", nil, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disabled user subscription, got %d", rec.Code)
	}

	// 9. Subscription rate limit (30 req/min)
	subIP := "198.51.100.77:9999"
	for i := 0; i < 30; i++ {
		rec = doRequest(t, h, http.MethodGet, "/vip-feed/"+user.SubPath, "", nil, subIP)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("rate limited early at request %d", i+1)
		}
	}
	rec = doRequest(t, h, http.MethodGet, "/vip-feed/"+user.SubPath, "", nil, subIP)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 31st subscription request within 1m, got %d", rec.Code)
	}
}

func TestCertUploadSubscriptionNginxAndTunnelRoutes(t *testing.T) {
	srv, token, _ := setupTestServer(t)
	h := srv.Handler()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject:      pkix.Name{CommonName: "sub-api.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		DNSNames:     []string{"sub-api.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	// Upload cert
	rec := doRequest(t, h, http.MethodPost, "/api/v1/domains/upload-cert", token, dto.UploadCertRequest{
		Domain:  "sub-api.example.com",
		Type:    "direct",
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"has_cert":true`) {
		t.Fatalf("POST /api/v1/domains/upload-cert failed: %d %s", rec.Code, rec.Body.String())
	}

	// Set sub_domain & enable subscription nginx proxy
	subDom := "sub-api.example.com"
	rec = doRequest(t, h, http.MethodPut, "/api/v1/settings", token, dto.UpdateSettingsRequest{SubDomain: &subDom}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/settings failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, h, http.MethodPost, "/api/v1/subscription/nginx", token, nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"matched_cert_domain":"sub-api.example.com"`) {
		t.Fatalf("POST /api/v1/subscription/nginx failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, h, http.MethodDelete, "/api/v1/subscription/nginx", token, nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("DELETE /api/v1/subscription/nginx failed: %d %s", rec.Code, rec.Body.String())
	}

	// API Nginx reverse proxy routes
	apiDom := "sub-api.example.com"
	rec = doRequest(t, h, http.MethodPut, "/api/v1/settings", token, dto.UpdateSettingsRequest{APIDomain: &apiDom}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/settings api_domain failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRequest(t, h, http.MethodPost, "/api/v1/panel/nginx", token, nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"direct_url":"https://sub-api.example.com"`) {
		t.Fatalf("POST /api/v1/panel/nginx failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRequest(t, h, http.MethodDelete, "/api/v1/panel/nginx", token, nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("DELETE /api/v1/panel/nginx failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, h, http.MethodGet, "/api/v1/tunnels/cf/status", token, nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"recommended_path_rule":"/d/*"`) {
		t.Fatalf("GET /api/v1/tunnels/cf/status unexpected: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSpeedtestEndpoints(t *testing.T) {
	srv, token, _ := setupTestServer(t)
	h := srv.Handler()

	rec := doRequest(t, h, http.MethodGet, "/api/v1/speedtest", "", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/v1/speedtest without token: got %d, want 401", rec.Code)
	}

	rec = doRequest(t, h, http.MethodGet, "/api/v1/speedtest", token, nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) || !strings.Contains(rec.Body.String(), `"sub_path":"/speedtest"`) {
		t.Fatalf("GET /api/v1/speedtest unexpected: %d %s", rec.Code, rec.Body.String())
	}

	bad := "not a domain"
	rec = doRequest(t, h, http.MethodPut, "/api/v1/speedtest", token, dto.UpdateSpeedtestRequest{Domain: &bad}, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT invalid domain: got %d, want 400: %s", rec.Code, rec.Body.String())
	}

	dom := "jp-speed.example.com"
	sub := "/x7f9k2"
	rec = doRequest(t, h, http.MethodPut, "/api/v1/speedtest", token, dto.UpdateSpeedtestRequest{Domain: &dom, SubPath: &sub}, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"domain":"jp-speed.example.com"`) || !strings.Contains(rec.Body.String(), `"sub_path":"/x7f9k2"`) {
		t.Fatalf("PUT /api/v1/speedtest failed: %d %s", rec.Code, rec.Body.String())
	}

	// Start/stop work end to end through the test server (file + nginx
	// config land in temp dirs via setupTestServer).
	rec = doRequest(t, h, http.MethodPost, "/api/v1/speedtest/start", token, nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("POST /api/v1/speedtest/start failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRequest(t, h, http.MethodPost, "/api/v1/speedtest/stop", token, nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("POST /api/v1/speedtest/stop failed: %d %s", rec.Code, rec.Body.String())
	}
}
