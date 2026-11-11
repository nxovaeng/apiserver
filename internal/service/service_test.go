package service_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"xray-panel-server/internal/config"
	"xray-panel-server/internal/database"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/nginx"
	"xray-panel-server/internal/service"
	"xray-panel-server/internal/wireguard"
)

func setupTestEnv(t *testing.T) (*gorm.DB, *config.Config, string) {
	t.Helper()
	tmpDir := t.TempDir()

	db, err := database.Init(filepath.Join(tmpDir, "panel.db"))
	if err != nil {
		t.Fatalf("database.Init: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		t.Fatalf("database.Migrate: %v", err)
	}

	cfg := config.Default()
	cfg.Database.Path = filepath.Join(tmpDir, "panel.db")
	cfg.Nginx.ConfigDir = filepath.Join(tmpDir, "nginx", "conf.d")
	cfg.Nginx.StreamDir = filepath.Join(tmpDir, "nginx", "stream.d")
	cfg.Nginx.CertDir = filepath.Join(tmpDir, "acme")
	cfg.Nginx.ReloadCmd = "true"
	cfg.Xray.ConfigPath = filepath.Join(tmpDir, "xray", "config.json")
	cfg.Xray.AssetsPath = filepath.Join(tmpDir, "xray-assets")
	cfg.Xray.SocketDir = tmpDir

	return db, cfg, tmpDir
}

func writeSelfSignedCert(t *testing.T, certPath, keyPath string, dnsNames []string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		t.Fatal(err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestTokenSeedAuthAndLifecycle(t *testing.T) {
	db, cfg, _ := setupTestEnv(t)

	seedRes, err := database.Seed(db, cfg)
	if err != nil {
		t.Fatalf("database.Seed: %v", err)
	}
	if !strings.HasPrefix(seedRes.InitialTokenPlaintext, "xrp_") || len(seedRes.InitialTokenPlaintext) != 52 {
		t.Fatalf("unexpected seeded token format: %q (len=%d)", seedRes.InitialTokenPlaintext, len(seedRes.InitialTokenPlaintext))
	}

	// Verify DB never stores plaintext
	var stored models.APIToken
	if err := db.First(&stored).Error; err != nil {
		t.Fatalf("query seeded token: %v", err)
	}
	if stored.TokenHash == seedRes.InitialTokenPlaintext || len(stored.TokenHash) != 64 {
		t.Fatalf("expected 64-char SHA-256 hash, got %q", stored.TokenHash)
	}

	cfg.Auth.BootstrapTokens = []string{"xrp_bootstrap_static_token_value"}
	tokSvc := service.NewTokenService(db, cfg, "1.0.0")

	// Authenticate seeded DB token
	ctx1, err := tokSvc.Authenticate(seedRes.InitialTokenPlaintext, "127.0.0.1")
	if err != nil || ctx1.IsBootstrap || ctx1.TokenName != "default" {
		t.Fatalf("expected valid default DB token, got ctx=%+v err=%v", ctx1, err)
	}

	// Authenticate bootstrap token
	ctxBoot, err := tokSvc.Authenticate("xrp_bootstrap_static_token_value", "10.0.0.5")
	if err != nil || !ctxBoot.IsBootstrap {
		t.Fatalf("expected valid bootstrap token, got ctx=%+v err=%v", ctxBoot, err)
	}

	// Create new token with expiry, authenticate, then revoke
	days := 7
	created, err := tokSvc.Create(dto.CreateTokenRequest{Name: "laptop", ExpiresDays: &days})
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	if !strings.HasPrefix(created.PlaintextToken, "xrp_") {
		t.Fatalf("unexpected created token: %s", created.PlaintextToken)
	}

	if _, err := tokSvc.Authenticate(created.PlaintextToken, "192.168.1.2"); err != nil {
		t.Fatalf("Authenticate created token: %v", err)
	}

	if _, err := tokSvc.RevokeOrDelete(created.Token.ID, false); err != nil {
		t.Fatalf("RevokeOrDelete: %v", err)
	}
	if _, err := tokSvc.Authenticate(created.PlaintextToken, "192.168.1.2"); err == nil {
		t.Fatalf("revoked token must fail authentication")
	}

	// Purge token
	delRes, err := tokSvc.RevokeOrDelete(created.Token.ID, true)
	if err != nil || !delRes.Deleted {
		t.Fatalf("expected deleted=true, got %+v err=%v", delRes, err)
	}
}

func TestUserUpdatePreservesImmutableFieldsAndUsesPublicHost(t *testing.T) {
	db, cfg, _ := setupTestEnv(t)
	if _, err := database.Seed(db, cfg); err != nil {
		t.Fatal(err)
	}

	sysSvc := service.NewSystemService(db, cfg, nil)
	host := "vps.example.com"
	if _, err := sysSvc.UpdateSettings(dto.UpdateSettingsRequest{ServerPublicHost: &host}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	userSvc := service.NewUserService(db)
	created, err := userSvc.Create(dto.CreateUserRequest{
		Name:              "Alice",
		Email:             "alice@example.com",
		TrafficLimitBytes: 1024 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}
	if !strings.HasPrefix(created.SubURLs.Base64, "https://vps.example.com/d/") {
		t.Fatalf("expected sub_url to use server_public_host, got %s", created.SubURLs.Base64)
	}

	// Simulate traffic sync updating TrafficUsed in DB
	now := time.Now().UTC()
	db.Model(&models.User{}).Where("id = ?", created.ID).Updates(map[string]interface{}{
		"traffic_used":  int64(500000),
		"traffic_reset": &now,
	})

	// Update user: SubPath, TrafficUsed, TrafficReset, CreatedAt must NOT be wiped
	updated, err := userSvc.Update(created.ID, dto.UpdateUserRequest{
		Name:              "Alice Updated",
		Email:             "alice2@example.com",
		TrafficLimitBytes: 2048,
	})
	if err != nil {
		t.Fatalf("Update user: %v", err)
	}
	if updated.SubPath != created.SubPath {
		t.Errorf("SubPath changed on update: %s -> %s", created.SubPath, updated.SubPath)
	}
	if updated.TrafficUsedBytes != 500000 {
		t.Errorf("TrafficUsedBytes lost on update: got %d", updated.TrafficUsedBytes)
	}
	if updated.TrafficResetAt == nil {
		t.Errorf("TrafficResetAt lost on update")
	}

	// Reset traffic
	resetUser, err := userSvc.ResetTraffic(created.ID)
	if err != nil || resetUser.TrafficUsedBytes != 0 {
		t.Fatalf("ResetTraffic failed: %+v err=%v", resetUser, err)
	}
}

func TestDomainsInboundsAndNginxLifecycle(t *testing.T) {
	db, cfg, tmpDir := setupTestEnv(t)
	if _, err := database.Seed(db, cfg); err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(cfg.Nginx.CertDir, "example.com_ecc", "fullchain.cer")
	keyPath := filepath.Join(cfg.Nginx.CertDir, "example.com_ecc", "example.com_ecc.key")
	writeSelfSignedCert(t, certPath, keyPath, []string{"*.example.com", "example.com"})

	domSvc := service.NewDomainService(db, cfg)

	// Invalid domain format must be rejected
	if _, err := domSvc.Create(dto.UpsertDomainRequest{Domain: "not a domain", CertPath: certPath, KeyPath: keyPath}); err == nil {
		t.Fatalf("expected validation error for invalid domain")
	}

	// Scan and import wildcard cert
	scanRes, err := domSvc.ScanCertificates()
	if err != nil || scanRes.Count != 1 || !scanRes.Certificates[0].IsWildcard {
		t.Fatalf("unexpected scan result: %+v err=%v", scanRes, err)
	}
	impRes, err := domSvc.ScanAndImportCertificates()
	if err != nil || impRes.ImportedCount != 1 || len(impRes.Domains) != 1 {
		t.Fatalf("unexpected scan-import result: %+v err=%v", impRes, err)
	}
	dom := impRes.Domains[0]
	if dom.Domain != "*.example.com" || !dom.IsWildcard || !dom.HasCert {
		t.Fatalf("unexpected imported domain: %+v", dom)
	}

	nginxGen := nginx.NewGenerator(cfg.Nginx.ConfigDir, cfg.Nginx.StreamDir)
	nginxGen.SetDB(db)
	nginxGen.SetSocketDir(tmpDir)
	nginxGen.SetReloadCmd("true")

	inbSvc := service.NewInboundService(db, cfg, nginxGen)
	inb, err := inbSvc.Create(dto.UpsertInboundRequest{
		Tag:      "edge-xhttp",
		Protocol: "vless",
		DomainID: dom.ID,
	})
	if err != nil {
		t.Fatalf("Create inbound: %v", err)
	}
	if !strings.HasSuffix(inb.ActualDomain, ".example.com") || inb.ActualDomain == "*.example.com" {
		t.Fatalf("expected generated random subdomain for wildcard cert, got %q", inb.ActualDomain)
	}

	nginxFile := filepath.Join(cfg.Nginx.ConfigDir, inb.ActualDomain+".conf")
	if _, err := os.Stat(nginxFile); err != nil {
		t.Fatalf("expected generated nginx config file %s: %v", nginxFile, err)
	}

	// Create WireGuard inbound & verify secret preservation on update
	priv, _, err := models.GenerateWGKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wgInb, err := inbSvc.Create(dto.UpsertInboundRequest{
		Tag:         "wg-relay",
		Protocol:    "wireguard",
		Port:        51825,
		WGSecretKey: priv,
	})
	if err != nil {
		t.Fatalf("Create wireguard inbound: %v", err)
	}
	if !wgInb.HasWGSecretKey || !wgInb.ExcludeFromSub || wgInb.UseUDS {
		t.Fatalf("unexpected wireguard inbound defaults: %+v", wgInb)
	}
	wgUpdated, err := inbSvc.Update(wgInb.ID, dto.UpsertInboundRequest{
		Tag:      "wg-relay",
		Protocol: "wireguard",
		Remark:   "updated without touching secret",
	})
	if err != nil || !wgUpdated.HasWGSecretKey {
		t.Fatalf("Update wireguard inbound should preserve secret: %+v err=%v", wgUpdated, err)
	}

	// Delete proxy inbound cleans up nginx config
	if _, err := inbSvc.Delete(inb.ID); err != nil {
		t.Fatalf("Delete inbound: %v", err)
	}
	if _, err := os.Stat(nginxFile); !os.IsNotExist(err) {
		t.Fatalf("expected nginx config file %s to be deleted", nginxFile)
	}
}

func TestOutboundsSecretsShareLinksAndWGParse(t *testing.T) {
	db, cfg, _ := setupTestEnv(t)
	outSvc := service.NewOutboundService(db, cfg)

	priv, _, _ := models.GenerateWGKeyPair()
	_, peerPub, _ := models.GenerateWGKeyPair()

	created, err := outSvc.Create(dto.UpsertOutboundRequest{
		Tag:         "warp-out",
		Type:        "wireguard",
		Server:      "engage.cloudflareclient.com",
		Port:        2408,
		WGSecretKey: priv,
		WGPublicKey: peerPub,
		WGLocalIPv4: "172.16.0.2/32",
	})
	if err != nil || !created.HasWGSecretKey || created.WGClientPubKey == "" {
		t.Fatalf("Create wireguard outbound failed: %+v err=%v", created, err)
	}

	// Update leaving WGSecretKey empty must preserve existing secret & client pubkey
	updated, err := outSvc.Update(created.ID, dto.UpsertOutboundRequest{
		Tag:         "warp-out",
		Type:        "wireguard",
		Server:      "engage.cloudflareclient.com",
		Port:        2408,
		WGPublicKey: peerPub,
		WGLocalIPv4: "172.16.0.2/32",
		Remark:      "kept secret",
	})
	if err != nil || !updated.HasWGSecretKey || updated.WGClientPubKey != created.WGClientPubKey {
		t.Fatalf("expected secret and derived pubkey to be preserved: %+v err=%v", updated, err)
	}

	// Parse WireGuard config
	parsed, err := outSvc.ParseWireGuardConfig("[Interface]\nPrivateKey = " + priv + "\nAddress = 10.2.0.2/32, fd00::2/128\nDNS = 1.1.1.1\nMTU = 1380\n[Peer]\nPublicKey = " + peerPub + "\nEndpoint = 1.2.3.4:51820\n")
	if err != nil {
		t.Fatalf("ParseWireGuardConfig: %v", err)
	}
	if parsed.Server != "1.2.3.4" || parsed.Port != 51820 || parsed.ClientPublicKey == "" || parsed.MTU != 1380 {
		t.Fatalf("unexpected parsed WG config: %+v", parsed)
	}

	// Import share link twice (verifying tag disambiguation)
	link := "vless://11111111-1111-1111-1111-111111111111@hk.example.com:443?type=ws&security=tls&sni=hk.example.com&path=%2Fws#HK1"
	imp1, err := outSvc.ImportShareLink(link)
	if err != nil || imp1.Server != "hk.example.com" || imp1.Port != 443 {
		t.Fatalf("ImportShareLink #1 failed: %+v err=%v", imp1, err)
	}
	imp2, err := outSvc.ImportShareLink(link)
	if err != nil || imp2.Tag == imp1.Tag {
		t.Fatalf("ImportShareLink #2 should succeed with distinct tag: %+v err=%v", imp2, err)
	}
}

func TestWireGuardServiceConflictAndExport(t *testing.T) {
	db, cfg, tmpDir := setupTestEnv(t)
	if _, err := database.Seed(db, cfg); err != nil {
		t.Fatal(err)
	}

	// Create an enabled inbound on port 51820 to test conflict detection
	db.Create(&models.Inbound{
		ID: "inb-1", Tag: "conflict-in", Protocol: models.ProtocolVLESS,
		Transport: models.TransportWS, Port: 51820, UseUDS: false, Enabled: true,
	})

	sysSvc := service.NewSystemService(db, cfg, nil)
	pubHost := "wg.example.com"
	_, _ = sysSvc.UpdateSettings(dto.UpdateSettingsRequest{ServerPublicHost: &pubHost})

	wgMgr := wireguard.NewManagerWithConfPath(db, filepath.Join(tmpDir, "wg0.conf"))
	wgSvc := service.NewWireGuardServiceWithManager(db, wgMgr)

	if _, err := wgSvc.UpdateServerConfig(dto.UpdateWGServerRequest{ListenPort: 51820}); err == nil {
		t.Fatalf("expected conflict error when port 51820 is used by enabled inbound")
	}

	updatedSrv, err := wgSvc.UpdateServerConfig(dto.UpdateWGServerRequest{ListenPort: 51830})
	if err != nil || updatedSrv.ListenPort != 51830 || !updatedSrv.HasPrivateKey {
		t.Fatalf("UpdateServerConfig failed: %+v err=%v", updatedSrv, err)
	}

	keys, err := wgSvc.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := wgSvc.CreatePeer(dto.UpsertWGPeerRequest{
		Name:       "relay-tokyo",
		PrivateKey: keys.PrivateKey,
	})
	if err != nil || peer.PublicKey != keys.PublicKey || peer.AllowedIPs != "10.0.0.2/32" {
		t.Fatalf("CreatePeer failed: %+v err=%v", peer, err)
	}

	exp, err := wgSvc.ExportPeerConfig(peer.ID)
	if err != nil {
		t.Fatalf("ExportPeerConfig: %v", err)
	}
	if exp.ServerHost != "wg.example.com" || !strings.Contains(exp.WGConf, "Endpoint = wg.example.com:51830") {
		t.Fatalf("unexpected exported peer config: %+v", exp)
	}
}

func TestSettingsAndXrayApplyValidation(t *testing.T) {
	db, cfg, tmpDir := setupTestEnv(t)
	if _, err := database.Seed(db, cfg); err != nil {
		t.Fatal(err)
	}

	// Fake xray binary script that succeeds on `-test`
	fakeXray := filepath.Join(tmpDir, "xray-ok.sh")
	if err := os.WriteFile(fakeXray, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg.Xray.BinaryPath = fakeXray

	nginxGen := nginx.NewGenerator(cfg.Nginx.ConfigDir, cfg.Nginx.StreamDir)
	nginxGen.SetDB(db)
	nginxGen.SetReloadCmd("true")

	sysSvc := service.NewSystemService(db, cfg, nginxGen)

	badSub := "/api/v1"
	if _, err := sysSvc.UpdateSettings(dto.UpdateSettingsRequest{SubPath: &badSub}); err == nil {
		t.Fatalf("expected error when sub_path conflicts with /api")
	}

	newSub := "secret-sub/"
	updated, err := sysSvc.UpdateSettings(dto.UpdateSettingsRequest{SubPath: &newSub})
	if err != nil || updated.SubPath != "/secret-sub" {
		t.Fatalf("expected normalized /secret-sub, got %+v err=%v", updated, err)
	}

	applyRes, err := sysSvc.ApplyXrayConfig(false)
	if err != nil || !applyRes.Applied {
		t.Fatalf("ApplyXrayConfig with passing validator failed: %+v err=%v", applyRes, err)
	}

	// Failing xray -test must return XRAY_VALIDATION_FAILED
	badXray := filepath.Join(tmpDir, "xray-fail.sh")
	if err := os.WriteFile(badXray, []byte("#!/bin/sh\necho 'invalid inbound' >&2\nexit 2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg.Xray.BinaryPath = badXray
	if _, err := sysSvc.ApplyXrayConfig(false); err == nil {
		t.Fatalf("expected XRAY_VALIDATION_FAILED error")
	} else if appErr, ok := service.AsAppError(err); !ok || appErr.Code != dto.ErrXrayValidationFailed {
		t.Fatalf("expected ErrXrayValidationFailed, got %v", err)
	}
}
