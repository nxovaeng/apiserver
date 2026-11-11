package service_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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
	cfg.Nginx.TestCmd = "true"
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

	// Fake systemctl on PATH so `systemctl restart xray` succeeds in tests.
	// The script is rewritten to fail later in this test to cover the
	// restart-failure path.
	systemctlPath := filepath.Join(tmpDir, "systemctl")
	if err := os.WriteFile(systemctlPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tmpDir+string(os.PathListSeparator)+os.Getenv("PATH"))

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

	// 1. First apply: real change, must write + restart.
	applyRes, err := sysSvc.ApplyXrayConfig()
	if err != nil || !applyRes.Applied || !applyRes.Changed || applyRes.Method != "restart" {
		t.Fatalf("ApplyXrayConfig with passing validator failed: %+v err=%v", applyRes, err)
	}
	if len(applyRes.Warnings) != 0 {
		t.Fatalf("unexpected warnings on clean apply: %v", applyRes.Warnings)
	}
	firstDisk, err := os.ReadFile(cfg.Xray.ConfigPath)
	if err != nil {
		t.Fatalf("applied config not on disk: %v", err)
	}

	// Preview is not dirty right after a successful apply.
	preview, err := sysSvc.GetXrayConfigPreview()
	if err != nil {
		t.Fatal(err)
	}
	if preview.Dirty || preview.CurrentHash == "" || preview.AppliedHash != preview.CurrentHash {
		t.Fatalf("expected clean preview after apply: %+v", preview)
	}

	// 2. Second apply without changes: unchanged, no write, no restart.
	applyRes, err = sysSvc.ApplyXrayConfig()
	if err != nil || applyRes.Applied || applyRes.Changed || applyRes.Method != "unchanged" {
		t.Fatalf("expected unchanged second apply: %+v err=%v", applyRes, err)
	}
	if !strings.Contains(applyRes.Message, "无变化") {
		t.Fatalf("unexpected unchanged message: %q", applyRes.Message)
	}
	secondDisk, _ := os.ReadFile(cfg.Xray.ConfigPath)
	if !bytes.Equal(firstDisk, secondDisk) {
		t.Fatalf("unchanged apply rewrote the config file")
	}

	// 3. Change the config (log level) -> preview dirty, apply writes + keeps .bak.
	debugLvl := "debug"
	if _, err := sysSvc.UpdateSettings(dto.UpdateSettingsRequest{XrayLogLevel: &debugLvl}); err != nil {
		t.Fatal(err)
	}
	preview, err = sysSvc.GetXrayConfigPreview()
	if err != nil {
		t.Fatal(err)
	}
	if !preview.Dirty || preview.CurrentHash == preview.AppliedHash {
		t.Fatalf("expected dirty preview after settings change: %+v", preview)
	}
	applyRes, err = sysSvc.ApplyXrayConfig()
	if err != nil || !applyRes.Applied || !applyRes.Changed {
		t.Fatalf("apply after change failed: %+v err=%v", applyRes, err)
	}
	bak, err := os.ReadFile(cfg.Xray.ConfigPath + ".bak")
	if err != nil {
		t.Fatalf("expected config.json.bak after second real apply: %v", err)
	}
	if !bytes.Equal(bak, firstDisk) {
		t.Fatalf("config.json.bak does not contain the previous config")
	}

	// 4. Failing xray -test must return XRAY_VALIDATION_FAILED and leave the
	// last good config (and no temp files) on disk.
	badXray := filepath.Join(tmpDir, "xray-fail.sh")
	if err := os.WriteFile(badXray, []byte("#!/bin/sh\necho 'invalid inbound' >&2\nexit 2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg.Xray.BinaryPath = badXray
	warnLvl := "warning"
	if _, err := sysSvc.UpdateSettings(dto.UpdateSettingsRequest{XrayLogLevel: &warnLvl}); err != nil {
		t.Fatal(err)
	}
	goodDisk, _ := os.ReadFile(cfg.Xray.ConfigPath)
	if _, err := sysSvc.ApplyXrayConfig(); err == nil {
		t.Fatalf("expected XRAY_VALIDATION_FAILED error")
	} else if appErr, ok := service.AsAppError(err); !ok || appErr.Code != dto.ErrXrayValidationFailed {
		t.Fatalf("expected ErrXrayValidationFailed, got %v", err)
	}
	afterFailDisk, _ := os.ReadFile(cfg.Xray.ConfigPath)
	if !bytes.Equal(goodDisk, afterFailDisk) {
		t.Fatalf("failed validation left an invalid config on disk")
	}
	if temps, _ := filepath.Glob(filepath.Join(filepath.Dir(cfg.Xray.ConfigPath), ".config.json.*")); len(temps) != 0 {
		t.Fatalf("temp config files left behind: %v", temps)
	}
	cfg.Xray.BinaryPath = fakeXray

	// 5. Restart failure must return an error and must not update the
	// applied hash (preview stays dirty, next apply retries the restart).
	if err := os.WriteFile(systemctlPath, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	previewBefore, err := sysSvc.GetXrayConfigPreview()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sysSvc.ApplyXrayConfig(); err == nil {
		t.Fatalf("expected error when systemctl restart fails")
	} else if appErr, ok := service.AsAppError(err); !ok || appErr.Code != dto.ErrSystemCommandFailed {
		t.Fatalf("expected ErrSystemCommandFailed, got %v", err)
	}
	previewAfter, err := sysSvc.GetXrayConfigPreview()
	if err != nil {
		t.Fatal(err)
	}
	if previewAfter.AppliedHash != previewBefore.AppliedHash || !previewAfter.Dirty {
		t.Fatalf("failed restart must not update applied hash: before=%+v after=%+v", previewBefore, previewAfter)
	}
	// Restore working systemctl: the retry must succeed. The disk already
	// holds the new config, but the applied hash differs, so it must not
	// take the unchanged shortcut.
	if err := os.WriteFile(systemctlPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	applyRes, err = sysSvc.ApplyXrayConfig()
	if err != nil || !applyRes.Applied || !applyRes.Changed {
		t.Fatalf("retry after failed restart failed: %+v err=%v", applyRes, err)
	}
}

func TestXrayConfigPreviewRedaction(t *testing.T) {
	db, cfg, _ := setupTestEnv(t)
	if _, err := database.Seed(db, cfg); err != nil {
		t.Fatal(err)
	}

	const userUUID = "550e8400-e29b-41d4-a716-446655440000"
	if err := db.Create(&models.User{
		UUID:    userUUID,
		Name:    "redact-user",
		Email:   "redact@example.com",
		Enabled: true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.Inbound{
		ID: "inb-vless", Tag: "vless-in", Protocol: models.ProtocolVLESS,
		Transport: models.TransportWS, Port: 10001, UseUDS: false,
		Enabled: true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	const wgSecret = "WGSECRET-PRIVATE-KEY-DO-NOT-LEAK"
	if err := db.Create(&models.Inbound{
		ID: "inb-wg", Tag: "wg-in", Protocol: models.ProtocolWireGuard,
		Port: 51820, UseUDS: false, WGSecretKey: wgSecret,
		Enabled: true,
	}).Error; err != nil {
		t.Fatal(err)
	}

	sysSvc := service.NewSystemService(db, cfg, nil)
	preview, err := sysSvc.GetXrayConfigPreview()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(preview.Raw, userUUID) {
		t.Fatalf("preview Raw leaks full user UUID")
	}
	if !strings.Contains(preview.Raw, userUUID[:8]+"****") {
		t.Fatalf("preview Raw does not contain masked client id, raw=%s", preview.Raw)
	}
	if strings.Contains(preview.Raw, wgSecret) {
		t.Fatalf("preview Raw leaks WireGuard secretKey")
	}
	if !strings.Contains(preview.Raw, `"secretKey": "***"`) {
		t.Fatalf("preview Raw does not redact secretKey, raw=%s", preview.Raw)
	}
	// Dirty: never applied.
	if !preview.Dirty || preview.AppliedHash != "" || preview.CurrentHash == "" {
		t.Fatalf("expected dirty preview before any apply: %+v", preview)
	}
	// The decoded config map must be redacted too, not just Raw.
	inbounds, ok := preview.Config["inbounds"].([]interface{})
	if !ok || len(inbounds) == 0 {
		t.Fatalf("preview config has no inbounds: %+v", preview.Config)
	}
	found := false
	for _, rawIn := range inbounds {
		in, ok := rawIn.(map[string]interface{})
		if !ok {
			continue
		}
		settings, ok := in["settings"].(map[string]interface{})
		if !ok {
			continue
		}
		clients, ok := settings["clients"].([]interface{})
		if !ok {
			continue
		}
		for _, rawCl := range clients {
			cl, ok := rawCl.(map[string]interface{})
			if !ok {
				continue
			}
			if id, _ := cl["id"].(string); id != "" {
				found = true
				if id != userUUID[:8]+"****" {
					t.Fatalf("client id not masked in config map: %q", id)
				}
			}
		}
	}
	if !found {
		t.Fatalf("no client id found in preview config")
	}
}

type fakeAcmeRunner struct {
	certDir string
	calls   [][]string
	envs    [][]string
	fail    bool
	code    int
	out     string
}

func (f *fakeAcmeRunner) Run(ctx context.Context, args []string, extraEnv []string) (string, int, error) {
	f.calls = append(f.calls, append([]string{}, args...))
	f.envs = append(f.envs, append([]string{}, extraEnv...))
	if f.fail {
		return f.out, f.code, errors.New("acme failed")
	}
	// Find -d base domain and emit valid self-signed files
	var baseDomain string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-d" && !strings.HasPrefix(args[i+1], "*.") {
			baseDomain = args[i+1]
			break
		}
	}
	if baseDomain != "" && f.code != -99 {
		eccDir := filepath.Join(f.certDir, baseDomain+"_ecc")
		_ = os.MkdirAll(eccDir, 0755)
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: baseDomain},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
			DNSNames:     []string{baseDomain, "*." + baseDomain},
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		keyDER, _ := x509.MarshalECPrivateKey(priv)
		_ = os.WriteFile(filepath.Join(eccDir, "fullchain.cer"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
		_ = os.WriteFile(filepath.Join(eccDir, baseDomain+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)
	}
	if f.code == 2 {
		return f.out, 2, errors.New("exit status 2")
	}
	return f.out, 0, nil
}

func TestCertificateUploadACMEIssueAndSubNginxProxy(t *testing.T) {
	db, cfg, tmpDir := setupTestEnv(t)
	if _, err := database.Seed(db, cfg); err != nil {
		t.Fatal(err)
	}

	domSvc := service.NewDomainService(db, cfg)

	// 1. Generate valid PEM pair and a mismatched key, test UploadCertificate
	certFile := filepath.Join(tmpDir, "src.pem")
	keyFile := filepath.Join(tmpDir, "src.key")
	otherCert := filepath.Join(tmpDir, "other.pem")
	otherKey := filepath.Join(tmpDir, "other.key")
	writeSelfSignedCert(t, certFile, keyFile, []string{"sub.example.com"})
	writeSelfSignedCert(t, otherCert, otherKey, []string{"other.example.com"})

	certBytes, _ := os.ReadFile(certFile)
	keyBytes, _ := os.ReadFile(keyFile)
	otherKeyBytes, _ := os.ReadFile(otherKey)

	if _, err := domSvc.UploadCertificate(dto.UploadCertRequest{
		Domain:  "sub.example.com",
		CertPEM: string(certBytes),
		KeyPEM:  string(otherKeyBytes),
	}); err == nil {
		t.Fatalf("expected validation error for mismatched certificate and private key")
	}

	uploaded, err := domSvc.UploadCertificate(dto.UploadCertRequest{
		Domain:  "sub.example.com",
		Type:    "direct",
		CertPEM: string(certBytes),
		KeyPEM:  string(keyBytes),
	})
	if err != nil || !uploaded.HasCert || uploaded.Domain != "sub.example.com" {
		t.Fatalf("UploadCertificate failed: %+v err=%v", uploaded, err)
	}

	// 2. Test ACME IssueCertificate with Cloudflare and LuaDNS + secret redaction
	runner := &fakeAcmeRunner{certDir: cfg.Nginx.CertDir, out: "issued ok"}
	domSvc.SetAcmeRunner(runner)

	cfRes, err := domSvc.IssueCertificate(context.Background(), dto.IssueCertRequest{
		Domain:          "cf.example.com",
		IncludeWildcard: true,
		Provider:        "cf",
		CFToken:         "cf-secret-token-xyz",
		CAServer:        "letsencrypt",
	})
	if err != nil || cfRes.Domain.Domain != "*.cf.example.com" || !cfRes.Domain.IsWildcard || !cfRes.Domain.HasCert {
		t.Fatalf("IssueCertificate cf failed: %+v err=%v", cfRes, err)
	}
	if len(runner.envs) == 0 || !strings.Contains(strings.Join(runner.envs[0], ","), "CF_Token=cf-secret-token-xyz") {
		t.Fatalf("expected CF_Token env passed to acme runner, got %+v", runner.envs)
	}

	luaRes, err := domSvc.IssueCertificate(context.Background(), dto.IssueCertRequest{
		Domain:   "lua.example.com",
		Provider: "luadns",
		LuaKey:   "lua-secret-key",
		LuaEmail: "ops@example.com",
	})
	if err != nil || luaRes.Provider != "luadns" || luaRes.Domain.Domain != "lua.example.com" {
		t.Fatalf("IssueCertificate luadns failed: %+v err=%v", luaRes, err)
	}

	// Secret redaction check on error
	failRunner := &fakeAcmeRunner{certDir: cfg.Nginx.CertDir, fail: true, code: 1, out: "bad token: cf-secret-999"}
	domSvc.SetAcmeRunner(failRunner)
	_, err = domSvc.IssueCertificate(context.Background(), dto.IssueCertRequest{
		Domain:   "bad.example.com",
		Provider: "cf",
		CFToken:  "cf-secret-999",
	})
	if err == nil || strings.Contains(err.Error(), "cf-secret-999") {
		t.Fatalf("expected redacted secret in error message, got %v", err)
	}

	// 3. Subscription Nginx proxy standalone & shared inbound + disable cleanup
	nginxGen := nginx.NewGenerator(cfg.Nginx.ConfigDir, cfg.Nginx.StreamDir)
	nginxGen.SetDB(db)
	nginxGen.SetReloadCmd("true")
	nginxGen.SetPanelListen("127.0.0.1:8082")
	sysSvc := service.NewSystemService(db, cfg, nginxGen)

	subDom := "sub.cf.example.com" // should match *.cf.example.com wildcard cert!
	subPrefix := "/my-feed"
	if _, err := sysSvc.UpdateSettings(dto.UpdateSettingsRequest{SubDomain: &subDom, SubPath: &subPrefix}); err != nil {
		t.Fatal(err)
	}
	subResp, err := sysSvc.ApplySubscriptionNginx()
	if err != nil || !subResp.Enabled || subResp.MatchedCertDomain != "*.cf.example.com" {
		t.Fatalf("ApplySubscriptionNginx failed: %+v err=%v", subResp, err)
	}
	rawConf, err := os.ReadFile(subResp.ConfigPath)
	if err != nil {
		t.Fatalf("read generated subscription nginx config: %v", err)
	}
	confStr := string(rawConf)
	if !strings.Contains(confStr, "location ^~ /my-feed/") || !strings.Contains(confStr, "return 404;") {
		t.Fatalf("unexpected subscription nginx config:\n%s", confStr)
	}

	// Disabling removes standalone subscription nginx file
	if _, err := sysSvc.DisableSubscriptionNginx(); err != nil {
		t.Fatalf("DisableSubscriptionNginx: %v", err)
	}
	if _, err := os.Stat(subResp.ConfigPath); !os.IsNotExist(err) {
		t.Fatalf("expected %s removed after disabling subscription nginx", subResp.ConfigPath)
	}

	// 4. API domain Nginx reverse proxy (HTTPS/CDN ready, merges cleanly when sharing sub_domain!)
	apiDom := "sub.cf.example.com"
	if _, err := sysSvc.UpdateSettings(dto.UpdateSettingsRequest{APIDomain: &apiDom}); err != nil {
		t.Fatal(err)
	}
	apiResp, err := sysSvc.ApplyAPINginx()
	if err != nil || !apiResp.Enabled || apiResp.DirectURL != "https://sub.cf.example.com" || apiResp.MatchedCertDomain != "*.cf.example.com" {
		t.Fatalf("ApplyAPINginx failed: %+v err=%v", apiResp, err)
	}
	// Enable subscription on the SAME domain: both /api/v1/ and /my-feed/ must coexist in one file
	if _, err := sysSvc.ApplySubscriptionNginx(); err != nil {
		t.Fatalf("ApplySubscriptionNginx on shared domain: %v", err)
	}
	mergedRaw, err := os.ReadFile(apiResp.ConfigPath)
	if err != nil {
		t.Fatalf("read merged endpoint nginx config: %v", err)
	}
	mergedStr := string(mergedRaw)
	if !strings.Contains(mergedStr, "location ^~ /api/v1/") || !strings.Contains(mergedStr, "location ^~ /my-feed/") || !strings.Contains(mergedStr, "proxy_buffering off;") {
		t.Fatalf("expected merged API + subscription Nginx directives:\n%s", mergedStr)
	}

	// Disabling subscription leaves API proxy active on that shared domain
	if _, err := sysSvc.DisableSubscriptionNginx(); err != nil {
		t.Fatalf("DisableSubscriptionNginx while API active: %v", err)
	}
	afterSubOffRaw, err := os.ReadFile(apiResp.ConfigPath)
	if err != nil {
		t.Fatalf("expected API config file preserved when subscription disabled: %v", err)
	}
	if !strings.Contains(string(afterSubOffRaw), "location ^~ /api/v1/") || strings.Contains(string(afterSubOffRaw), "location ^~ /my-feed/") {
		t.Fatalf("unexpected config after disabling sub while API active:\n%s", string(afterSubOffRaw))
	}

	// Disabling API removes the file completely
	if _, err := sysSvc.DisableAPINginx(); err != nil {
		t.Fatalf("DisableAPINginx: %v", err)
	}
	if _, err := os.Stat(apiResp.ConfigPath); !os.IsNotExist(err) {
		t.Fatalf("expected %s removed after disabling API nginx", apiResp.ConfigPath)
	}
}

type fakeTunnelRunner struct {
	installed bool
	calls     [][]string
}

func (r *fakeTunnelRunner) LookPath(name string) (string, error) {
	if name == "cloudflared" && r.installed {
		return "/usr/local/bin/cloudflared", nil
	}
	return "", errors.New("not found")
}

func (r *fakeTunnelRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if len(args) > 0 && args[0] == "--version" {
		return "cloudflared version 2025.1.0", nil
	}
	if len(args) >= 2 && args[0] == "is-active" {
		return "active", nil
	}
	if len(args) >= 2 && args[0] == "is-enabled" {
		return "enabled", nil
	}
	return "ok", nil
}

func (r *fakeTunnelRunner) FileExists(path string) bool {
	if strings.Contains(path, "cloudflared.service") {
		return r.installed
	}
	return false
}

func TestCFTunnelServiceSetupAndNormalization(t *testing.T) {
	db, cfg, _ := setupTestEnv(t)
	if _, err := database.Seed(db, cfg); err != nil {
		t.Fatal(err)
	}

	tunSvc := service.NewCFTunnelService(db, cfg)
	runner := &fakeTunnelRunner{installed: true}
	tunSvc.SetRunner(runner)

	st := tunSvc.GetStatus(context.Background())
	if !st.Installed || !st.Active || st.RecommendedService != "http://127.0.0.1:8082" {
		t.Fatalf("unexpected CFTunnelStatus: %+v", st)
	}

	res, err := tunSvc.SetupTunnel(context.Background(), dto.CFTunnelSetupRequest{
		TunnelToken: "sudo cloudflared service install eyJhIjoiYWJjMTIzIn0=",
	})
	if err != nil || !res.Success {
		t.Fatalf("SetupTunnel failed: %+v err=%v", res, err)
	}

	foundInstall := false
	for _, c := range runner.calls {
		if len(c) == 4 && c[1] == "service" && c[2] == "install" && c[3] == "eyJhIjoiYWJjMTIzIn0=" {
			foundInstall = true
		}
	}
	if !foundInstall {
		t.Fatalf("expected stripped token passed to cloudflared service install, calls=%+v", runner.calls)
	}
}
