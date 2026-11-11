package service

import (
	"testing"

	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
)

func TestGenerateAPITokenSalted(t *testing.T) {
	raw1, prefix1, hash1, salt1, err := models.GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}
	if len(salt1) != 64 {
		t.Fatalf("salt length = %d, want 64 hex chars (32 bytes)", len(salt1))
	}
	want, err := models.HashAPITokenWithSalt(raw1, salt1)
	if err != nil || want != hash1 {
		t.Fatalf("salted hash mismatch: %v", err)
	}
	if hash1 == models.HashAPIToken(raw1) {
		t.Fatalf("stored hash must differ from the legacy unsalted hash")
	}
	if prefix1 != models.TokenDisplayPrefix(raw1) {
		t.Fatalf("prefix mismatch")
	}

	// A second token must get a different salt and hash.
	_, _, hash2, salt2, err := models.GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}
	if salt2 == salt1 || hash2 == hash1 {
		t.Fatalf("tokens must have distinct salts and hashes")
	}
}

func TestAuthenticateSaltedToken(t *testing.T) {
	db, cfg, _ := setupLegoTestEnv(t)
	svc := NewTokenService(db, cfg, "test")

	res, err := svc.Create(dto.CreateTokenRequest{Name: "test-token"})
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	ctx, err := svc.Authenticate(res.PlaintextToken, "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate salted token: %v", err)
	}
	if ctx.TokenName != "test-token" || ctx.IsBootstrap {
		t.Fatalf("unexpected auth context: %+v", ctx)
	}
	if _, err := svc.Authenticate("xrp_bogus-invalid-token", "127.0.0.1"); err == nil {
		t.Fatalf("bogus token must not authenticate")
	}

	var row models.APIToken
	if err := db.First(&row, "id = ?", res.Token.ID).Error; err != nil {
		t.Fatalf("fetch token row: %v", err)
	}
	if row.Salt == "" {
		t.Fatalf("expected a stored salt")
	}
	if row.TokenHash == models.HashAPIToken(res.PlaintextToken) {
		t.Fatalf("stored hash must be salted, not the legacy unsalted hash")
	}
}

func TestAuthenticateLegacyTokenUpgrades(t *testing.T) {
	db, cfg, _ := setupLegoTestEnv(t)
	raw, _, _, _, err := models.GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}
	legacy := models.APIToken{
		Name:        "legacy",
		TokenPrefix: models.TokenDisplayPrefix(raw),
		TokenHash:   models.HashAPIToken(raw),
		Salt:        "",
	}
	if err := db.Create(&legacy).Error; err != nil {
		t.Fatalf("create legacy token row: %v", err)
	}

	svc := NewTokenService(db, cfg, "test")
	if _, err := svc.Authenticate(raw, "127.0.0.1"); err != nil {
		t.Fatalf("legacy token should authenticate once: %v", err)
	}

	var row models.APIToken
	if err := db.First(&row, "id = ?", legacy.ID).Error; err != nil {
		t.Fatalf("fetch token row: %v", err)
	}
	if row.Salt == "" {
		t.Fatalf("expected the legacy row to be upgraded with a salt")
	}
	if row.TokenHash == models.HashAPIToken(raw) {
		t.Fatalf("expected the legacy hash to be replaced by a salted hash")
	}

	// The upgraded token must keep working.
	if _, err := svc.Authenticate(raw, "127.0.0.1"); err != nil {
		t.Fatalf("upgraded token should still authenticate: %v", err)
	}
}

func TestAuthenticateBootstrapUnchanged(t *testing.T) {
	db, cfg, _ := setupLegoTestEnv(t)
	cfg.Auth.BootstrapTokens = []string{"xrp_bootstrap-test-token"}
	svc := NewTokenService(db, cfg, "test")

	ctx, err := svc.Authenticate("xrp_bootstrap-test-token", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate bootstrap token: %v", err)
	}
	if !ctx.IsBootstrap || ctx.TokenName != "bootstrap-1" {
		t.Fatalf("unexpected bootstrap auth context: %+v", ctx)
	}
}
