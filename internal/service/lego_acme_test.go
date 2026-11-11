package service

import (
	"context"
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

	"github.com/go-acme/lego/v4/certificate"
	"gorm.io/gorm"

	"xray-panel-server/internal/config"
	"xray-panel-server/internal/database"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/utils"
)

func setupLegoTestEnv(t *testing.T) (*gorm.DB, *config.Config, string) {
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
	cfg.Nginx.CertDir = filepath.Join(tmpDir, "acme")
	cfg.Nginx.ReloadCmd = "true"
	cfg.Nginx.TestCmd = "true"

	return db, cfg, tmpDir
}

// makeTestSelfSignedCert returns PEM-encoded self-signed certificate + key.
func makeTestSelfSignedCert(t *testing.T, notAfter time.Time, dnsNames []string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func writeTestSelfSignedCert(t *testing.T, certPath, keyPath string, notAfter time.Time, dnsNames []string) {
	t.Helper()
	certPEM, keyPEM := makeTestSelfSignedCert(t, notAfter, dnsNames)
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCertNeedsRenewal(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		expiry    time.Time
		threshold int
		want      bool
	}{
		{"expires in 10 days", now.Add(10 * 24 * time.Hour), 30, true},
		{"expires in 29 days", now.Add(29 * 24 * time.Hour), 30, true},
		{"expires in exactly 30 days", now.Add(30 * 24 * time.Hour), 30, false},
		{"expires in 60 days", now.Add(60 * 24 * time.Hour), 30, false},
		{"already expired", now.Add(-time.Hour), 30, true},
		{"zero expiry means unknown, do not renew", time.Time{}, 30, false},
		{"zero threshold disables renewal", now.Add(24 * time.Hour), 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CertNeedsRenewal(tc.expiry, now, tc.threshold); got != tc.want {
				t.Fatalf("CertNeedsRenewal(%v, threshold=%d) = %v, want %v", tc.expiry, tc.threshold, got, tc.want)
			}
		})
	}
}

func TestWriteLegoCertFilesAcmeLayout(t *testing.T) {
	_, cfg, _ := setupLegoTestEnv(t)
	certPEM, keyPEM := makeTestSelfSignedCert(t, time.Now().Add(90*24*time.Hour), []string{"example.com"})
	res := &certificate.Resource{Domain: "example.com", Certificate: certPEM, PrivateKey: keyPEM}

	certPath, keyPath, err := writeLegoCertFiles(cfg.Nginx.CertDir, "example.com", res)
	if err != nil {
		t.Fatalf("writeLegoCertFiles: %v", err)
	}
	if want := filepath.Join(cfg.Nginx.CertDir, "example.com_ecc", "fullchain.cer"); certPath != want {
		t.Fatalf("certPath = %s, want %s", certPath, want)
	}
	if want := filepath.Join(cfg.Nginx.CertDir, "example.com_ecc", "example.com.key"); keyPath != want {
		t.Fatalf("keyPath = %s, want %s", keyPath, want)
	}
	// resolveIssuedCertPaths (the acme.sh lookup) must find the lego files.
	foundCert, foundKey, ok := resolveIssuedCertPaths(cfg.Nginx.CertDir, "example.com")
	if !ok || foundCert != certPath || foundKey != keyPath {
		t.Fatalf("resolveIssuedCertPaths = (%s, %s, %v), want (%s, %s, true)", foundCert, foundKey, ok, certPath, keyPath)
	}
	// WriteFile applies the process umask, so assert "no more permissive
	// than" instead of exact bits (e.g. umask 027 turns 0644 into 0640).
	if st, err := os.Stat(certPath); err != nil || st.Mode().Perm()&^0644 != 0 {
		t.Fatalf("cert file perms = %v (err %v), want at most 0644", st.Mode().Perm(), err)
	}
	if st, err := os.Stat(keyPath); err != nil || st.Mode().Perm()&^0600 != 0 {
		t.Fatalf("key file perms = %v (err %v), want at most 0600", st.Mode().Perm(), err)
	}
}

func TestLoadOrCreateLegoUserRoundTrip(t *testing.T) {
	_, cfg, _ := setupLegoTestEnv(t)
	u1, err := loadOrCreateLegoUser(cfg.Nginx.CertDir, "admin@example.com")
	if err != nil {
		t.Fatalf("loadOrCreateLegoUser: %v", err)
	}
	u2, err := loadOrCreateLegoUser(cfg.Nginx.CertDir, "admin@example.com")
	if err != nil {
		t.Fatalf("loadOrCreateLegoUser second call: %v", err)
	}
	k1, ok := u1.GetPrivateKey().(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("account key is not ECDSA")
	}
	k2, ok := u2.GetPrivateKey().(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("account key is not ECDSA on reload")
	}
	if k1.D.Cmp(k2.D) != 0 {
		t.Fatalf("account key changed across loads")
	}
	if st, err := os.Stat(filepath.Join(cfg.Nginx.CertDir, "lego", "account.key")); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("account.key perms = %v (err %v), want 0600", st.Mode().Perm(), err)
	}
	if st, err := os.Stat(filepath.Join(cfg.Nginx.CertDir, "lego")); err != nil || st.Mode().Perm() != 0700 {
		t.Fatalf("lego dir perms = %v (err %v), want 0700", st.Mode().Perm(), err)
	}
}

func TestLegoIssuerReuse(t *testing.T) {
	_, cfg, _ := setupLegoTestEnv(t)
	certPEM, keyPEM := makeTestSelfSignedCert(t, time.Now().Add(60*24*time.Hour), []string{"example.com"})

	issuer := newLegoIssuer(cfg.Nginx.CertDir)
	calls := 0
	issuer.obtain = func(_ context.Context, _ LegoIssueParams, _ *legoUser) (*certificate.Resource, error) {
		calls++
		return &certificate.Resource{Domain: "example.com", Certificate: certPEM, PrivateKey: keyPEM}, nil
	}

	// No existing certificate: obtain runs once.
	if _, _, reused, _, err := issuer.Issue(context.Background(), LegoIssueParams{Domain: "example.com", CFToken: "tok"}); err != nil || reused || calls != 1 {
		t.Fatalf("first Issue: reused=%v calls=%d err=%v", reused, calls, err)
	}
	// Existing certificate still valid 60 days: reused, obtain not called again.
	if _, _, reused, _, err := issuer.Issue(context.Background(), LegoIssueParams{Domain: "example.com", CFToken: "tok"}); err != nil || !reused || calls != 1 {
		t.Fatalf("second Issue: reused=%v calls=%d err=%v (want reuse, 1 call)", reused, calls, err)
	}
}

// fakeLegoIssuer implements LegoIssuer without network access.
type fakeLegoIssuer struct {
	certDir         string
	certPEM, keyPEM []byte
	calls           int
}

func (f *fakeLegoIssuer) Issue(_ context.Context, params LegoIssueParams) (string, string, bool, string, error) {
	baseDomain := strings.TrimSpace(strings.TrimPrefix(params.Domain, "*."))
	if certPath, keyPath, ok := resolveIssuedCertPaths(f.certDir, baseDomain); ok {
		if _, expiry, _, _, err := utils.ParseCertificateDetails(certPath); err == nil && time.Until(expiry) > legoReuseDays*24*time.Hour {
			return certPath, keyPath, true, "reused", nil
		}
	}
	f.calls++
	res := &certificate.Resource{Domain: baseDomain, Certificate: f.certPEM, PrivateKey: f.keyPEM}
	certPath, keyPath, err := writeLegoCertFiles(f.certDir, baseDomain, res)
	return certPath, keyPath, false, "fake issued", err
}

func TestIssueCertificateLegoBranch(t *testing.T) {
	db, cfg, _ := setupLegoTestEnv(t)
	svc := NewDomainService(db, cfg)
	certPEM, keyPEM := makeTestSelfSignedCert(t, time.Now().Add(90*24*time.Hour), []string{"example.com"})
	fake := &fakeLegoIssuer{certDir: cfg.Nginx.CertDir, certPEM: certPEM, keyPEM: keyPEM}
	svc.SetLegoIssuer(fake)

	req := dto.IssueCertRequest{
		Domain:   "example.com",
		Provider: "cf",
		CAServer: "letsencrypt",
		CFToken:  "test-token-123",
	}
	res, err := svc.IssueCertificate(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueCertificate (lego): %v", err)
	}
	if res.ReusedExisting {
		t.Fatalf("first issuance must not be a reuse")
	}
	if res.Provider != "cf" || res.CAServer != "letsencrypt" {
		t.Fatalf("unexpected provider/CA in response: %s/%s", res.Provider, res.CAServer)
	}
	if fake.calls != 1 {
		t.Fatalf("obtain calls = %d, want 1", fake.calls)
	}
	if _, err := os.Stat(filepath.Join(cfg.Nginx.CertDir, "example.com_ecc", "fullchain.cer")); err != nil {
		t.Fatalf("expected cert in acme.sh layout: %v", err)
	}
	if p, ca := svc.readCertSource("example.com"); p != "cf" || ca != "letsencrypt" {
		t.Fatalf("recorded source = %s/%s, want cf/letsencrypt", p, ca)
	}

	// Second call reuses the still-valid certificate and does not re-issue.
	res2, err := svc.IssueCertificate(context.Background(), req)
	if err != nil {
		t.Fatalf("second IssueCertificate: %v", err)
	}
	if !res2.ReusedExisting {
		t.Fatalf("second issuance should reuse the existing certificate")
	}
	if fake.calls != 1 {
		t.Fatalf("obtain calls = %d after reuse, want 1", fake.calls)
	}
}

func TestImportSingleCertificatePathRestriction(t *testing.T) {
	db, cfg, tmpDir := setupLegoTestEnv(t)
	svc := NewDomainService(db, cfg)

	// Certificate outside certDir: must be rejected before any file is read.
	outside := filepath.Join(tmpDir, "elsewhere")
	outCert := filepath.Join(outside, "fullchain.cer")
	outKey := filepath.Join(outside, "example.com.key")
	writeTestSelfSignedCert(t, outCert, outKey, time.Now().Add(365*24*time.Hour), []string{"example.com"})
	if _, err := svc.ImportSingleCertificate(dto.ImportCertRequest{Domain: "example.com", CertPath: outCert, KeyPath: outKey}); err == nil {
		t.Fatalf("expected import outside certDir to be rejected")
	} else if !strings.Contains(err.Error(), "证书目录") {
		t.Fatalf("unexpected error for outside-certDir import: %v", err)
	}

	// Path traversal out of certDir: must be rejected.
	traversal := filepath.Join(cfg.Nginx.CertDir, "..", "elsewhere", "fullchain.cer")
	if _, err := svc.ImportSingleCertificate(dto.ImportCertRequest{Domain: "example.com", CertPath: traversal, KeyPath: outKey}); err == nil {
		t.Fatalf("expected traversal import to be rejected")
	}

	// Certificate inside certDir: accepted.
	inCert := filepath.Join(cfg.Nginx.CertDir, "example.com_ecc", "fullchain.cer")
	inKey := filepath.Join(cfg.Nginx.CertDir, "example.com_ecc", "example.com.key")
	writeTestSelfSignedCert(t, inCert, inKey, time.Now().Add(365*24*time.Hour), []string{"example.com"})
	res, err := svc.ImportSingleCertificate(dto.ImportCertRequest{Domain: "example.com", CertPath: inCert, KeyPath: inKey})
	if err != nil {
		t.Fatalf("import inside certDir should succeed: %v", err)
	}
	if res.Domain != "example.com" {
		t.Fatalf("imported domain = %s, want example.com", res.Domain)
	}
}

func TestUploadCertificateStaysInCertDir(t *testing.T) {
	db, cfg, _ := setupLegoTestEnv(t)
	svc := NewDomainService(db, cfg)
	certPEM, keyPEM := makeTestSelfSignedCert(t, time.Now().Add(365*24*time.Hour), []string{"upload.example.com"})

	res, err := svc.UploadCertificate(dto.UploadCertRequest{
		Domain:  "upload.example.com",
		Type:    "direct",
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
	})
	if err != nil {
		t.Fatalf("UploadCertificate: %v", err)
	}
	if !strings.HasPrefix(res.CertPath, filepath.Clean(cfg.Nginx.CertDir)+string(os.PathSeparator)) {
		t.Fatalf("uploaded cert path %s is outside certDir", res.CertPath)
	}
	if _, err := os.Stat(res.CertPath); err != nil {
		t.Fatalf("uploaded cert file missing: %v", err)
	}
}

func TestRenewExpiringCertificatesSkips(t *testing.T) {
	db, cfg, _ := setupLegoTestEnv(t)
	svc := NewDomainService(db, cfg)
	t.Setenv("CF_TOKEN", "")
	t.Setenv("CLOUDFLARE_DNS_API_TOKEN", "")
	t.Setenv("LUA_KEY", "")
	t.Setenv("LUA_EMAIL", "")

	addDomain := func(name string, notAfter time.Time) {
		certPath := filepath.Join(cfg.Nginx.CertDir, name+"_ecc", "fullchain.cer")
		keyPath := filepath.Join(cfg.Nginx.CertDir, name+"_ecc", name+".key")
		writeTestSelfSignedCert(t, certPath, keyPath, notAfter, []string{name})
		if err := db.Create(&models.Domain{
			Domain:   name,
			Type:     models.DomainTypeDirect,
			CertPath: certPath,
			KeyPath:  keyPath,
			Enabled:  true,
		}).Error; err != nil {
			t.Fatal(err)
		}
	}

	// Expiring in 5 days, but no recorded issuance source: skip.
	addDomain("soon.example.com", time.Now().Add(5*24*time.Hour))
	// Valid for 90 days with a recorded source: not due, skip.
	addDomain("later.example.com", time.Now().Add(90*24*time.Hour))
	svc.recordCertSource("later.example.com", "cf", "letsencrypt")
	// Expiring in 5 days with a recorded source, but no credentials in env: skip.
	addDomain("nocreds.example.com", time.Now().Add(5*24*time.Hour))
	svc.recordCertSource("nocreds.example.com", "cf", "letsencrypt")

	renewed, skipped, failed := svc.RenewExpiringCertificates(context.Background())
	if renewed != 0 || failed != 0 {
		t.Fatalf("RenewExpiringCertificates = renewed=%d failed=%d, want 0/0", renewed, failed)
	}
	if skipped != 3 {
		t.Fatalf("RenewExpiringCertificates skipped=%d, want 3", skipped)
	}
}

func TestRenewalRequestEnvCredentials(t *testing.T) {
	d := models.Domain{Domain: "example.com", Type: models.DomainTypeDirect, IsWildcard: true}

	t.Setenv("CF_TOKEN", "tok-123")
	t.Setenv("CF_ZONE_ID", "zone-1")
	req, ok := renewalRequest(d, "cf", "letsencrypt")
	if !ok || req.CFToken != "tok-123" || req.CFZoneID != "zone-1" || req.Domain != "example.com" || !req.IncludeWildcard {
		t.Fatalf("renewalRequest cf = %+v ok=%v", req, ok)
	}

	t.Setenv("CF_TOKEN", "")
	t.Setenv("CLOUDFLARE_DNS_API_TOKEN", "")
	if _, ok := renewalRequest(d, "cf", "letsencrypt"); ok {
		t.Fatalf("renewalRequest should fail without CF credentials")
	}

	t.Setenv("LUA_KEY", "lua-key")
	t.Setenv("LUA_EMAIL", "admin@example.com")
	req, ok = renewalRequest(d, "luadns", "letsencrypt")
	if !ok || req.LuaKey != "lua-key" || req.LuaEmail != "admin@example.com" {
		t.Fatalf("renewalRequest luadns = %+v ok=%v", req, ok)
	}

	if _, ok := renewalRequest(d, "unknown-provider", "letsencrypt"); ok {
		t.Fatalf("renewalRequest should fail for unknown provider")
	}
}

func TestRecordReadCertSource(t *testing.T) {
	db, cfg, _ := setupLegoTestEnv(t)
	svc := NewDomainService(db, cfg)
	if p, ca := svc.readCertSource("example.com"); p != "" || ca != "" {
		t.Fatalf("expected empty source, got %s/%s", p, ca)
	}
	svc.recordCertSource("example.com", "cf", "letsencrypt")
	if p, ca := svc.readCertSource("example.com"); p != "cf" || ca != "letsencrypt" {
		t.Fatalf("recorded source = %s/%s, want cf/letsencrypt", p, ca)
	}
	svc.recordCertSource("example.com", "luadns", "zerossl")
	if p, ca := svc.readCertSource("example.com"); p != "luadns" || ca != "zerossl" {
		t.Fatalf("updated source = %s/%s, want luadns/zerossl", p, ca)
	}
}
