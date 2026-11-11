package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"

	"xray-panel-server/internal/dto"
	applogger "xray-panel-server/internal/logger"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/nginx"
	"xray-panel-server/internal/utils"
)

// LegoIssueParams carries everything the lego Cloudflare DNS-01 flow needs.
// Credentials are passed as struct fields, never read from environment
// variables by the issuance path itself.
type LegoIssueParams struct {
	// Domain is the base domain without any "*." prefix.
	Domain string
	// WantWildcard additionally requests "*.Domain" on the same certificate.
	WantWildcard bool
	// CFToken is a Cloudflare API token (preferred). If empty, CFKey+CFEmail
	// (Global API Key) are used instead.
	CFToken  string
	CFKey    string
	CFEmail  string
	CFZoneID string
	// Email is the ACME account contact address; may be empty for Let's Encrypt.
	Email string
}

// LegoIssuer issues certificates through go-acme/lego.
type LegoIssuer interface {
	// Issue obtains (or reuses) a certificate and writes it to the acme.sh
	// layout under certDir. It returns the certificate and key paths, whether
	// an existing still-valid certificate was reused, a human-readable
	// summary, and an error.
	Issue(ctx context.Context, params LegoIssueParams) (certPath, keyPath string, reused bool, output string, err error)
}

// legoObtainFunc performs the actual ACME exchange and returns the issued
// certificate resource. It is a field (rather than a direct call) so tests
// can substitute a fake issuer without touching the network.
type legoObtainFunc func(ctx context.Context, params LegoIssueParams, user *legoUser) (*certificate.Resource, error)

// legoIssuer is the production LegoIssuer implementation.
type legoIssuer struct {
	certDir string
	obtain  legoObtainFunc
}

func newLegoIssuer(certDir string) *legoIssuer {
	l := &legoIssuer{certDir: certDir}
	l.obtain = l.defaultObtain
	return l
}

// legoDir is the subdirectory of certDir holding lego's ACME account key
// and registration. Certificate files themselves are NOT stored here; they
// go to the acme.sh layout (see writeLegoCertFiles).
const legoDirName = "lego"

// legoReuseDays mirrors the renewal threshold: a certificate still valid for
// longer than this is reused instead of re-issued.
const legoReuseDays = 30

func (l *legoIssuer) Issue(ctx context.Context, params LegoIssueParams) (string, string, bool, string, error) {
	baseDomain := strings.TrimSpace(strings.TrimPrefix(params.Domain, "*."))
	if baseDomain == "" {
		return "", "", false, "", errors.New("域名不能为空")
	}
	if params.CFToken == "" && (params.CFKey == "" || params.CFEmail == "") {
		return "", "", false, "", errors.New("Cloudflare 需提供 CF_Token，或同时提供 CF_Key 与 CF_Email")
	}

	// Reuse: never re-issue while the on-disk certificate is still valid for
	// more than legoReuseDays. This keeps manual re-issue and the renewal
	// worker from burning Let's Encrypt rate limits.
	if certPath, keyPath, ok := resolveIssuedCertPaths(l.certDir, baseDomain); ok {
		if _, expiry, _, _, err := utils.ParseCertificateDetails(certPath); err == nil {
			if time.Until(expiry) > legoReuseDays*24*time.Hour {
				return certPath, keyPath, true, "证书仍在有效期内（>" + fmt.Sprint(legoReuseDays) + " 天），复用已有证书", nil
			}
		}
	}

	user, err := loadOrCreateLegoUser(l.certDir, params.Email)
	if err != nil {
		return "", "", false, "", fmt.Errorf("加载 ACME 账户失败: %w", err)
	}

	res, err := l.obtain(ctx, params, user)
	if err != nil {
		return "", "", false, "", err
	}

	certPath, keyPath, err := writeLegoCertFiles(l.certDir, baseDomain, res)
	if err != nil {
		return "", "", false, "", err
	}

	domains := []string{baseDomain}
	if params.WantWildcard {
		domains = append(domains, "*."+baseDomain)
	}
	return certPath, keyPath, false,
		"lego 已签发证书（Cloudflare DNS-01，Let's Encrypt）: " + strings.Join(domains, ", "), nil
}

// defaultObtain runs the real lego exchange: build the client, register the
// ACME account on first use, set the Cloudflare DNS-01 provider, and obtain
// the certificate.
func (l *legoIssuer) defaultObtain(_ context.Context, params LegoIssueParams, user *legoUser) (*certificate.Resource, error) {
	cfg := lego.NewConfig(user)
	cfg.CADirURL = lego.LEDirectoryProduction
	// EC P-256 keys, matching the acme.sh "_ecc" directory layout.
	cfg.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("创建 ACME 客户端失败: %w", err)
	}

	if user.GetRegistration() == nil {
		res, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("注册 ACME 账户失败: %w", err)
		}
		user.registration = res
		if err := saveLegoRegistration(l.certDir, res); err != nil {
			return nil, fmt.Errorf("保存 ACME 注册信息失败: %w", err)
		}
	}

	provider, err := cloudflare.NewDNSProviderConfig(&cloudflare.Config{
		AuthToken:          params.CFToken,
		AuthKey:            params.CFKey,
		AuthEmail:          params.CFEmail,
		ZoneToken:          params.CFZoneID,
		TTL:                120,
		PropagationTimeout: 2 * time.Minute,
		PollingInterval:    dns01.DefaultPollingInterval,
		HTTPClient:         &http.Client{Timeout: 30 * time.Second},
	})
	if err != nil {
		return nil, fmt.Errorf("创建 Cloudflare DNS provider 失败: %w", err)
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("设置 DNS-01 provider 失败: %w", err)
	}

	domains := []string{strings.TrimSpace(strings.TrimPrefix(params.Domain, "*."))}
	if params.WantWildcard {
		domains = append(domains, "*."+domains[0])
	}

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("ACME 签发失败: %w", err)
	}
	return res, nil
}

// legoUser implements registration.User for the lego client.
type legoUser struct {
	email        string
	privateKey   crypto.PrivateKey
	registration *registration.Resource
}

func (u *legoUser) GetEmail() string                        { return u.email }
func (u *legoUser) GetRegistration() *registration.Resource { return u.registration }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey        { return u.privateKey }

// loadOrCreateLegoUser loads the persisted ACME account key (and registration
// URI, if any) from certDir/lego, or creates a fresh P-256 key on first use.
func loadOrCreateLegoUser(certDir, email string) (*legoUser, error) {
	dir := filepath.Join(certDir, legoDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("创建 lego 目录失败: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("设置 lego 目录权限失败: %w", err)
	}

	keyPath := filepath.Join(dir, "account.key")
	key, err := loadLegoAccountKey(keyPath)
	if err != nil {
		return nil, err
	}
	if key == nil {
		ecKey, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if genErr != nil {
			return nil, fmt.Errorf("生成 ACME 账户密钥失败: %w", genErr)
		}
		der, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return nil, fmt.Errorf("序列化 ACME 账户密钥失败: %w", err)
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
			return nil, fmt.Errorf("保存 ACME 账户密钥失败: %w", err)
		}
		key = ecKey
	}

	user := &legoUser{email: strings.TrimSpace(email), privateKey: key}
	if reg, err := loadLegoRegistration(dir); err != nil {
		return nil, err
	} else if reg != nil {
		user.registration = reg
	}
	return user, nil
}

func loadLegoAccountKey(keyPath string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取 ACME 账户密钥失败: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("ACME 账户密钥不是有效的 PEM")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 ACME 账户密钥失败: %w", err)
	}
	return key, nil
}

type legoRegistrationFile struct {
	URI string `json:"uri"`
}

func loadLegoRegistration(dir string) (*registration.Resource, error) {
	data, err := os.ReadFile(filepath.Join(dir, "account.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取 ACME 注册信息失败: %w", err)
	}
	var f legoRegistrationFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("解析 ACME 注册信息失败: %w", err)
	}
	if strings.TrimSpace(f.URI) == "" {
		return nil, nil
	}
	return &registration.Resource{URI: f.URI}, nil
}

func saveLegoRegistration(certDir string, res *registration.Resource) error {
	data, err := json.Marshal(legoRegistrationFile{URI: res.URI})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(certDir, legoDirName, "account.json"), append(data, '\n'), 0600)
}

// writeLegoCertFiles writes an issued certificate to the exact acme.sh
// layout (resolveIssuedCertPaths finds <baseDomain>_ecc/fullchain.cer +
// <baseDomain>.key first), so nginx templates and ScanCertificates work
// unchanged.
func writeLegoCertFiles(certDir, baseDomain string, res *certificate.Resource) (string, string, error) {
	if len(res.Certificate) == 0 {
		return "", "", errors.New("ACME 返回的证书为空")
	}
	if len(res.PrivateKey) == 0 {
		return "", "", errors.New("ACME 返回的私钥为空")
	}
	if _, _, _, _, err := utils.ParseCertificateDetailsFromBytes(res.Certificate, baseDomain); err != nil {
		return "", "", fmt.Errorf("ACME 返回的证书无法解析: %w", err)
	}

	dir := filepath.Join(certDir, baseDomain+"_ecc")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", "", fmt.Errorf("创建证书目录失败: %w", err)
	}
	certPath := filepath.Join(dir, "fullchain.cer")
	keyPath := filepath.Join(dir, baseDomain+".key")
	if err := os.WriteFile(certPath, res.Certificate, 0644); err != nil {
		return "", "", fmt.Errorf("写入证书文件失败: %w", err)
	}
	if err := os.WriteFile(keyPath, res.PrivateKey, 0600); err != nil {
		return "", "", fmt.Errorf("写入私钥文件失败: %w", err)
	}
	return certPath, keyPath, nil
}

// reloadNginx reloads nginx using the configured reload command.
func (s *DomainService) reloadNginx() error {
	if s.cfg == nil {
		return nil
	}
	ng := nginx.NewGenerator(s.cfg.Nginx.ConfigDir, s.cfg.Nginx.StreamDir)
	if s.cfg.Nginx.ReloadCmd != "" {
		ng.SetReloadCmd(s.cfg.Nginx.ReloadCmd)
	}
	return ng.Reload()
}

// --- Certificate issuance source tracking (for the renewal worker) ---
//
// The Domain row does not record which provider/CA issued its certificate,
// so issuance records provider+CA in the generic settings KV store. Only the
// provider and CA names are stored here; DNS API credentials are never
// persisted. The renewal worker reads these keys back to re-issue along the
// original path.
func certSourceKey(kind, domain string) string {
	return "cert_" + kind + "_" + domain
}

func (s *DomainService) recordCertSource(domain, provider, ca string) {
	set := func(key, value string) {
		var st models.Setting
		if err := s.db.Where("key = ?", key).First(&st).Error; err == nil {
			st.Value = value
			_ = s.db.Save(&st).Error
		} else {
			_ = s.db.Create(&models.Setting{Key: key, Value: value, Type: "string"}).Error
		}
	}
	set(certSourceKey("provider", domain), provider)
	set(certSourceKey("ca", domain), ca)
}

func (s *DomainService) readCertSource(domain string) (provider, ca string) {
	provider = models.GetSettingValue(s.db, certSourceKey("provider", domain), "")
	ca = models.GetSettingValue(s.db, certSourceKey("ca", domain), "")
	return provider, ca
}

// --- Certificate renewal worker ---

// CertRenewalThresholdDays is the number of days before expiry at which a
// certificate is considered due for renewal.
const CertRenewalThresholdDays = 30

// CertRenewalInterval is the default period between renewal checks.
const CertRenewalInterval = 24 * time.Hour

// CertNeedsRenewal reports whether a certificate expiring at expiry needs to
// be renewed now. It is a pure function so it can be unit tested without a
// database or network.
func CertNeedsRenewal(expiry time.Time, now time.Time, thresholdDays int) bool {
	if expiry.IsZero() || thresholdDays <= 0 {
		return false
	}
	return expiry.Sub(now) < time.Duration(thresholdDays)*24*time.Hour
}

// StartCertRenewalWorker runs the daily certificate renewal check in the
// background, mirroring the traffic-sync worker pattern (initial delay, then
// a ticker; ctx cancellation stops it). Failures are only logged; the worker
// never blocks startup and never aborts other work.
func (s *DomainService) StartCertRenewalWorker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = CertRenewalInterval
	}
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}

		s.RenewExpiringCertificates(ctx)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.RenewExpiringCertificates(ctx)
			}
		}
	}()
}

// RenewExpiringCertificates checks every domain once and renews certificates
// expiring within CertRenewalThresholdDays, re-issuing along the recorded
// original provider/CA path (lego and acme.sh branches are both reused via
// IssueCertificate). DNS API credentials are not stored anywhere, so the
// worker reads them from environment variables; a domain whose credentials
// are unavailable is skipped with a warning instead of failing.
func (s *DomainService) RenewExpiringCertificates(ctx context.Context) (renewed, skipped, failed int) {
	var domains []models.Domain
	if err := s.db.Find(&domains).Error; err != nil {
		applogger.Error("证书续期: 查询域名失败: %v", err)
		return 0, 0, 0
	}

	now := time.Now()
	for _, d := range domains {
		if strings.TrimSpace(d.CertPath) == "" {
			skipped++
			continue
		}
		_, expiry, _, _, err := utils.ParseCertificateDetails(d.CertPath)
		if err != nil {
			applogger.Warn("证书续期: 解析 %s 的证书失败: %v，跳过", d.Domain, err)
			skipped++
			continue
		}
		if !CertNeedsRenewal(expiry, now, CertRenewalThresholdDays) {
			skipped++
			continue
		}

		provider, ca := s.readCertSource(d.Domain)
		if provider == "" || ca == "" {
			applogger.Warn("证书续期: %s 未记录签发来源（provider/CA），跳过自动续期，请在桌面端手动签发", d.Domain)
			skipped++
			continue
		}
		req, ok := renewalRequest(d, provider, ca)
		if !ok {
			applogger.Warn("证书续期: %s 缺少 %s 续期凭证（环境变量），跳过自动续期", d.Domain, provider)
			skipped++
			continue
		}
		if _, err := s.IssueCertificate(ctx, req); err != nil {
			applogger.Error("证书续期: %s 续期失败: %v", d.Domain, err)
			failed++
			continue
		}
		applogger.Info("证书续期: %s 已续期", d.Domain)
		renewed++
	}
	return renewed, skipped, failed
}

// renewalRequest rebuilds an IssueCertRequest for d from the recorded
// provider/CA plus DNS credentials from the environment. It reports false
// when the required credentials are absent, so the caller can skip the
// domain instead of failing the whole run.
//
// Credential sources (environment only; nothing is persisted):
//   - Cloudflare: CF_TOKEN or CLOUDFLARE_DNS_API_TOKEN (optional
//     CF_ZONE_ID / CLOUDFLARE_ZONE_ID), account email from ACME_EMAIL.
//   - LuaDNS: LUA_KEY + LUA_EMAIL.
func renewalRequest(d models.Domain, provider, ca string) (dto.IssueCertRequest, bool) {
	req := dto.IssueCertRequest{
		Domain:          d.Domain,
		IncludeWildcard: d.IsWildcard,
		Type:            string(d.Type),
		Provider:        provider,
		CAServer:        ca,
	}
	switch provider {
	case "cf", "cloudflare":
		token := firstEnv("CF_TOKEN", "CLOUDFLARE_DNS_API_TOKEN")
		if token == "" {
			return req, false
		}
		req.CFToken = token
		req.CFZoneID = firstEnv("CF_ZONE_ID", "CLOUDFLARE_ZONE_ID")
		req.Email = os.Getenv("ACME_EMAIL")
	case "luadns", "lua":
		key := os.Getenv("LUA_KEY")
		email := os.Getenv("LUA_EMAIL")
		if key == "" || email == "" {
			return req, false
		}
		req.LuaKey = key
		req.LuaEmail = email
		req.Email = email
	default:
		return req, false
	}
	return req, true
}

// firstEnv returns the first non-empty environment variable among names.
func firstEnv(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}
