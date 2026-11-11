package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"xray-panel-server/internal/config"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/utils"
)

var domainRegex = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// AcmeRunner executes acme.sh commands with isolated environment credentials.
type AcmeRunner interface {
	Run(ctx context.Context, args []string, extraEnv []string) (output string, exitCode int, err error)
}

// DomainService manages domains and TLS/ACME certificate discovery, upload, and issuance.
type DomainService struct {
	db         *gorm.DB
	cfg        *config.Config
	acmeRunner AcmeRunner
}

func NewDomainService(db *gorm.DB, cfg *config.Config) *DomainService {
	s := &DomainService{db: db, cfg: cfg}
	s.acmeRunner = newExecAcmeRunner(cfg, s.certDir)
	return s
}

// newExecAcmeRunner builds the production acme.sh runner from config. An
// empty archive URL/SHA-256 means "use the pinned release"; a nil
// AutoInstall means enabled.
func newExecAcmeRunner(cfg *config.Config, certDirFn func() string) *execAcmeRunner {
	r := &execAcmeRunner{certDirFn: certDirFn}
	if cfg == nil {
		return r
	}
	if cfg.Acme.AutoInstall != nil && !*cfg.Acme.AutoInstall {
		r.autoInstallDisabled = true
	}
	if u := strings.TrimSpace(cfg.Acme.ArchiveURL); u != "" {
		r.archiveURL = u
	}
	if h := strings.TrimSpace(cfg.Acme.ArchiveSHA256); h != "" {
		r.archiveSHA256 = strings.ToLower(h)
	}
	return r
}

// SetAcmeRunner injects a custom ACME runner (for testing).
func (s *DomainService) SetAcmeRunner(runner AcmeRunner) {
	if runner != nil {
		s.acmeRunner = runner
	}
}

func (s *DomainService) List() (*dto.DomainListResponse, error) {
	var domains []models.Domain
	if err := s.db.Order("created_at DESC").Find(&domains).Error; err != nil {
		return nil, NewInternalError("Failed to fetch domains", err)
	}
	dtos := make([]dto.DomainDTO, len(domains))
	for i, d := range domains {
		dtos[i] = toDomainDTO(d)
	}
	return &dto.DomainListResponse{Domains: dtos, Total: len(dtos)}, nil
}

func (s *DomainService) Get(id string) (*dto.DomainDTO, error) {
	var domain models.Domain
	if err := s.db.First(&domain, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Domain not found")
	}
	dto := toDomainDTO(domain)
	return &dto, nil
}

func (s *DomainService) Create(req dto.UpsertDomainRequest) (*dto.DomainDTO, error) {
	domainName := strings.TrimSpace(req.Domain)
	if !validateDomainFormat(domainName) {
		return nil, NewValidationError("域名格式无效")
	}

	dtype := models.DomainTypeDirect
	if req.Type != "" {
		dtype = models.DomainType(req.Type)
	}
	if !isValidDomainType(dtype) {
		return nil, NewValidationError("无效的域名类型，允许值: direct, cdn")
	}

	certPath := strings.TrimSpace(req.CertPath)
	keyPath := strings.TrimSpace(req.KeyPath)
	if dtype == models.DomainTypeDirect || dtype == models.DomainTypeCDN {
		if err := validateCertificatePaths(certPath, keyPath); err != nil {
			return nil, err
		}
		if err := s.validateCertPathWithinCertDir(certPath); err != nil {
			return nil, err
		}
		if err := s.validateCertPathWithinCertDir(keyPath); err != nil {
			return nil, err
		}
	}

	isWildcard := req.IsWildcard || strings.HasPrefix(domainName, "*.")
	if !isWildcard && certPath != "" {
		if _, _, _, isWC, err := utils.ParseCertificateDetails(certPath); err == nil {
			isWildcard = isWC
		}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	domain := models.Domain{
		Domain:     domainName,
		Type:       dtype,
		IsWildcard: isWildcard,
		CertPath:   certPath,
		KeyPath:    keyPath,
		Enabled:    enabled,
	}

	if err := s.db.Create(&domain).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, NewConflictError("域名已存在")
		}
		return nil, NewInternalError("创建域名失败", err)
	}

	dto := toDomainDTO(domain)
	return &dto, nil
}

func (s *DomainService) Update(id string, req dto.UpsertDomainRequest) (*dto.DomainDTO, error) {
	var domain models.Domain
	if err := s.db.First(&domain, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Domain not found")
	}

	domainName := strings.TrimSpace(req.Domain)
	if !validateDomainFormat(domainName) {
		return nil, NewValidationError("域名格式无效")
	}

	dtype := domain.Type
	if req.Type != "" {
		dtype = models.DomainType(req.Type)
	}
	if !isValidDomainType(dtype) {
		return nil, NewValidationError("无效的域名类型，允许值: direct, cdn")
	}

	certPath := strings.TrimSpace(req.CertPath)
	keyPath := strings.TrimSpace(req.KeyPath)
	if dtype == models.DomainTypeDirect || dtype == models.DomainTypeCDN {
		if err := validateCertificatePaths(certPath, keyPath); err != nil {
			return nil, err
		}
		if err := s.validateCertPathWithinCertDir(certPath); err != nil {
			return nil, err
		}
		if err := s.validateCertPathWithinCertDir(keyPath); err != nil {
			return nil, err
		}
	}

	isWildcard := req.IsWildcard || strings.HasPrefix(domainName, "*.")
	if !isWildcard && certPath != "" {
		if _, _, _, isWC, err := utils.ParseCertificateDetails(certPath); err == nil {
			isWildcard = isWC
		}
	}

	domain.Domain = domainName
	domain.Type = dtype
	domain.IsWildcard = isWildcard
	domain.CertPath = certPath
	domain.KeyPath = keyPath
	if req.Enabled != nil {
		domain.Enabled = *req.Enabled
	}

	if err := s.db.Save(&domain).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, NewConflictError("域名已存在")
		}
		return nil, NewInternalError("更新域名失败", err)
	}

	dto := toDomainDTO(domain)
	return &dto, nil
}

func (s *DomainService) Delete(id string) (*dto.DeleteResponse, error) {
	result := s.db.Delete(&models.Domain{}, "id = ?", id)
	if result.Error != nil {
		return nil, NewInternalError("Failed to delete domain", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, NewNotFoundError("Domain not found")
	}
	return &dto.DeleteResponse{ID: id, Deleted: true}, nil
}

func (s *DomainService) ScanCertificates() (*dto.ScanCertificatesResponse, error) {
	certDir := s.certDir()
	certs, err := discoverCertificates(certDir)
	if err != nil {
		return nil, err
	}
	return &dto.ScanCertificatesResponse{
		CertDir:      certDir,
		Certificates: certs,
		Count:        len(certs),
	}, nil
}

func (s *DomainService) ScanAndImportCertificates() (*dto.ScanImportCertificatesResponse, error) {
	certDir := s.certDir()
	certs, err := discoverCertificates(certDir)
	if err != nil {
		return nil, err
	}

	importedCount := 0
	updatedCount := 0
	skippedCount := 0
	errs := make([]string, 0)

	for _, cert := range certs {
		_, _, certDomains, isWildcard, parseErr := utils.ParseCertificateDetails(cert.CertPath)
		if parseErr != nil {
			errs = append(errs, fmt.Sprintf("解析证书 %s 失败: %v", cert.Domain, parseErr))
			continue
		}

		actualDomain := cert.Domain
		for _, d := range certDomains {
			if strings.HasPrefix(d, "*.") {
				actualDomain = d
				break
			}
		}

		var existing models.Domain
		if err := s.db.Where("domain = ?", actualDomain).First(&existing).Error; err == nil {
			if existing.CertPath != cert.CertPath || existing.KeyPath != cert.KeyPath || existing.IsWildcard != isWildcard {
				existing.CertPath = cert.CertPath
				existing.KeyPath = cert.KeyPath
				existing.IsWildcard = isWildcard
				if saveErr := s.db.Save(&existing).Error; saveErr != nil {
					errs = append(errs, fmt.Sprintf("更新 %s 失败: %v", actualDomain, saveErr))
					continue
				}
				updatedCount++
			} else {
				skippedCount++
			}
			continue
		}

		newDomain := models.Domain{
			Domain:     actualDomain,
			Type:       models.DomainTypeDirect,
			IsWildcard: isWildcard,
			CertPath:   cert.CertPath,
			KeyPath:    cert.KeyPath,
			Enabled:    true,
		}
		if createErr := s.db.Create(&newDomain).Error; createErr != nil {
			errs = append(errs, fmt.Sprintf("导入 %s 失败: %v", actualDomain, createErr))
			continue
		}
		importedCount++
	}

	listRes, err := s.List()
	if err != nil {
		return nil, err
	}

	return &dto.ScanImportCertificatesResponse{
		CertDir:       certDir,
		ImportedCount: importedCount,
		UpdatedCount:  updatedCount,
		SkippedCount:  skippedCount,
		Errors:        errs,
		Domains:       listRes.Domains,
	}, nil
}

// validateCertPathWithinCertDir requires p to be an absolute path inside the
// configured certificate directory (Nginx.CertDir, default /root/.acme.sh).
// This stops a token holder from pointing the panel at arbitrary files on
// disk (the server runs as root) via import-cert. The check runs before the
// file is read or parsed.
func (s *DomainService) validateCertPathWithinCertDir(p string) error {
	certDir := filepath.Clean(s.certDir())
	clean := filepath.Clean(strings.TrimSpace(p))
	if !filepath.IsAbs(clean) {
		return NewValidationError("证书路径必须是绝对路径: " + p)
	}
	if clean != certDir && !strings.HasPrefix(clean, certDir+string(os.PathSeparator)) {
		return NewValidationError("证书路径必须位于证书目录内 (" + certDir + "): " + p)
	}
	return nil
}

func (s *DomainService) ImportSingleCertificate(req dto.ImportCertRequest) (*dto.DomainDTO, error) {
	certPath := strings.TrimSpace(req.CertPath)
	keyPath := strings.TrimSpace(req.KeyPath)
	if err := validateCertificatePaths(certPath, keyPath); err != nil {
		return nil, err
	}
	if err := s.validateCertPathWithinCertDir(certPath); err != nil {
		return nil, err
	}
	if err := s.validateCertPathWithinCertDir(keyPath); err != nil {
		return nil, err
	}

	_, _, certDomains, isWildcard, _ := utils.ParseCertificateDetails(certPath)
	actualDomain := strings.TrimSpace(req.Domain)
	for _, d := range certDomains {
		if strings.HasPrefix(d, "*.") {
			actualDomain = d
			break
		}
	}
	if !validateDomainFormat(actualDomain) {
		return nil, NewValidationError("域名格式无效")
	}

	var existing models.Domain
	if err := s.db.Where("domain = ?", actualDomain).First(&existing).Error; err == nil {
		existing.CertPath = certPath
		existing.KeyPath = keyPath
		existing.IsWildcard = isWildcard
		if saveErr := s.db.Save(&existing).Error; saveErr != nil {
			return nil, NewInternalError("更新证书域名失败", saveErr)
		}
		dto := toDomainDTO(existing)
		return &dto, nil
	}

	newDomain := models.Domain{
		Domain:     actualDomain,
		Type:       models.DomainTypeDirect,
		IsWildcard: isWildcard,
		CertPath:   certPath,
		KeyPath:    keyPath,
		Enabled:    true,
	}
	if err := s.db.Create(&newDomain).Error; err != nil {
		return nil, NewInternalError("导入证书域名失败", err)
	}
	dto := toDomainDTO(newDomain)
	return &dto, nil
}

// UploadCertificate validates and saves PEM certificate + private key files to certDir and upserts Domain.
func (s *DomainService) UploadCertificate(req dto.UploadCertRequest) (*dto.DomainDTO, error) {
	domainName := strings.TrimSpace(req.Domain)
	if !validateDomainFormat(domainName) {
		return nil, NewValidationError("域名格式无效")
	}

	dtype := models.DomainTypeDirect
	if req.Type != "" {
		dtype = models.DomainType(strings.TrimSpace(req.Type))
	}
	if dtype != models.DomainTypeDirect && dtype != models.DomainTypeCDN {
		return nil, NewValidationError("上传证书仅支持 direct 或 cdn 域名类型")
	}

	certPEM := strings.TrimSpace(req.CertPEM)
	keyPEM := strings.TrimSpace(req.KeyPEM)
	if certPEM == "" || keyPEM == "" {
		return nil, NewValidationError("证书内容与私钥内容不能为空")
	}

	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return nil, NewValidationError("证书与私钥解析失败或不匹配: " + err.Error())
	}

	_, _, certDomains, isWildcard, parseErr := utils.ParseCertificateDetailsFromBytes([]byte(certPEM), domainName)
	if parseErr != nil {
		return nil, NewValidationError("解析 X.509 证书失败: " + parseErr.Error())
	}
	if strings.HasPrefix(domainName, "*.") {
		isWildcard = true
	} else {
		for _, d := range certDomains {
			if strings.HasPrefix(d, "*.") {
				isWildcard = true
				break
			}
		}
	}

	certDir := s.certDir()
	safeFolder := sanitizeCertFolderName(domainName)
	targetDir := filepath.Clean(filepath.Join(certDir, safeFolder))
	// Uploaded PEM content is always written under certDir; reuse the same
	// containment check as import-cert so both entry points share one rule.
	if err := s.validateCertPathWithinCertDir(targetDir); err != nil {
		return nil, NewValidationError("非法的证书存储路径")
	}
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, NewInternalError("创建证书目录失败", err)
	}

	certPath := filepath.Join(targetDir, "fullchain.pem")
	keyPath := filepath.Join(targetDir, "privkey.pem")
	if err := os.WriteFile(certPath, []byte(certPEM+"\n"), 0644); err != nil {
		return nil, NewInternalError("写入证书文件失败", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM+"\n"), 0600); err != nil {
		return nil, NewInternalError("写入私钥文件失败", err)
	}

	return s.upsertCertDomain(domainName, dtype, isWildcard, certPath, keyPath, req.Enabled)
}

// IssueCertificate issues a TLS certificate using DNS-01 ACME (Cloudflare or LuaDNS) via acme.sh.
func (s *DomainService) IssueCertificate(ctx context.Context, req dto.IssueCertRequest) (*dto.IssueCertResponse, error) {
	domainName := strings.TrimSpace(req.Domain)
	if !validateDomainFormat(domainName) {
		return nil, NewValidationError("域名格式无效")
	}

	dtype := models.DomainTypeDirect
	if req.Type != "" {
		dtype = models.DomainType(strings.TrimSpace(req.Type))
	}
	if dtype != models.DomainTypeDirect && dtype != models.DomainTypeCDN {
		return nil, NewValidationError("申请证书仅支持 direct 或 cdn 域名类型")
	}

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	var dnsPlugin string
	var extraEnv []string
	var secretsToRedact []string

	switch provider {
	case "cf", "cloudflare":
		provider = "cf"
		dnsPlugin = "dns_cf"
		cfToken := strings.TrimSpace(req.CFToken)
		cfKey := strings.TrimSpace(req.CFKey)
		cfEmail := strings.TrimSpace(req.CFEmail)
		cfZoneID := strings.TrimSpace(req.CFZoneID)
		if cfToken != "" {
			extraEnv = append(extraEnv, "CF_Token="+cfToken)
			secretsToRedact = append(secretsToRedact, cfToken)
			if cfZoneID != "" {
				extraEnv = append(extraEnv, "CF_Zone_ID="+cfZoneID)
			}
		} else if cfKey != "" && cfEmail != "" {
			extraEnv = append(extraEnv, "CF_Key="+cfKey, "CF_Email="+cfEmail)
			secretsToRedact = append(secretsToRedact, cfKey)
			if cfZoneID != "" {
				extraEnv = append(extraEnv, "CF_Zone_ID="+cfZoneID)
			}
		} else {
			return nil, NewValidationError("Cloudflare 需提供 CF_Token，或同时提供 CF_Key 与 CF_Email")
		}
	case "luadns", "lua":
		provider = "luadns"
		dnsPlugin = "dns_lua"
		luaKey := strings.TrimSpace(req.LuaKey)
		luaEmail := strings.TrimSpace(req.LuaEmail)
		if luaKey == "" || luaEmail == "" {
			return nil, NewValidationError("LuaDNS 必须提供 lua_key 与 lua_email")
		}
		extraEnv = append(extraEnv, "LUA_Key="+luaKey, "LUA_Email="+luaEmail)
		secretsToRedact = append(secretsToRedact, luaKey)
	default:
		return nil, NewValidationError("不支持的 DNS 服务商，当前支持: cf (Cloudflare), luadns")
	}

	caServer := strings.ToLower(strings.TrimSpace(req.CAServer))
	if caServer == "" {
		caServer = "letsencrypt"
	}
	if caServer != "letsencrypt" && caServer != "zerossl" {
		return nil, NewValidationError("不支持的 CA 服务商，允许值: letsencrypt, zerossl")
	}
	email := strings.TrimSpace(req.Email)
	if caServer == "zerossl" && email == "" {
		return nil, NewValidationError("使用 ZeroSSL 申请证书时必须填写邮箱 (email)")
	}

	baseDomain := strings.TrimPrefix(domainName, "*.")
	wantWildcard := req.IncludeWildcard || strings.HasPrefix(domainName, "*.")
	storedDomain := baseDomain
	if wantWildcard {
		storedDomain = "*." + baseDomain
	}

	if email != "" {
		regArgs := []string{"--register-account", "-m", email, "--server", caServer}
		regOut, regCode, regErr := s.acmeRunner.Run(ctx, regArgs, extraEnv)
		if regErr != nil && regCode < 0 {
			return nil, NewSystemCommandError("ACME 账户初始化失败: "+redactSecrets(regOut, secretsToRedact), regErr)
		}
	}

	issueArgs := []string{"--issue", "--dns", dnsPlugin, "--server", caServer, "-d", baseDomain}
	if wantWildcard {
		issueArgs = append(issueArgs, "-d", "*."+baseDomain)
	}
	reloadCmd := "systemctl reload nginx"
	if s.cfg != nil && s.cfg.Nginx.ReloadCmd != "" {
		reloadCmd = s.cfg.Nginx.ReloadCmd
	}
	issueArgs = append(issueArgs, "--reloadcmd", reloadCmd)
	if req.Force {
		issueArgs = append(issueArgs, "--force")
	}

	output, exitCode, runErr := s.acmeRunner.Run(ctx, issueArgs, extraEnv)
	cleanOutput := redactSecrets(output, secretsToRedact)
	reused := false

	if runErr != nil {
		if exitCode == 2 {
			// acme.sh returns exit code 2 when certificate is unchanged / skipped
			reused = true
		} else {
			return nil, NewSystemCommandError("ACME 证书申请失败: "+cleanOutput, runErr)
		}
	}

	certPath, keyPath, ok := resolveIssuedCertPaths(s.certDir(), baseDomain)
	if !ok {
		return nil, NewSystemCommandError("证书命令执行完成但未找到签发文件: "+cleanOutput, errors.New("issued cert files missing"))
	}

	domDTO, err := s.upsertCertDomain(storedDomain, dtype, wantWildcard, certPath, keyPath, nil)
	if err != nil {
		return nil, err
	}

	return &dto.IssueCertResponse{
		Domain:         *domDTO,
		Provider:       provider,
		CAServer:       caServer,
		ReusedExisting: reused,
		Output:         cleanOutput,
	}, nil
}

func (s *DomainService) upsertCertDomain(domainName string, dtype models.DomainType, isWildcard bool, certPath, keyPath string, enabledPtr *bool) (*dto.DomainDTO, error) {
	var existing models.Domain
	if err := s.db.Where("domain = ?", domainName).First(&existing).Error; err == nil {
		existing.Type = dtype
		existing.IsWildcard = isWildcard
		existing.CertPath = certPath
		existing.KeyPath = keyPath
		if enabledPtr != nil {
			existing.Enabled = *enabledPtr
		} else {
			existing.Enabled = true
		}
		if err := s.db.Save(&existing).Error; err != nil {
			return nil, NewInternalError("更新域名证书记录失败", err)
		}
		dto := toDomainDTO(existing)
		return &dto, nil
	}

	enabled := true
	if enabledPtr != nil {
		enabled = *enabledPtr
	}
	newDomain := models.Domain{
		Domain:     domainName,
		Type:       dtype,
		IsWildcard: isWildcard,
		CertPath:   certPath,
		KeyPath:    keyPath,
		Enabled:    enabled,
	}
	if err := s.db.Create(&newDomain).Error; err != nil {
		return nil, NewInternalError("保存域名证书记录失败", err)
	}
	dto := toDomainDTO(newDomain)
	return &dto, nil
}

func sanitizeCertFolderName(domain string) string {
	cleaned := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(domain)), "*.", "_wildcard.")
	cleaned = strings.ReplaceAll(cleaned, "/", "_")
	cleaned = strings.ReplaceAll(cleaned, "..", "_")
	return cleaned
}

func resolveIssuedCertPaths(certDir, baseDomain string) (string, string, bool) {
	candidates := []string{
		filepath.Join(certDir, baseDomain+"_ecc"),
		filepath.Join(certDir, baseDomain),
		filepath.Join(certDir, baseDomain+"_rsa"),
	}
	for _, dir := range candidates {
		fullchain := filepath.Join(dir, "fullchain.cer")
		certFallback := filepath.Join(dir, baseDomain+".cer")
		keyFile := filepath.Join(dir, baseDomain+".key")
		if fileExists(keyFile) {
			if fileExists(fullchain) {
				return fullchain, keyFile, true
			}
			if fileExists(certFallback) {
				return certFallback, keyFile, true
			}
		}
	}
	return "", "", false
}

func redactSecrets(text string, secrets []string) string {
	res := text
	for _, sec := range secrets {
		if sec != "" {
			res = strings.ReplaceAll(res, sec, "***")
		}
	}
	return strings.TrimSpace(res)
}

const (
	// Pinned acme.sh release. The master branch is never used: a floating
	// ref plus no integrity check meant any upstream change (or a
	// compromised download) would run as root on first issuance.
	// Bump together with defaultAcmeArchiveSHA256 and scripts/install.sh.
	defaultAcmeVersion    = "3.1.6"
	defaultAcmeArchiveURL = "https://github.com/acmesh-official/acme.sh/archive/refs/tags/3.1.6.tar.gz"
	// SHA-256 of the 3.1.6 release tarball, fetched 2026-11-11 over HTTPS
	// and verified to contain acme.sh + dnsapi/dns_cf.sh. A custom
	// archive_url in config must come with its own archive_sha256.
	defaultAcmeArchiveSHA256 = "0d3f9000ac44a6331314742a88c475f79134e24fc991997883652adc59efc486"
	maxAcmeArchiveBytes      = 64 << 20 // 64 MiB safety limit for the acme.sh archive
)

type execAcmeRunner struct {
	certDirFn           func() string
	archiveURL          string
	archiveSHA256       string // empty = skip verification (only for tests with a local archive)
	httpClient          *http.Client
	skipSystemLookup    bool
	autoInstallDisabled bool
	installMu           sync.Mutex
}

func (r *execAcmeRunner) Run(ctx context.Context, args []string, extraEnv []string) (string, int, error) {
	certDir := strings.TrimSpace(r.certDirFn())
	if certDir == "" {
		certDir = "/root/.acme.sh"
	}

	acmeBin, acmeHome, err := r.ensureBinary(ctx, certDir)
	if err != nil {
		return err.Error(), -1, err
	}

	fullArgs := []string{"--home", acmeHome}
	if filepath.Clean(certDir) != filepath.Clean(acmeHome) {
		fullArgs = append(fullArgs, "--cert-home", certDir)
	}
	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, acmeBin, fullArgs...)
	// Pin the acme.sh working directory explicitly. --home already does
	// this, but LE_WORKING_DIR/LE_CONFIG_HOME make it independent of $HOME
	// and of any --home parsing change: account.conf and the account key
	// must never land in an unexpected home directory.
	env := envWithHome(os.Environ(), resolveHomeEnv(certDir), extraEnv)
	env = append(env, "LE_WORKING_DIR="+acmeHome, "LE_CONFIG_HOME="+acmeHome)
	cmd.Env = env

	outBytes, runErr := cmd.CombinedOutput()
	output := string(outBytes)
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return output, exitErr.ExitCode(), runErr
		}
		return output, -1, runErr
	}
	// Issuance / account registration can create account.conf and account
	// keys; re-tighten best-effort so a permissive umask never leaves
	// DNS API credentials world-readable.
	r.tightenAcmeHome(acmeHome, certDir)
	return output, 0, nil
}

func (r *execAcmeRunner) ensureBinary(ctx context.Context, certDir string) (string, string, error) {
	if acmeBin, acmeHome, ok := r.findExistingBinary(certDir); ok {
		return acmeBin, acmeHome, nil
	}

	r.installMu.Lock()
	defer r.installMu.Unlock()

	if acmeBin, acmeHome, ok := r.findExistingBinary(certDir); ok {
		return acmeBin, acmeHome, nil
	}

	if r.autoInstallDisabled {
		return "", "", fmt.Errorf("未找到 acme.sh，且配置已关闭自动安装 (acme.auto_install=false)；请用 scripts/install.sh 预装，或开启自动安装")
	}

	archiveURL := strings.TrimSpace(r.archiveURL)
	if archiveURL == "" {
		archiveURL = defaultAcmeArchiveURL
	}
	expectedSHA256 := strings.ToLower(strings.TrimSpace(r.archiveSHA256))
	if expectedSHA256 == "" && archiveURL == defaultAcmeArchiveURL {
		expectedSHA256 = defaultAcmeArchiveSHA256
	}
	if expectedSHA256 == "" {
		return "", "", fmt.Errorf("拒绝下载 acme.sh：未提供 archive_sha256，无法校验安装包完整性")
	}
	installed, err := installAcmeFromArchive(ctx, r.httpClient, archiveURL, expectedSHA256, certDir)
	if err != nil {
		return "", "", err
	}
	return installed, certDir, nil
}

func (r *execAcmeRunner) findExistingBinary(certDir string) (string, string, bool) {
	var candidates []string
	if strings.TrimSpace(certDir) != "" {
		candidates = append(candidates, filepath.Join(certDir, "acme.sh"))
	}
	if !r.skipSystemLookup {
		if userHome, err := os.UserHomeDir(); err == nil && strings.TrimSpace(userHome) != "" {
			candidates = append(candidates, filepath.Join(userHome, ".acme.sh", "acme.sh"))
		}
		candidates = append(candidates, "/root/.acme.sh/acme.sh")
	}

	for _, c := range candidates {
		if fileExists(c) {
			return c, resolveAcmeHomeDir(c), true
		}
	}
	if !r.skipSystemLookup {
		if p, err := exec.LookPath("acme.sh"); err == nil {
			return p, resolveAcmeHomeDir(p), true
		}
	}
	return "", "", false
}

func resolveAcmeHomeDir(acmeBin string) string {
	dir := filepath.Dir(acmeBin)
	if dirExists(filepath.Join(dir, "dnsapi")) {
		return dir
	}
	if resolved, err := filepath.EvalSymlinks(acmeBin); err == nil {
		resolvedDir := filepath.Dir(resolved)
		if dirExists(filepath.Join(resolvedDir, "dnsapi")) {
			return resolvedDir
		}
	}
	return dir
}

func installAcmeFromArchive(ctx context.Context, client *http.Client, archiveURL, expectedSHA256, targetHome string) (string, error) {
	// The acme home holds account.conf with DNS API credentials
	// (CF_Token etc.) and the ACME account key: 0700, and tighten an
	// already-existing directory too (MkdirAll alone never narrows perms).
	if err := os.MkdirAll(targetHome, 0700); err != nil {
		return "", fmt.Errorf("创建 acme.sh 目录 %s 失败: %w", targetHome, err)
	}
	if err := os.Chmod(targetHome, 0700); err != nil {
		return "", fmt.Errorf("收紧 acme.sh 目录权限 %s 失败: %w", targetHome, err)
	}

	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, nil)
	if err != nil {
		return "", fmt.Errorf("构造 acme.sh 下载请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "xray-panel-server")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("下载 acme.sh 失败 (%s): %w", archiveURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippetBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("下载 acme.sh 返回 HTTP %d (%s): %s", resp.StatusCode, archiveURL, strings.TrimSpace(string(snippetBytes)))
	}

	tmpDir, err := os.MkdirTemp("", "xray-panel-acme-*")
	if err != nil {
		return "", fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download to a file first so the SHA-256 can be verified before
	// anything from the archive is executed. The archive is only ~0.5 MiB;
	// maxAcmeArchiveBytes still caps a malicious oversized response.
	archiveFile, err := os.CreateTemp(tmpDir, "acme-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("创建下载临时文件失败: %w", err)
	}
	archivePath := archiveFile.Name()
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(archiveFile, hasher), io.LimitReader(resp.Body, maxAcmeArchiveBytes+1))
	closeErr := archiveFile.Close()
	if copyErr != nil {
		return "", fmt.Errorf("下载 acme.sh 失败 (%s): %w", archiveURL, copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("保存 acme.sh 安装包失败: %w", closeErr)
	}
	if written > maxAcmeArchiveBytes {
		return "", fmt.Errorf("acme.sh 安装包超过大小限制 (%d 字节)", maxAcmeArchiveBytes)
	}
	actualSHA256 := hex.EncodeToString(hasher.Sum(nil))
	if actualSHA256 != strings.ToLower(expectedSHA256) {
		return "", fmt.Errorf("acme.sh 安装包 SHA-256 校验失败：期望 %s，实际 %s（安装包可能被篡改或版本已变更，请更新配置中的 pin）", strings.ToLower(expectedSHA256), actualSHA256)
	}

	archiveReader, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("读取 acme.sh 安装包失败: %w", err)
	}
	defer archiveReader.Close()
	if err := extractTarGz(archiveReader, tmpDir); err != nil {
		return "", fmt.Errorf("解压 acme.sh 压缩包失败: %w", err)
	}

	installerScript := findExtractedAcmeScript(tmpDir)
	if installerScript == "" {
		return "", fmt.Errorf("解压后的压缩包中未找到 acme.sh 安装脚本")
	}
	_ = os.Chmod(installerScript, 0755)

	homeEnv := resolveHomeEnv(targetHome)
	installEnv := envWithHome(os.Environ(), homeEnv, nil)
	installEnv = append(installEnv, "LE_WORKING_DIR="+targetHome, "LE_CONFIG_HOME="+targetHome)

	installArgs := []string{"--install", "--home", targetHome}
	_, cronErr := exec.LookPath("crontab")
	if cronErr != nil {
		installArgs = append(installArgs, "--nocron", "--force")
	}

	runInstall := func(args []string) (string, error) {
		cmd := exec.CommandContext(ctx, installerScript, args...)
		cmd.Dir = filepath.Dir(installerScript)
		cmd.Env = installEnv
		out, runErr := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), runErr
	}

	outStr, runErr := runInstall(installArgs)
	installed := filepath.Join(targetHome, "acme.sh")
	if runErr != nil || !fileExists(installed) {
		if cronErr == nil {
			retryArgs := []string{"--install", "--home", targetHome, "--nocron", "--force"}
			retryOut, retryErr := runInstall(retryArgs)
			if retryErr == nil && fileExists(installed) {
				_ = os.Chmod(installed, 0755)
				return finalizeAcmeInstall(ctx, installed, targetHome)
			}
			if retryOut != "" {
				outStr = retryOut
			}
			if retryErr != nil {
				runErr = retryErr
			}
		}
		if runErr != nil {
			return "", fmt.Errorf("自动安装 acme.sh 失败: %v (%s)", runErr, outStr)
		}
		return "", fmt.Errorf("未找到 acme.sh 可执行文件 (%s): %s", installed, outStr)
	}

	_ = os.Chmod(installed, 0755)
	return finalizeAcmeInstall(ctx, installed, targetHome)
}

// finalizeAcmeInstall tightens permissions on the freshly installed acme
// home and smoke-tests the binary before the panel trusts it. A wrong
// binary (or a half-copied install) must fail here, not at the first real
// issuance.
func finalizeAcmeInstall(ctx context.Context, installed, targetHome string) (string, error) {
	tightenAcmeHome(targetHome, targetHome)
	cmd := exec.CommandContext(ctx, installed, "--home", targetHome, "--version")
	cmd.Env = envWithHome(os.Environ(), resolveHomeEnv(targetHome), []string{"LE_WORKING_DIR=" + targetHome, "LE_CONFIG_HOME=" + targetHome})
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("安装后校验 acme.sh 失败 (%s): %v", strings.TrimSpace(string(out)), err)
	}
	if !strings.Contains(string(out), "acme.sh") && !strings.Contains(string(out), "3.") {
		return "", fmt.Errorf("安装后校验 acme.sh 失败：--version 输出异常: %s", strings.TrimSpace(string(out)))
	}
	return installed, nil
}

// tightenAcmeHome enforces 0700 on a panel-managed acme home and 0600 on
// the files that hold credentials. It only touches homes the panel owns
// (acmeHome == certDir or inside it); a system-wide acme.sh found via PATH
// is left alone.
func (r *execAcmeRunner) tightenAcmeHome(acmeHome, certDir string) {
	tightenAcmeHome(acmeHome, certDir)
}

func tightenAcmeHome(acmeHome, certDir string) {
	home := filepath.Clean(strings.TrimSpace(acmeHome))
	base := filepath.Clean(strings.TrimSpace(certDir))
	if home == "" || base == "" {
		return
	}
	if home != base && !strings.HasPrefix(home, base+string(os.PathSeparator)) {
		return
	}
	_ = os.Chmod(home, 0700)
	for _, name := range []string{"account.conf", "account.key"} {
		_ = os.Chmod(filepath.Join(home, name), 0600)
	}
}

func extractTarGz(r io.Reader, destDir string) error {
	gzr, err := gzip.NewReader(io.LimitReader(r, maxAcmeArchiveBytes))
	if err != nil {
		return err
	}
	defer gzr.Close()

	cleanDest := filepath.Clean(destDir)
	tr := tar.NewReader(gzr)
	var totalWritten int64

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		cleanRel := filepath.Clean(hdr.Name)
		if cleanRel == "." || cleanRel == string(os.PathSeparator) {
			continue
		}
		if filepath.IsAbs(cleanRel) || cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("非法归档路径: %s", hdr.Name)
		}

		targetPath := filepath.Join(cleanDest, cleanRel)
		if !strings.HasPrefix(targetPath, cleanDest+string(os.PathSeparator)) {
			return fmt.Errorf("非法解压目标路径: %s", targetPath)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			mode := os.FileMode(hdr.Mode) & os.ModePerm
			if mode == 0 {
				mode = 0755
			}
			if err := os.MkdirAll(targetPath, mode); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if hdr.Size < 0 || totalWritten+hdr.Size > maxAcmeArchiveBytes {
				return fmt.Errorf("归档解压体积超过安全限制")
			}
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return err
			}
			mode := os.FileMode(hdr.Mode) & os.ModePerm
			if mode == 0 {
				mode = 0644
			}
			f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			written, copyErr := io.CopyN(f, tr, hdr.Size)
			closeErr := f.Close()
			if copyErr != nil && !errors.Is(copyErr, io.EOF) {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			totalWritten += written
		case tar.TypeXHeader, tar.TypeXGlobalHeader:
			continue
		}
	}
	return nil
}

func findExtractedAcmeScript(rootDir string) string {
	direct := filepath.Join(rootDir, "acme.sh")
	if fileExists(direct) {
		return direct
	}
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			candidate := filepath.Join(rootDir, entry.Name(), "acme.sh")
			if fileExists(candidate) {
				return candidate
			}
		}
	}
	return ""
}

func resolveHomeEnv(certDir string) string {
	clean := filepath.Clean(strings.TrimSpace(certDir))
	// Standard layout <home>/.acme.sh: HOME is the parent directory, which
	// is what acme.sh itself assumes ($HOME/.acme.sh). This makes HOME
	// deterministic instead of inheriting whatever the service was started
	// with.
	if filepath.Base(clean) == ".acme.sh" {
		if parent := filepath.Dir(clean); parent != "" && parent != "." {
			return parent
		}
	}
	if h := strings.TrimSpace(os.Getenv("HOME")); h != "" {
		return h
	}
	if h, err := os.UserHomeDir(); err == nil && strings.TrimSpace(h) != "" {
		return h
	}
	if os.Geteuid() == 0 {
		return "/root"
	}
	if parent := filepath.Dir(clean); parent != "" && parent != "." {
		return parent
	}
	// Never fall back to /tmp: a world-writable HOME would let acme.sh
	// (or anything it shells out to) create files outside the panel's
	// directories.
	return clean
}

func envWithHome(baseEnv []string, homeVal string, extraEnv []string) []string {
	res := make([]string, 0, len(baseEnv)+len(extraEnv)+1)
	hasHome := false
	for _, entry := range baseEnv {
		if strings.HasPrefix(entry, "HOME=") {
			if strings.TrimSpace(strings.TrimPrefix(entry, "HOME=")) == "" {
				res = append(res, "HOME="+homeVal)
			} else {
				res = append(res, entry)
			}
			hasHome = true
			continue
		}
		res = append(res, entry)
	}
	if !hasHome {
		res = append(res, "HOME="+homeVal)
	}
	res = append(res, extraEnv...)
	return res
}

// findMatchingDomainCert locates an enabled direct/cdn Domain with existing cert+key files matching host
// (exact match first, then *.parent wildcard match).
func findMatchingDomainCert(db *gorm.DB, host string) (*models.Domain, error) {
	target := strings.ToLower(strings.TrimSpace(host))
	if target == "" {
		return nil, NewValidationError("域名不能为空")
	}

	var domains []models.Domain
	if err := db.Where("enabled = ? AND type IN ?", true, []string{string(models.DomainTypeDirect), string(models.DomainTypeCDN)}).
		Order("is_wildcard ASC, created_at DESC").Find(&domains).Error; err != nil {
		return nil, NewInternalError("查询域名证书失败", err)
	}

	for i := range domains {
		d := &domains[i]
		if strings.EqualFold(d.Domain, target) && fileExists(d.CertPath) && fileExists(d.KeyPath) {
			return d, nil
		}
	}

	parts := strings.SplitN(target, ".", 2)
	if len(parts) == 2 {
		wildcardName := "*." + parts[1]
		for i := range domains {
			d := &domains[i]
			if strings.EqualFold(d.Domain, wildcardName) && fileExists(d.CertPath) && fileExists(d.KeyPath) {
				return d, nil
			}
		}
	}

	return nil, nil
}

func (s *DomainService) certDir() string {
	if s.cfg != nil && s.cfg.Nginx.CertDir != "" {
		return s.cfg.Nginx.CertDir
	}
	return "/root/.acme.sh"
}

func discoverCertificates(certDir string) ([]dto.CertificateInfo, error) {
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		return nil, NewNotFoundError("Certificate directory not found: " + certDir)
	}

	entries, err := os.ReadDir(certDir)
	if err != nil {
		return nil, NewInternalError("Failed to read certificate directory", err)
	}

	isAcmeShDir := strings.Contains(certDir, ".acme.sh") || strings.Contains(certDir, "acme.sh")
	certificates := make([]dto.CertificateInfo, 0)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirName := entry.Name()
		if dirName == "." || dirName == ".." {
			continue
		}
		if isAcmeShDir {
			if dirName == "ca" || dirName == "deploy" || dirName == "dnsapi" || dirName == "notify" {
				continue
			}
		} else if dirName == "README" || dirName == "ca" {
			continue
		}

		domainPath := filepath.Join(certDir, dirName)
		domain := strings.TrimSuffix(strings.TrimSuffix(dirName, "_ecc"), "_rsa")

		var certPath, keyPath string
		acmeCertPath := filepath.Join(domainPath, dirName+".cer")
		acmeFullchainPath := filepath.Join(domainPath, "fullchain.cer")
		acmeKeyPath := filepath.Join(domainPath, dirName+".key")

		if fileExists(acmeFullchainPath) {
			certPath = acmeFullchainPath
		} else if fileExists(acmeCertPath) {
			certPath = acmeCertPath
		}
		if fileExists(acmeKeyPath) {
			keyPath = acmeKeyPath
		}

		if certPath == "" || keyPath == "" {
			leCertPath := filepath.Join(domainPath, "fullchain.pem")
			leKeyPath := filepath.Join(domainPath, "privkey.pem")
			if fileExists(leCertPath) && fileExists(leKeyPath) {
				certPath = leCertPath
				keyPath = leKeyPath
			}
		}

		if certPath == "" || keyPath == "" {
			continue
		}

		issuer, expiry, domains, isWildcard, parseErr := utils.ParseCertificateDetails(certPath)
		status, daysToExpiry := classifyCertificateStatus(expiry)
		if parseErr != nil {
			issuer = "Unknown"
			expiry = time.Time{}
			domains = []string{domain}
			status = "unknown"
			daysToExpiry = 0
			isWildcard = false
		}

		certificates = append(certificates, dto.CertificateInfo{
			Domain:       domain,
			Domains:      domains,
			CertPath:     certPath,
			KeyPath:      keyPath,
			ExpiryDate:   expiry,
			DaysToExpiry: daysToExpiry,
			Status:       status,
			Issuer:       issuer,
			IsWildcard:   isWildcard,
			Exists:       true,
		})
	}

	return certificates, nil
}

func classifyCertificateStatus(expiry time.Time) (string, int) {
	daysToExpiry := int(time.Until(expiry).Hours() / 24)
	if daysToExpiry < 0 {
		return "expired", daysToExpiry
	}
	if daysToExpiry <= 30 {
		return "expiring_soon", daysToExpiry
	}
	return "valid", daysToExpiry
}

func validateDomainFormat(domain string) bool {
	if domain == "" {
		return false
	}
	return domainRegex.MatchString(domain)
}

func isValidDomainType(t models.DomainType) bool {
	return t == models.DomainTypeDirect || t == models.DomainTypeCDN
}

func validateCertificatePaths(certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return NewValidationError("证书路径和密钥路径不能为空")
	}
	if !fileExists(certPath) {
		return NewValidationError("证书文件不存在: " + certPath)
	}
	if !fileExists(keyPath) {
		return NewValidationError("密钥文件不存在: " + keyPath)
	}
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func toDomainDTO(d models.Domain) dto.DomainDTO {
	dto := dto.DomainDTO{
		ID:         d.ID,
		Domain:     d.Domain,
		Type:       string(d.Type),
		IsWildcard: d.IsWildcard,
		CertPath:   d.CertPath,
		KeyPath:    d.KeyPath,
		Enabled:    d.Enabled,
		CreatedAt:  d.CreatedAt,
		UpdatedAt:  d.UpdatedAt,
	}

	if d.CertPath != "" {
		if issuer, expiry, _, _, err := utils.ParseCertificateDetails(d.CertPath); err == nil {
			dto.HasCert = true
			dto.CertExpiryDate = &expiry
			days := int(time.Until(expiry).Hours() / 24)
			dto.DaysToExpiry = &days
			dto.CertIssuer = issuer
		}
	}

	return dto
}
