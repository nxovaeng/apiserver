package service

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm"

	"xray-panel-server/internal/config"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/utils"
)

var domainRegex = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// DomainService manages domains and TLS/ACME certificate discovery & import.
type DomainService struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewDomainService(db *gorm.DB, cfg *config.Config) *DomainService {
	return &DomainService{db: db, cfg: cfg}
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
		return nil, NewValidationError("无效的域名类型，允许值: direct, cdn, reality")
	}

	certPath := strings.TrimSpace(req.CertPath)
	keyPath := strings.TrimSpace(req.KeyPath)
	if dtype == models.DomainTypeDirect || dtype == models.DomainTypeCDN {
		if err := validateCertificatePaths(certPath, keyPath); err != nil {
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
		Domain:      domainName,
		Type:        dtype,
		IsWildcard:  isWildcard,
		ServerName:  strings.TrimSpace(req.ServerName),
		Fingerprint: strings.TrimSpace(req.Fingerprint),
		ShortID:     strings.TrimSpace(req.ShortID),
		PrivateKey:  strings.TrimSpace(req.PrivateKey),
		PublicKey:   strings.TrimSpace(req.PublicKey),
		CertPath:    certPath,
		KeyPath:     keyPath,
		Enabled:     enabled,
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
		return nil, NewValidationError("无效的域名类型，允许值: direct, cdn, reality")
	}

	certPath := strings.TrimSpace(req.CertPath)
	keyPath := strings.TrimSpace(req.KeyPath)
	if dtype == models.DomainTypeDirect || dtype == models.DomainTypeCDN {
		if err := validateCertificatePaths(certPath, keyPath); err != nil {
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
	domain.ServerName = strings.TrimSpace(req.ServerName)
	domain.Fingerprint = strings.TrimSpace(req.Fingerprint)
	domain.ShortID = strings.TrimSpace(req.ShortID)
	if strings.TrimSpace(req.PrivateKey) != "" {
		domain.PrivateKey = strings.TrimSpace(req.PrivateKey)
	}
	if strings.TrimSpace(req.PublicKey) != "" {
		domain.PublicKey = strings.TrimSpace(req.PublicKey)
	}
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

func (s *DomainService) ImportSingleCertificate(req dto.ImportCertRequest) (*dto.DomainDTO, error) {
	certPath := strings.TrimSpace(req.CertPath)
	keyPath := strings.TrimSpace(req.KeyPath)
	if err := validateCertificatePaths(certPath, keyPath); err != nil {
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
	return t == models.DomainTypeDirect || t == models.DomainTypeCDN || t == models.DomainTypeReality
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

func toDomainDTO(d models.Domain) dto.DomainDTO {
	dto := dto.DomainDTO{
		ID:            d.ID,
		Domain:        d.Domain,
		Type:          string(d.Type),
		IsWildcard:    d.IsWildcard,
		ServerName:    d.ServerName,
		Fingerprint:   d.Fingerprint,
		ShortID:       d.ShortID,
		HasPrivateKey: d.PrivateKey != "",
		PublicKey:     d.PublicKey,
		CertPath:      d.CertPath,
		KeyPath:       d.KeyPath,
		Enabled:       d.Enabled,
		CreatedAt:     d.CreatedAt,
		UpdatedAt:     d.UpdatedAt,
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
