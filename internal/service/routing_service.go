package service

import (
	"strings"

	"gorm.io/gorm"

	"xray-panel-server/internal/config"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/geodata"
	"xray-panel-server/internal/models"
)

// RoutingService manages Xray routing rules, presets, and GeoData discovery.
type RoutingService struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewRoutingService(db *gorm.DB, cfg *config.Config) *RoutingService {
	return &RoutingService{db: db, cfg: cfg}
}

func (s *RoutingService) List() (*dto.RoutingRuleListResponse, error) {
	var rules []models.RoutingRule
	if err := s.db.Order("priority ASC, created_at DESC").Find(&rules).Error; err != nil {
		return nil, NewInternalError("Failed to list routing rules", err)
	}
	dtos := make([]dto.RoutingRuleDTO, len(rules))
	for i, r := range rules {
		dtos[i] = toRoutingRuleDTO(r)
	}
	return &dto.RoutingRuleListResponse{Rules: dtos, Total: len(dtos)}, nil
}

func (s *RoutingService) Get(id string) (*dto.RoutingRuleDTO, error) {
	var rule models.RoutingRule
	if err := s.db.First(&rule, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Routing rule not found")
	}
	dto := toRoutingRuleDTO(rule)
	return &dto, nil
}

func (s *RoutingService) Create(req dto.UpsertRoutingRuleRequest) (*dto.RoutingRuleDTO, error) {
	name := strings.TrimSpace(req.Name)
	outboundTag := strings.TrimSpace(req.OutboundTag)
	rtype := models.RuleType(strings.TrimSpace(req.Type))

	if name == "" || outboundTag == "" || !isValidRuleType(rtype) {
		return nil, NewValidationError("规则名称、规则类型和目标出站不能为空")
	}

	priority := req.Priority
	if priority == 0 {
		priority = 100
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	rule := models.RoutingRule{
		Name:        name,
		Type:        rtype,
		InboundTag:  strings.TrimSpace(req.InboundTag),
		Domains:     strings.TrimSpace(req.Domains),
		IPs:         strings.TrimSpace(req.IPs),
		GeoSiteTags: strings.TrimSpace(req.GeoSiteTags),
		GeoIPCodes:  strings.TrimSpace(req.GeoIPCodes),
		Protocols:   strings.TrimSpace(req.Protocols),
		OutboundTag: outboundTag,
		Priority:    priority,
		Enabled:     enabled,
		Remark:      strings.TrimSpace(req.Remark),
	}

	if err := s.db.Create(&rule).Error; err != nil {
		return nil, NewInternalError("Failed to create routing rule", err)
	}

	dto := toRoutingRuleDTO(rule)
	return &dto, nil
}

func (s *RoutingService) Update(id string, req dto.UpsertRoutingRuleRequest) (*dto.RoutingRuleDTO, error) {
	var existing models.RoutingRule
	if err := s.db.First(&existing, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Routing rule not found")
	}

	name := strings.TrimSpace(req.Name)
	outboundTag := strings.TrimSpace(req.OutboundTag)
	rtype := models.RuleType(strings.TrimSpace(req.Type))
	if name == "" || outboundTag == "" || !isValidRuleType(rtype) {
		return nil, NewValidationError("规则名称、规则类型和目标出站不能为空")
	}

	existing.Name = name
	existing.Type = rtype
	existing.InboundTag = strings.TrimSpace(req.InboundTag)
	existing.Domains = strings.TrimSpace(req.Domains)
	existing.IPs = strings.TrimSpace(req.IPs)
	existing.GeoSiteTags = strings.TrimSpace(req.GeoSiteTags)
	existing.GeoIPCodes = strings.TrimSpace(req.GeoIPCodes)
	existing.Protocols = strings.TrimSpace(req.Protocols)
	existing.OutboundTag = outboundTag
	if req.Priority != 0 {
		existing.Priority = req.Priority
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	existing.Remark = strings.TrimSpace(req.Remark)

	if err := s.db.Save(&existing).Error; err != nil {
		return nil, NewInternalError("Failed to update routing rule", err)
	}

	dto := toRoutingRuleDTO(existing)
	return &dto, nil
}

func (s *RoutingService) Delete(id string) (*dto.DeleteResponse, error) {
	result := s.db.Delete(&models.RoutingRule{}, "id = ?", id)
	if result.Error != nil {
		return nil, NewInternalError("Failed to delete routing rule", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, NewNotFoundError("Routing rule not found")
	}
	return &dto.DeleteResponse{ID: id, Deleted: true}, nil
}

func (s *RoutingService) Toggle(id string) (*dto.RoutingRuleDTO, error) {
	var rule models.RoutingRule
	if err := s.db.First(&rule, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Routing rule not found")
	}
	rule.Enabled = !rule.Enabled
	if err := s.db.Save(&rule).Error; err != nil {
		return nil, NewInternalError("Failed to toggle routing rule", err)
	}
	dto := toRoutingRuleDTO(rule)
	return &dto, nil
}

func (s *RoutingService) ImportPreset(presetName string) (*dto.ImportPresetResponse, error) {
	presets := models.PresetRoutingRules()
	rules, exists := presets[presetName]
	if !exists {
		return nil, NewNotFoundError("预设模板不存在: " + presetName)
	}

	imported := 0
	skipped := 0
	for _, r := range rules {
		var existing models.RoutingRule
		if err := s.db.Where("name = ?", r.Name).First(&existing).Error; err == nil {
			skipped++
			continue
		}
		ruleCopy := r
		if err := s.db.Create(&ruleCopy).Error; err != nil {
			skipped++
			continue
		}
		imported++
	}

	listRes, err := s.List()
	if err != nil {
		return nil, err
	}

	return &dto.ImportPresetResponse{
		Preset:        presetName,
		ImportedCount: imported,
		SkippedCount:  skipped,
		Rules:         listRes.Rules,
	}, nil
}

func (s *RoutingService) GetGeoData() *dto.GeoDataInfo {
	assetsPath := "/usr/local/share/xray"
	if s.cfg != nil && s.cfg.Xray.AssetsPath != "" {
		assetsPath = s.cfg.Xray.AssetsPath
	}
	parser := geodata.NewGeoDataParser(assetsPath)
	info := parser.GetGeoDataInfo()
	return &dto.GeoDataInfo{
		GeoSiteAvailable: info.GeoSiteAvailable,
		GeoIPAvailable:   info.GeoIPAvailable,
		GeoSiteTags:      info.GeoSiteTags,
		GeoIPCodes:       info.GeoIPCodes,
	}
}

func isValidRuleType(t models.RuleType) bool {
	switch t {
	case models.RuleTypeInbound, models.RuleTypeDomain, models.RuleTypeIP,
		models.RuleTypeGeoSite, models.RuleTypeGeoIP, models.RuleTypeProtocol:
		return true
	default:
		return false
	}
}

func toRoutingRuleDTO(r models.RoutingRule) dto.RoutingRuleDTO {
	return dto.RoutingRuleDTO{
		ID:          r.ID,
		Name:        r.Name,
		Type:        string(r.Type),
		InboundTag:  r.InboundTag,
		Domains:     r.Domains,
		IPs:         r.IPs,
		GeoSiteTags: r.GeoSiteTags,
		GeoIPCodes:  r.GeoIPCodes,
		Protocols:   r.Protocols,
		OutboundTag: r.OutboundTag,
		Priority:    r.Priority,
		Enabled:     r.Enabled,
		Remark:      r.Remark,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}
