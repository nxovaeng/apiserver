package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"xray-panel-server/internal/config"
	"xray-panel-server/internal/dto"
	applogger "xray-panel-server/internal/logger"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/nginx"
	"xray-panel-server/internal/system"
	"xray-panel-server/internal/xray"
)

// SystemService manages Server-mode settings, Xray lifecycle, panel restart, and service logs.
type SystemService struct {
	db       *gorm.DB
	cfg      *config.Config
	nginxGen *nginx.ConfigGenerator
}

func NewSystemService(db *gorm.DB, cfg *config.Config, nginxGen *nginx.ConfigGenerator) *SystemService {
	return &SystemService{db: db, cfg: cfg, nginxGen: nginxGen}
}

func (s *SystemService) GetSettings() (*dto.SettingsDTO, error) {
	var settings []models.Setting
	if err := s.db.Find(&settings).Error; err != nil {
		return nil, NewInternalError("Failed to fetch settings", err)
	}

	m := make(map[string]string, len(settings))
	for _, item := range settings {
		m[item.Key] = item.Value
	}

	get := func(key, def string) string {
		if v, ok := m[key]; ok {
			return v
		}
		return def
	}

	trafficLimit, _ := strconv.ParseInt(get("default_traffic_limit", "0"), 10, 64)
	expireDays, _ := strconv.Atoi(get("default_expire_days", "30"))

	return &dto.SettingsDTO{
		PanelTitle:              get("panel_title", "Xray Panel"),
		SubDomain:               get("sub_domain", ""),
		SubPath:                 models.NormalizeSubPath(get("sub_path", "/d")),
		SubNginxEnabled:         get("sub_nginx_enabled", "false") == "true",
		APIDomain:               get("api_domain", ""),
		APINginxEnabled:         get("api_nginx_enabled", "false") == "true",
		ServerPublicHost:        get("server_public_host", ""),
		XrayLogLevel:            get("xray_log_level", "warning"),
		EnableTrafficStats:      get("enable_traffic_stats", "true") != "false",
		EnableSniffing:          get("enable_sniffing", "true") != "false",
		DefaultTrafficLimit:     trafficLimit,
		DefaultExpireDays:       expireDays,
		DirectDomainStrategy:    get("direct_domain_strategy", "UseIPv4"),
		CNIPFallback:            get("cn_ip_fallback", "proton"),
		MonthlyNetBaselineSent:  get("monthly_net_baseline_sent", ""),
		MonthlyNetBaselineRecv:  get("monthly_net_baseline_recv", ""),
		MonthlyNetBaselineMonth: get("monthly_net_baseline_month", ""),
	}, nil
}

func (s *SystemService) UpdateSettings(req dto.UpdateSettingsRequest) (*dto.SettingsDTO, error) {
	updates := make(map[string]string)

	if req.PanelTitle != nil {
		updates["panel_title"] = strings.TrimSpace(*req.PanelTitle)
	}
	if req.SubDomain != nil {
		updates["sub_domain"] = cleanHost(*req.SubDomain)
	}
	if req.SubPath != nil {
		normalized := models.NormalizeSubPath(*req.SubPath)
		if normalized == "/api" || strings.HasPrefix(normalized, "/api/") {
			return nil, NewValidationError("订阅路径前缀不能与 /api 冲突")
		}
		updates["sub_path"] = normalized
	}
	if req.SubNginxEnabled != nil {
		updates["sub_nginx_enabled"] = strconv.FormatBool(*req.SubNginxEnabled)
	}
	if req.APIDomain != nil {
		updates["api_domain"] = cleanHost(*req.APIDomain)
	}
	if req.APINginxEnabled != nil {
		updates["api_nginx_enabled"] = strconv.FormatBool(*req.APINginxEnabled)
	}
	if req.ServerPublicHost != nil {
		updates["server_public_host"] = cleanHost(*req.ServerPublicHost)
	}
	if req.XrayLogLevel != nil {
		lvl := strings.ToLower(strings.TrimSpace(*req.XrayLogLevel))
		switch lvl {
		case "debug", "info", "warning", "error", "none":
			updates["xray_log_level"] = lvl
		default:
			return nil, NewValidationError("无效的 xray_log_level，允许值: debug, info, warning, error, none")
		}
	}
	if req.EnableTrafficStats != nil {
		updates["enable_traffic_stats"] = strconv.FormatBool(*req.EnableTrafficStats)
	}
	if req.EnableSniffing != nil {
		updates["enable_sniffing"] = strconv.FormatBool(*req.EnableSniffing)
	}
	if req.DefaultTrafficLimit != nil {
		if *req.DefaultTrafficLimit < 0 {
			return nil, NewValidationError("default_traffic_limit 不能为负数")
		}
		updates["default_traffic_limit"] = strconv.FormatInt(*req.DefaultTrafficLimit, 10)
	}
	if req.DefaultExpireDays != nil {
		if *req.DefaultExpireDays < 0 {
			return nil, NewValidationError("default_expire_days 不能为负数")
		}
		updates["default_expire_days"] = strconv.Itoa(*req.DefaultExpireDays)
	}
	if req.DirectDomainStrategy != nil {
		strategy := strings.TrimSpace(*req.DirectDomainStrategy)
		switch strategy {
		case "AsIs", "UseIP", "UseIPv4", "UseIPv6":
			updates["direct_domain_strategy"] = strategy
		default:
			return nil, NewValidationError("无效的 direct_domain_strategy，允许值: AsIs, UseIP, UseIPv4, UseIPv6")
		}
	}
	if req.CNIPFallback != nil {
		// Empty disables the built-in geoip:cn → Proton catch-all rule.
		updates["cn_ip_fallback"] = strings.TrimSpace(*req.CNIPFallback)
	}

	for key, val := range updates {
		var setting models.Setting
		if err := s.db.Where("key = ?", key).First(&setting).Error; err == nil {
			setting.Value = val
			if err := s.db.Save(&setting).Error; err != nil {
				return nil, NewInternalError("Failed to update setting "+key, err)
			}
		} else {
			if err := s.db.Create(&models.Setting{Key: key, Value: val}).Error; err != nil {
				return nil, NewInternalError("Failed to create setting "+key, err)
			}
		}
	}

	nginxNeedsSync := req.SubNginxEnabled != nil || req.APINginxEnabled != nil ||
		((req.SubDomain != nil || req.SubPath != nil) && models.GetSubNginxEnabled(s.db)) ||
		(req.APIDomain != nil && models.GetAPINginxEnabled(s.db))
	if s.nginxGen != nil && nginxNeedsSync {
		if _, err := syncManagedNginx(s.db, s.nginxGen, true, ""); err != nil {
			applogger.Warn("Failed to sync endpoint Nginx after settings update: %v", err)
		}
	}

	return s.GetSettings()
}

// ApplySubscriptionNginx enables and writes Nginx HTTPS reverse proxy config for sub_domain/sub_path.
func (s *SystemService) ApplySubscriptionNginx() (*dto.SubscriptionNginxResponse, error) {
	subDomain := models.GetSubDomain(s.db)
	if subDomain == "" {
		return nil, NewValidationError("请先填写并保存订阅域名 (sub_domain)")
	}
	subPath := models.GetSubPath(s.db)
	if s.nginxGen == nil {
		return nil, NewInternalError("Nginx generator not configured", nil)
	}

	if err := upsertSettingKV(s.db, "sub_nginx_enabled", "true"); err != nil {
		return nil, err
	}

	info, err := syncManagedNginx(s.db, s.nginxGen, true, "sub")
	if err != nil {
		_ = upsertSettingKV(s.db, "sub_nginx_enabled", "false")
		return nil, err
	}

	return &dto.SubscriptionNginxResponse{
		Enabled:           true,
		Domain:            subDomain,
		SubPath:           subPath,
		ConfigPath:        info.SubConfigPath,
		MatchedCertDomain: info.SubMatchedCert,
		Reloaded:          true,
		Message:           "订阅域名 Nginx 反代配置已生成并生效（仅放行 " + subPath + "/ 路径）",
	}, nil
}

// DisableSubscriptionNginx removes standalone subscription Nginx config and re-syncs remaining configs.
func (s *SystemService) DisableSubscriptionNginx() (*dto.SubscriptionNginxResponse, error) {
	if err := upsertSettingKV(s.db, "sub_nginx_enabled", "false"); err != nil {
		return nil, err
	}
	if s.nginxGen != nil {
		if _, err := syncManagedNginx(s.db, s.nginxGen, true, ""); err != nil {
			return nil, NewSystemCommandError("清理订阅 Nginx 配置失败: "+err.Error(), err)
		}
	}
	return &dto.SubscriptionNginxResponse{
		Enabled:  false,
		Domain:   models.GetSubDomain(s.db),
		SubPath:  models.GetSubPath(s.db),
		Reloaded: true,
		Message:  "已停用订阅 Nginx 反代",
	}, nil
}

// ApplyAPINginx enables and writes Nginx HTTPS reverse proxy config for api_domain -> /api/v1/ (HTTPS/CDN ready).
func (s *SystemService) ApplyAPINginx() (*dto.APINginxResponse, error) {
	apiDomain := models.GetAPIDomain(s.db)
	if apiDomain == "" {
		return nil, NewValidationError("请先填写并保存 API 域名 (api_domain)")
	}
	if s.nginxGen == nil {
		return nil, NewInternalError("Nginx generator not configured", nil)
	}

	if err := upsertSettingKV(s.db, "api_nginx_enabled", "true"); err != nil {
		return nil, err
	}

	info, err := syncManagedNginx(s.db, s.nginxGen, true, "api")
	if err != nil {
		_ = upsertSettingKV(s.db, "api_nginx_enabled", "false")
		return nil, err
	}

	return &dto.APINginxResponse{
		Enabled:           true,
		Domain:            apiDomain,
		DirectURL:         "https://" + apiDomain,
		ConfigPath:        info.APIConfigPath,
		MatchedCertDomain: info.APIMatchedCert,
		Reloaded:          true,
		Message:           "API 域名 Nginx HTTPS 反代已生效（支持直连 HTTPS 与 Cloudflare CDN，SSE 缓冲已关闭）",
	}, nil
}

// DisableAPINginx disables API Nginx reverse proxy and re-syncs remaining managed configs.
func (s *SystemService) DisableAPINginx() (*dto.APINginxResponse, error) {
	if err := upsertSettingKV(s.db, "api_nginx_enabled", "false"); err != nil {
		return nil, err
	}
	if s.nginxGen != nil {
		if _, err := syncManagedNginx(s.db, s.nginxGen, true, ""); err != nil {
			return nil, NewSystemCommandError("清理 API Nginx 配置失败: "+err.Error(), err)
		}
	}
	apiDomain := models.GetAPIDomain(s.db)
	directURL := ""
	if apiDomain != "" {
		directURL = "https://" + apiDomain
	}
	return &dto.APINginxResponse{
		Enabled:   false,
		Domain:    apiDomain,
		DirectURL: directURL,
		Reloaded:  true,
		Message:   "已停用 API Nginx 反代",
	}, nil
}

func upsertSettingKV(db *gorm.DB, key, val string) error {
	var setting models.Setting
	if err := db.Where("key = ?", key).First(&setting).Error; err == nil {
		setting.Value = val
		if err := db.Save(&setting).Error; err != nil {
			return NewInternalError("Failed to update setting "+key, err)
		}
		return nil
	}
	if err := db.Create(&models.Setting{Key: key, Value: val}).Error; err != nil {
		return NewInternalError("Failed to create setting "+key, err)
	}
	return nil
}

type managedNginxSyncInfo struct {
	SubConfigPath  string
	SubMatchedCert string
	APIConfigPath  string
	APIMatchedCert string
}

func syncManagedNginx(db *gorm.DB, nginxGen *nginx.ConfigGenerator, reload bool, strictTarget string) (managedNginxSyncInfo, error) {
	var info managedNginxSyncInfo
	if nginxGen == nil {
		return info, nil
	}

	var inbounds []models.Inbound
	if err := db.Preload("Domain").Where("enabled = ?", true).Find(&inbounds).Error; err != nil {
		return info, NewInternalError("Failed to load inbounds for Nginx sync", err)
	}
	if err := nginxGen.GenerateHTTPConfig(inbounds); err != nil {
		return info, NewSystemCommandError("Failed to generate Nginx HTTP config: "+err.Error(), err)
	}

	standalone := make(map[string]nginx.EndpointProxySpec)
	configDir := nginxGen.ConfigDir()
	if configDir == "" {
		configDir = "/etc/nginx/conf.d"
	}

	resolveStandalone := func(targetKey, domain, label string) (*models.Domain, bool, error) {
		if hasInboundForDomain(inbounds, domain) {
			return nil, true, nil
		}
		certDom, err := findMatchingDomainCert(db, domain)
		if err != nil {
			return nil, false, err
		}
		if certDom == nil {
			msg := "未找到匹配" + label + " " + domain + " 的有效 TLS 证书，请先在「域名证书」上传或申请证书"
			if strictTarget == targetKey {
				return nil, false, NewValidationError(msg)
			}
			applogger.Warn("%s", msg)
			return nil, false, nil
		}
		return certDom, false, nil
	}

	subDomain := models.GetSubDomain(db)
	subPath := models.GetSubPath(db)
	if models.GetSubNginxEnabled(db) && subDomain != "" {
		certDom, shared, err := resolveStandalone("sub", subDomain, "订阅域名")
		if err != nil {
			return info, err
		}
		if shared {
			info.SubMatchedCert = subDomain
			info.SubConfigPath = filepath.Join(configDir, subDomain+".conf")
		} else if certDom != nil {
			info.SubMatchedCert = certDom.Domain
			k := strings.ToLower(subDomain)
			spec := standalone[k]
			spec.Domain = subDomain
			spec.CertPath = certDom.CertPath
			spec.KeyPath = certDom.KeyPath
			spec.SubPath = subPath
			standalone[k] = spec
		}
	}

	apiDomain := models.GetAPIDomain(db)
	if models.GetAPINginxEnabled(db) && apiDomain != "" {
		certDom, shared, err := resolveStandalone("api", apiDomain, "API 域名")
		if err != nil {
			return info, err
		}
		if shared {
			info.APIMatchedCert = apiDomain
			info.APIConfigPath = filepath.Join(configDir, apiDomain+".conf")
		} else if certDom != nil {
			info.APIMatchedCert = certDom.Domain
			k := strings.ToLower(apiDomain)
			spec := standalone[k]
			spec.Domain = apiDomain
			spec.CertPath = certDom.CertPath
			spec.KeyPath = certDom.KeyPath
			spec.ExposeAPI = true
			standalone[k] = spec
		}
	}

	written, err := nginxGen.SyncEndpointProxies(standalone)
	if err != nil {
		return info, NewSystemCommandError("生成端点 Nginx 配置失败: "+err.Error(), err)
	}
	if subDomain != "" {
		if p, ok := written[strings.ToLower(subDomain)]; ok {
			info.SubConfigPath = p
		}
	}
	if apiDomain != "" {
		if p, ok := written[strings.ToLower(apiDomain)]; ok {
			info.APIConfigPath = p
		}
	}

	if err := nginxGen.TestConfig(); err != nil {
		return info, NewSystemCommandError("Nginx 配置校验失败 (nginx -t): "+err.Error(), err)
	}
	if reload {
		if err := nginxGen.Reload(); err != nil {
			applogger.Warn("Failed to reload Nginx: %v", err)
		} else {
			applogger.Info("Nginx reloaded successfully")
		}
	}
	return info, nil
}

func hasInboundForDomain(inbounds []models.Inbound, targetDomain string) bool {
	for _, inb := range inbounds {
		if inb.Domain == nil {
			continue
		}
		effective := inb.Domain.Domain
		if inb.ActualDomain != "" {
			effective = inb.ActualDomain
		}
		if strings.EqualFold(effective, targetDomain) {
			return true
		}
	}
	return false
}

func (s *SystemService) GetXrayStatus() *dto.XrayStatusResponse {
	out, err := exec.Command("systemctl", "is-active", "xray").Output()
	status := strings.TrimSpace(string(out))
	if err != nil && status == "" {
		status = "unknown"
	}
	return &dto.XrayStatusResponse{
		Status: status,
		Active: status == "active",
	}
}

func (s *SystemService) RestartXray() (*dto.XrayRestartResponse, error) {
	if out, err := exec.Command("systemctl", "restart", "xray").CombinedOutput(); err != nil {
		return nil, NewSystemCommandError("Failed to restart Xray: "+strings.TrimSpace(string(out)), err)
	}
	st := s.GetXrayStatus()
	return &dto.XrayRestartResponse{
		Restarted: true,
		Status:    st.Status,
		Active:    st.Active,
	}, nil
}

// GenerateXrayConfig generates pure Server-mode Xray JSON configuration from DB state.
func (s *SystemService) GenerateXrayConfig() (*xray.Config, []byte, error) {
	var users []models.User
	var inbounds []models.Inbound
	var outbounds []models.Outbound
	var rules []models.RoutingRule

	if err := s.db.Where("enabled = ?", true).Find(&users).Error; err != nil {
		return nil, nil, NewInternalError("Failed to load users for Xray config", err)
	}
	if err := s.db.Preload("Domain").Where("enabled = ?", true).Find(&inbounds).Error; err != nil {
		return nil, nil, NewInternalError("Failed to load inbounds for Xray config", err)
	}
	if err := s.db.Where("enabled = ?", true).Find(&outbounds).Error; err != nil {
		return nil, nil, NewInternalError("Failed to load outbounds for Xray config", err)
	}
	if err := s.db.Where("enabled = ?", true).Order("priority ASC").Find(&rules).Error; err != nil {
		return nil, nil, NewInternalError("Failed to load routing rules for Xray config", err)
	}

	apiPort := 10085
	socketDir := "/dev/shm"
	if s.cfg != nil {
		if s.cfg.Xray.APIPort > 0 {
			apiPort = s.cfg.Xray.APIPort
		}
		if s.cfg.Xray.SocketDir != "" {
			socketDir = s.cfg.Xray.SocketDir
		}
	}

	gen := xray.NewGenerator().
		SetUsers(users).
		SetInbounds(inbounds).
		SetOutbounds(outbounds).
		SetRoutingRules(rules).
		SetAPIPort(apiPort).
		SetSocketDir(socketDir).
		SetLogLevel(models.GetXrayLogLevel(s.db)).
		SetEnableTrafficStats(models.GetEnableTrafficStats(s.db)).
		SetEnableSniffing(models.GetEnableSniffing(s.db)).
		SetDirectDomainStrategy(models.GetDirectDomainStrategy(s.db)).
		SetCNIPFallback(models.GetCNIPFallback(s.db))

	cfgObj, err := gen.Generate()
	if err != nil {
		return nil, nil, NewInternalError("Failed to generate Xray config", err)
	}
	rawJSON, err := json.MarshalIndent(cfgObj, "", "  ")
	if err != nil {
		return nil, nil, NewInternalError("Failed to serialize Xray config", err)
	}

	return cfgObj, rawJSON, nil
}

func (s *SystemService) GetXrayConfigPreview() (*dto.XrayConfigResponse, error) {
	_, raw, err := s.GenerateXrayConfig()
	if err != nil {
		return nil, err
	}
	var asMap map[string]interface{}
	if err := json.Unmarshal(raw, &asMap); err != nil {
		return nil, NewInternalError("Failed to decode Xray config JSON", err)
	}
	// 预览先脱敏再返回：config 与 raw 均来自脱敏后的 JSON，见
	// redactXrayConfigForPreview 的规则注释。
	redacted := redactXrayConfigForPreview(asMap)
	redactedRaw, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		return nil, NewInternalError("Failed to serialize redacted Xray config", err)
	}
	currentHash := sha256Hex(raw)
	appliedHash := GetAppliedConfigHash(s.db)
	return &dto.XrayConfigResponse{
		Config:      redacted,
		Raw:         string(redactedRaw),
		CurrentHash: currentHash,
		AppliedHash: appliedHash,
		// applied 为空且 current 非空时也算 dirty（从未成功应用过）。
		Dirty: currentHash != appliedHash,
	}, nil
}

// appliedConfigHashKey 是记录上次成功应用的 Xray 配置哈希的 Setting key。
// 与 models/setting.go 的 GetXrayLogLevel 等 helper 同模式：用 Setting 表存。
const appliedConfigHashKey = "xray_applied_config_hash"

// GetAppliedConfigHash returns the SHA256 of the last successfully applied
// Xray config, or "" if nothing has been applied yet.
func GetAppliedConfigHash(db *gorm.DB) string {
	return models.GetSettingValue(db, appliedConfigHashKey, "")
}

// SetAppliedConfigHash records hash as the last successfully applied config.
// Only call after a full successful apply; failed applies must not update it.
func SetAppliedConfigHash(db *gorm.DB, hash string) error {
	var setting models.Setting
	if err := db.Where("key = ?", appliedConfigHashKey).First(&setting).Error; err == nil {
		setting.Value = hash
		if err := db.Save(&setting).Error; err != nil {
			return NewInternalError("Failed to update setting "+appliedConfigHashKey, err)
		}
		return nil
	}
	if err := db.Create(&models.Setting{
		Key:    appliedConfigHashKey,
		Value:  hash,
		Type:   "string",
		Remark: "SHA256 of last successfully applied Xray config",
	}).Error; err != nil {
		return NewInternalError("Failed to create setting "+appliedConfigHashKey, err)
	}
	return nil
}

// sha256Hex returns the lowercase hex SHA256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// redactXrayConfigForPreview 对生成的 Xray 配置做脱敏，供 GET /xray/config
// 预览返回。脱敏规则：
//
//  1. 递归遍历：key 不区分大小写包含 secret / private / password / passwd /
//     token 时，值一律替换为 "***"（无论值是字符串还是其它类型）。这覆盖
//     WireGuard 的 secretKey、私钥等字段。
//  2. VLESS/Trojan 客户端列表（inbounds[].settings.clients 中的对象）：
//     "id" 字段只保留前 8 个字符，其余用 "****" 代替（如
//     "550e8400****"）；长度不超过 8 个字符的 id 整体替换为 "****"。
//     其余位置的 "id" 不动。
//  3. 其余字段原样返回。
//
// 注意：函数不修改入参，返回一份新的 map；Raw 字段同步用脱敏后的 JSON
// 重新序列化，调用方拿到的 config 与 raw 均不含明文密钥与完整用户 UUID。
func redactXrayConfigForPreview(cfg map[string]interface{}) map[string]interface{} {
	var walk func(v interface{}, inClients bool) interface{}
	walk = func(v interface{}, inClients bool) interface{} {
		switch t := v.(type) {
		case map[string]interface{}:
			out := make(map[string]interface{}, len(t))
			for k, val := range t {
				if isSensitiveConfigKey(k) {
					out[k] = "***"
					continue
				}
				if inClients && strings.EqualFold(k, "id") {
					out[k] = maskClientID(val)
					continue
				}
				// 入站 clients 与出站 vnext[].users[] 里的 id 都是账号凭证，同样掩码。
				childInClients := inClients || strings.EqualFold(k, "clients") || strings.EqualFold(k, "users")
				out[k] = walk(val, childInClients)
			}
			return out
		case []interface{}:
			out := make([]interface{}, len(t))
			for i, e := range t {
				out[i] = walk(e, inClients)
			}
			return out
		default:
			return v
		}
	}
	return walk(cfg, false).(map[string]interface{})
}

// isSensitiveConfigKey reports whether a config key holds a secret value.
func isSensitiveConfigKey(key string) bool {
	lower := strings.ToLower(key)
	for _, sub := range []string{"secret", "private", "password", "passwd", "token"} {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// maskClientID keeps only the first 8 characters of a client id, replacing
// the rest with "****". Non-string or short values become "****".
func maskClientID(v interface{}) interface{} {
	s, ok := v.(string)
	if !ok {
		return "****"
	}
	r := []rune(s)
	if len(r) <= 8 {
		return "****"
	}
	return string(r[:8]) + "****"
}

// ApplyXrayConfig generates the Xray config from DB state and applies it on
// demand: if the generated config is identical to both the on-disk file and
// the last successfully applied config, nothing is written or restarted.
// Otherwise it validates the new config, writes it atomically and restarts
// Xray. There is no hot reload: every real change restarts Xray.
func (s *SystemService) ApplyXrayConfig() (*dto.XrayApplyResponse, error) {
	_, configJSON, err := s.GenerateXrayConfig()
	if err != nil {
		return nil, err
	}

	configPath := "/usr/local/etc/xray/config.json"
	binaryPath := "/usr/local/bin/xray"
	if s.cfg != nil {
		if s.cfg.Xray.ConfigPath != "" {
			configPath = s.cfg.Xray.ConfigPath
		}
		if s.cfg.Xray.BinaryPath != "" {
			binaryPath = s.cfg.Xray.BinaryPath
		}
	}

	currentHash := sha256Hex(configJSON)
	appliedHash := GetAppliedConfigHash(s.db)

	// 脏检查：磁盘内容与上次成功应用的哈希都与当前一致时直接返回，不写盘、
	// 不校验、不重启、不碰 nginx。appliedHash 也要比对：上次应用若在重启
	// 环节失败，磁盘已是新配置但 xray 仍跑着旧配置，此时必须重试重启，
	// 不能直接返回 unchanged。
	if disk, err := os.ReadFile(configPath); err == nil && sha256Hex(disk) == currentHash && appliedHash == currentHash {
		return &dto.XrayApplyResponse{
			Applied:   false,
			Method:    "unchanged",
			ConfigLen: len(configJSON),
			Changed:   false,
			Message:   "配置无变化，未重启",
		}, nil
	}

	testConfigDir := resolveXrayTestConfigDir(s.cfg)
	// 先测后写：测试配置写入独立的 test_config_dir（避免污染正式配置目录 /usr/local/etc/xray），
	// 且以 .json 结尾 + 显式传 -format json；校验通过后再原子更新正式 config.json。
	tmpPath, err := writeTempXrayFile(testConfigDir, "validate-*.json", configJSON, 0644)
	if err != nil {
		return nil, NewSystemCommandError("Failed to prepare temp Xray test config: "+err.Error(), err)
	}
	defer os.Remove(tmpPath)

	cmd := exec.Command(binaryPath, "run", "-test", "-format", "json", "-c", tmpPath)
	if s.cfg != nil && strings.TrimSpace(s.cfg.Xray.AssetsPath) != "" {
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+strings.TrimSpace(s.cfg.Xray.AssetsPath))
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		errMsg := strings.TrimSpace(string(output))
		if len(errMsg) > 500 {
			errMsg = errMsg[:500] + "..."
		}
		return nil, NewXrayValidationError("配置校验失败，服务未重启: "+errMsg, map[string]interface{}{
			"xray_output": errMsg,
		})
	}

	// 校验通过：保留一份 config.json.bak，并在目标目录内通过非 .json 暂存文件原子替换正式 config.json，
	// 避免跨文件系统 rename 失败 (EXDEV) 且不在生产目录留任何多余 .json 文件。
	bakPath := configPath + ".bak"
	if oldData, readErr := os.ReadFile(configPath); readErr == nil {
		if err := writeFileAtomically(bakPath, oldData, 0644); err != nil {
			return nil, NewSystemCommandError("Failed to back up old Xray config: "+err.Error(), err)
		}
	}
	if err := writeFileAtomically(configPath, configJSON, 0644); err != nil {
		return nil, NewSystemCommandError("Failed to write Xray config: "+err.Error(), err)
	}

	if s.nginxGen != nil {
		if _, syncErr := syncManagedNginx(s.db, s.nginxGen, false, ""); syncErr != nil {
			return nil, syncErr
		}
	}

	if err := exec.Command("systemctl", "restart", "xray").Run(); err != nil {
		return nil, NewSystemCommandError("重启 Xray 服务失败，配置已写入但服务仍在运行旧配置: "+err.Error(), err)
	}
	applogger.Info("Xray service restarted successfully")

	var warnings []string
	if s.nginxGen != nil {
		if err := s.nginxGen.Reload(); err != nil {
			warnings = append(warnings, "Nginx reload 失败: "+err.Error())
			applogger.Warn("Failed to reload Nginx: %v", err)
		} else {
			applogger.Info("Nginx reloaded successfully")
		}
	}

	// 只有整条链路成功才记录已应用哈希；失败的应用不更新该哈希。
	if err := SetAppliedConfigHash(s.db, currentHash); err != nil {
		warnings = append(warnings, "已应用哈希记录失败: "+err.Error())
		applogger.Warn("Failed to record applied Xray config hash: %v", err)
	}

	return &dto.XrayApplyResponse{
		Applied:   true,
		Method:    "restart",
		ConfigLen: len(configJSON),
		Changed:   true,
		Warnings:  warnings,
		Message:   "配置已写入文件并重启服务",
	}, nil
}

func (s *SystemService) RestartPanel() *dto.PanelRestartResponse {
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = exec.Command("systemctl", "restart", "xray-panel-server").Start()
	}()
	return &dto.PanelRestartResponse{
		Restarting: true,
		Message:    "Panel restart scheduled",
	}
}

func (s *SystemService) GetLogs(serviceName string, lines int) (*dto.LogsResponse, error) {
	if serviceName == "" {
		serviceName = system.LogSourceXray
	}
	if !system.IsValidLogSource(serviceName) {
		return nil, NewValidationError("不支持的日志服务名，允许值: xray, panel, wireguard, nginx")
	}
	if lines <= 0 {
		lines = 100
	}
	if lines > 1000 {
		lines = 1000
	}

	content, err := system.GetServiceLogs(serviceName, lines)
	if err != nil {
		return nil, NewSystemCommandError("读取日志失败", err)
	}

	return &dto.LogsResponse{
		Service: serviceName,
		Lines:   lines,
		Content: content,
	}, nil
}

func resolveXrayTestConfigDir(cfg *config.Config) string {
	if cfg != nil && strings.TrimSpace(cfg.Xray.TestConfigDir) != "" {
		return strings.TrimSpace(cfg.Xray.TestConfigDir)
	}
	return filepath.Join(os.TempDir(), "xray-panel-test")
}

func writeTempXrayFile(dir, pattern string, data []byte, perm os.FileMode) (string, error) {
	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", err
		}
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	path := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := os.Chmod(path, perm); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func writeFileAtomically(targetPath string, data []byte, perm os.FileMode) error {
	stagePath, err := writeTempXrayFile(filepath.Dir(targetPath), ".stage-*.tmp", data, perm)
	if err != nil {
		return err
	}
	if err := os.Rename(stagePath, targetPath); err != nil {
		_ = os.Remove(stagePath)
		return err
	}
	return nil
}
