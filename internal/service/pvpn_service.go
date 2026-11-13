package service

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"gorm.io/gorm"
	"xray-panel-server/internal/config"
	"xray-panel-server/internal/dto"
	applogger "xray-panel-server/internal/logger"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/proton"
)

// PVPNRunner abstracts system command execution for testability.
type PVPNRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
	LookPath(file string) (string, error)
	FileExists(path string) bool
}

type defaultPVPNRunner struct{}

func (defaultPVPNRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (defaultPVPNRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (defaultPVPNRunner) FileExists(path string) bool {
	return fileExists(path)
}

// PVPNService coordinates Proton VPN guest credentials, wireproxy runtime, and Xray outbound integration.
type PVPNService struct {
	db      *gorm.DB
	cfg     *config.Config
	runner  PVPNRunner
	manager *proton.Manager
}

// NewPVPNService creates a new PVPNService.
func NewPVPNService(db *gorm.DB, cfg *config.Config) *PVPNService {
	dataDir := "/opt/xray-panel/proton"
	binPath := "/usr/local/bin/wireproxy"
	socksHost := "127.0.0.1"
	socksPort := 1080

	if db != nil {
		val := models.GetSettingValue(db, "pvpn_socks_port", "")
		if p, err := strconv.Atoi(val); err == nil && p > 0 {
			socksPort = p
		}
	}

	if cfg != nil {
		if strings.TrimSpace(cfg.PVPN.DataDir) != "" {
			dataDir = strings.TrimSpace(cfg.PVPN.DataDir)
		} else if strings.TrimSpace(cfg.PVPN.InstallDir) != "" {
			dataDir = strings.TrimSpace(cfg.PVPN.InstallDir)
		}
		if strings.TrimSpace(cfg.PVPN.BinaryPath) != "" {
			binPath = strings.TrimSpace(cfg.PVPN.BinaryPath)
		}
		if strings.TrimSpace(cfg.PVPN.SocksHost) != "" {
			socksHost = strings.TrimSpace(cfg.PVPN.SocksHost)
		}
		if socksPort == 1080 && cfg.PVPN.SocksPort > 0 {
			socksPort = cfg.PVPN.SocksPort
		}
	}

	mgrCfg := proton.ManagerConfig{
		DataDir:    dataDir,
		BinaryPath: binPath,
		SocksHost:  socksHost,
		SocksPort:  socksPort,
	}
	mgr := proton.NewManager(mgrCfg, nil)

	return &PVPNService{
		db:      db,
		cfg:     cfg,
		runner:  defaultPVPNRunner{},
		manager: mgr,
	}
}

// SetRunner overrides the command runner for unit tests.
func (s *PVPNService) SetRunner(r PVPNRunner) {
	if r != nil {
		s.runner = r
	}
}

// SetManager overrides the proton manager for unit tests.
func (s *PVPNService) SetManager(m *proton.Manager) {
	if m != nil {
		s.manager = m
	}
}

func (s *PVPNService) getSocksPort() int {
	if s.db != nil {
		val := models.GetSettingValue(s.db, "pvpn_socks_port", "")
		if p, err := strconv.Atoi(val); err == nil && p > 0 {
			return p
		}
	}
	if s.manager != nil {
		return s.manager.GetSocksPort()
	}
	if s.cfg != nil && s.cfg.PVPN.SocksPort > 0 {
		return s.cfg.PVPN.SocksPort
	}
	return 1080
}

// GetStatus queries the wireproxy status and checks Xray outbound availability.
func (s *PVPNService) GetStatus(ctx context.Context) (*dto.PVPNStatusResponse, error) {
	_, err := s.manager.LocateWireproxy()
	installed := err == nil

	running, activeSrv, activeCC, exitIP, certExp := s.manager.Status(ctx)
	svcStatus := "not_installed"
	if installed {
		if running {
			svcStatus = "active"
		} else {
			svcStatus = "inactive"
		}
	}

	srvName := activeSrv
	if srvName == "" {
		srvName = "None"
	}

	loggedIn := false
	sessionPath := ""
	if s.manager != nil {
		loggedIn = s.manager.HasValidSession()
		sessionPath = s.manager.GetSessionPath()
	}

	res := &dto.PVPNStatusResponse{
		Installed:      installed,
		ServiceStatus:  svcStatus,
		Running:        running,
		Server:         srvName,
		Country:        activeCC,
		IP:             exitIP,
		Port:           s.getSocksPort(),
		LoggedIn:       loggedIn,
		AuthMode:       "guest",
		CertExpiresAt:  certExp,
		OutboundExists: false,
		OutboundTag:    "proton",
		APIEndpoint:    "internal://proton-engine",
		SessionPath:    sessionPath,
	}

	// Check if proton outbound exists in DB
	var outbound models.Outbound
	if err := s.db.WithContext(ctx).Where("tag = ?", "proton").First(&outbound).Error; err == nil && outbound.ID != "" {
		res.OutboundExists = true
	} else if err := s.db.WithContext(ctx).Where("type = ? AND port = ?", models.OutboundSOCKS5, s.getSocksPort()).First(&outbound).Error; err == nil && outbound.ID != "" {
		res.OutboundExists = true
		res.OutboundTag = outbound.Tag
	}

	return res, nil
}

// GetCountries returns available Proton VPN exit countries.
func (s *PVPNService) GetCountries(ctx context.Context) (*dto.PVPNCountriesResponse, error) {
	countries, err := s.manager.GetCountries(ctx)
	if err != nil {
		return nil, NewSystemCommandError("获取 Proton 出口国家列表失败: "+err.Error(), err)
	}

	resp := &dto.PVPNCountriesResponse{
		Countries: make([]dto.PVPNCountryDTO, 0, len(countries)),
	}

	for _, c := range countries {
		code := strings.ToUpper(strings.TrimSpace(c.Code))
		resp.Countries = append(resp.Countries, dto.PVPNCountryDTO{
			Code:    code,
			Name:    formatCountryName(code),
			Count:   c.Count,
			AvgLoad: c.AvgLoad,
		})
	}

	return resp, nil
}

// GetServers returns available servers for a specific country.
func (s *PVPNService) GetServers(ctx context.Context, country string) (*dto.PVPNServersResponse, error) {
	country = strings.TrimSpace(country)
	srvs, err := s.manager.GetServers(ctx, country)
	if err != nil {
		return nil, NewSystemCommandError("获取节点列表失败: "+err.Error(), err)
	}

	resp := &dto.PVPNServersResponse{
		Servers: make([]dto.PVPNServerDTO, 0, len(srvs)),
	}

	for _, srv := range srvs {
		resp.Servers = append(resp.Servers, dto.PVPNServerDTO{
			Name:    srv.Name,
			EntryIP: srv.EntryIP,
			ExitIP:  srv.EntryIP,
			Country: srv.Country,
			Tier:    srv.Tier,
			Load:    srv.Load,
			Score:   srv.Score,
			Status:  1,
		})
	}

	return resp, nil
}

// Connect selects and connects to the requested country or server, and ensures the Xray outbound exists.
func (s *PVPNService) Connect(ctx context.Context, req dto.PVPNConnectRequest) (*dto.PVPNConnectResponse, error) {
	country := strings.ToUpper(strings.TrimSpace(req.Country))
	server := strings.TrimSpace(req.Server)
	if country == "" && server == "" {
		country = "US"
	}

	targetServer, err := s.manager.Connect(ctx, country, server)
	if err != nil {
		return nil, NewSystemCommandError("连接 Proton 出口节点失败: "+err.Error(), err)
	}

	// Auto ensure proton outbound in Xray if requested or not yet existing
	outboundTag := "proton"
	if req.EnsureOutbound {
		if _, err := s.EnsureOutbound(ctx); err != nil {
			applogger.Warn("Failed to auto-ensure proton outbound: %v", err)
		}
	}

	return &dto.PVPNConnectResponse{
		Success:     true,
		Server:      targetServer.Name,
		Country:     targetServer.Country,
		OutboundTag: outboundTag,
		Message:     fmt.Sprintf("已成功连接至 %s (出口地区: %s)", targetServer.Name, targetServer.Country),
	}, nil
}

// Disconnect stops the wireproxy process.
func (s *PVPNService) Disconnect(ctx context.Context) (*dto.PVPNActionResponse, error) {
	if err := s.manager.Disconnect(ctx); err != nil {
		return nil, NewSystemCommandError("断开连接失败: "+err.Error(), err)
	}

	return &dto.PVPNActionResponse{
		Success: true,
		Message: "Proton Wireproxy 代理已断开",
	}, nil
}

// ServiceAction controls the wireproxy service (start/stop/restart).
func (s *PVPNService) ServiceAction(ctx context.Context, action string) (*dto.PVPNActionResponse, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	allowed := map[string]bool{"start": true, "stop": true, "restart": true, "status": true}
	if !allowed[action] {
		return nil, NewValidationError("不支持的服务操作: " + action)
	}

	switch action {
	case "start":
		if _, err := s.manager.Connect(ctx, "", ""); err != nil {
			return nil, NewSystemCommandError("启动 Wireproxy 失败: "+err.Error(), err)
		}
	case "stop":
		_ = s.manager.Disconnect(ctx)
	case "restart":
		_ = s.manager.Disconnect(ctx)
		if _, err := s.manager.Connect(ctx, "", ""); err != nil {
			return nil, NewSystemCommandError("重启 Wireproxy 失败: "+err.Error(), err)
		}
	}

	return &dto.PVPNActionResponse{
		Success: true,
		Message: fmt.Sprintf("Wireproxy 服务已执行 %s 操作", action),
	}, nil
}

// EnsureOutbound ensures that Xray has a SOCKS5 outbound pointing to local wireproxy (127.0.0.1:1080).
func (s *PVPNService) EnsureOutbound(ctx context.Context) (*dto.OutboundDTO, error) {
	var existing models.Outbound
	socksPort := s.getSocksPort()

	if err := s.db.WithContext(ctx).Where("tag = ?", "proton").First(&existing).Error; err == nil && existing.ID != "" {
		if existing.Type != models.OutboundSOCKS5 || existing.Port != socksPort || existing.Server != "127.0.0.1" {
			existing.Type = models.OutboundSOCKS5
			existing.Server = "127.0.0.1"
			existing.Port = socksPort
			existing.Enabled = true
			if err := s.db.WithContext(ctx).Save(&existing).Error; err != nil {
				return nil, NewInternalError("更新 proton 出站失败", err)
			}
		}
		dtoObj := toOutboundDTO(existing)
		return &dtoObj, nil
	}

	// Create new proton outbound
	newOutbound := models.Outbound{
		Tag:     "proton",
		Type:    models.OutboundSOCKS5,
		Server:  "127.0.0.1",
		Port:    socksPort,
		Enabled: true,
	}

	if err := s.db.WithContext(ctx).Create(&newOutbound).Error; err != nil {
		return nil, NewInternalError("创建 proton 出站配置失败", err)
	}

	dtoObj := toOutboundDTO(newOutbound)
	return &dtoObj, nil
}

// Install ensures wireproxy executable is downloaded and available on the host.
func (s *PVPNService) Install(ctx context.Context) (*dto.PVPNActionResponse, error) {
	binPath, err := s.manager.EnsureWireproxy(ctx)
	if err != nil {
		return nil, NewSystemCommandError("安装 wireproxy 失败: "+err.Error(), err)
	}

	return &dto.PVPNActionResponse{
		Success: true,
		Message: fmt.Sprintf("wireproxy 二进制已成功部署就绪: %s", binPath),
	}, nil
}

// GetConfig returns current Proton Wireproxy configuration.
func (s *PVPNService) GetConfig(ctx context.Context) (*dto.PVPNConfigResponse, error) {
	port := s.getSocksPort()
	host := "127.0.0.1"
	dataDir := "/opt/xray-panel/proton"
	sessionPath := ""
	if s.manager != nil {
		host = s.manager.GetSocksHost()
		dataDir = s.manager.GetDataDir()
		sessionPath = s.manager.GetSessionPath()
	}

	return &dto.PVPNConfigResponse{
		SocksPort:   port,
		SocksHost:   host,
		DataDir:     dataDir,
		SessionPath: sessionPath,
	}, nil
}

// UpdateConfig updates the Proton WireProxy configuration (such as SOCKS5 port).
func (s *PVPNService) UpdateConfig(ctx context.Context, req dto.PVPNConfigRequest) (*dto.PVPNConfigResponse, error) {
	if req.SocksPort <= 0 || req.SocksPort > 65535 {
		return nil, NewValidationError("端口号必须在 1 到 65535 之间")
	}

	// 1. Update setting in database
	if s.db != nil {
		var setting models.Setting
		if err := s.db.WithContext(ctx).Where("key = ?", "pvpn_socks_port").First(&setting).Error; err != nil {
			setting = models.Setting{
				Key:    "pvpn_socks_port",
				Value:  strconv.Itoa(req.SocksPort),
				Type:   "int",
				Remark: "Proton Wireproxy SOCKS5 listen port",
			}
			if err := s.db.WithContext(ctx).Create(&setting).Error; err != nil {
				return nil, NewInternalError("保存端口配置失败", err)
			}
		} else {
			setting.Value = strconv.Itoa(req.SocksPort)
			if err := s.db.WithContext(ctx).Save(&setting).Error; err != nil {
				return nil, NewInternalError("更新端口配置失败", err)
			}
		}
	}

	// 2. Update manager & hot reload wireproxy if running
	if s.manager != nil {
		if err := s.manager.SetSocksPort(ctx, req.SocksPort); err != nil {
			return nil, NewSystemCommandError("更新 WireProxy 端口失败: "+err.Error(), err)
		}
	}

	// 3. Update outbound in DB if tag=proton exists
	if s.db != nil {
		var outbound models.Outbound
		if err := s.db.WithContext(ctx).Where("tag = ?", "proton").First(&outbound).Error; err == nil && outbound.ID != "" {
			outbound.Port = req.SocksPort
			_ = s.db.WithContext(ctx).Save(&outbound)
		}
	}

	res, err := s.GetConfig(ctx)
	if err != nil {
		return nil, err
	}
	res.Message = fmt.Sprintf("已成功更新 Proton SOCKS5 端口为 %d", req.SocksPort)
	return res, nil
}

// Login triggers an explicit fresh guest login, fetches a 24h certificate, and refreshes nodes.
func (s *PVPNService) Login(ctx context.Context) (*dto.PVPNLoginResponse, error) {
	if s.manager == nil {
		return nil, NewInternalError("Proton 引擎未就绪", nil)
	}

	sess, err := s.manager.ForceLoginGuest(ctx)
	if err != nil {
		return nil, NewSystemCommandError("Proton 访客登录失败: "+err.Error(), err)
	}

	return &dto.PVPNLoginResponse{
		Success:       true,
		Message:       "已成功获取最新 Proton 访客凭据与 24 小时 WireGuard 证书",
		CertExpiresAt: sess.CertExpiresAt,
		AuthMode:      sess.AuthMode,
		SessionPath:   s.manager.GetSessionPath(),
	}, nil
}

func formatCountryName(code string) string {
	names := map[string]string{
		"US": "美国 (United States)",
		"NL": "荷兰 (Netherlands)",
		"JP": "日本 (Japan)",
		"CH": "瑞士 (Switzerland)",
		"DE": "德国 (Germany)",
		"GB": "英国 (United Kingdom)",
		"SG": "新加坡 (Singapore)",
		"CA": "加拿大 (Canada)",
		"FR": "法国 (France)",
		"AU": "澳大利亚 (Australia)",
		"HK": "中国香港 (Hong Kong)",
		"TW": "中国台湾 (Taiwan)",
		"KR": "韩国 (South Korea)",
		"SE": "瑞典 (Sweden)",
		"NO": "挪威 (Norway)",
		"IS": "冰岛 (Iceland)",
		"RO": "罗马尼亚 (Romania)",
		"ES": "西班牙 (Spain)",
		"IT": "意大利 (Italy)",
		"PL": "波兰 (Poland)",
		"BR": "巴西 (Brazil)",
		"IN": "印度 (India)",
	}
	if name, ok := names[code]; ok {
		return name
	}
	return code
}
