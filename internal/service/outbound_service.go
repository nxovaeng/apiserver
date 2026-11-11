package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"xray-panel-server/internal/config"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/utils"
	"xray-panel-server/internal/xray"
)

// OutboundService manages Xray outbounds, share-link import, WireGuard parsing, and dial tests.
type OutboundService struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewOutboundService(db *gorm.DB, cfg *config.Config) *OutboundService {
	return &OutboundService{db: db, cfg: cfg}
}

func (s *OutboundService) List() (*dto.OutboundListResponse, error) {
	var outbounds []models.Outbound
	if err := s.db.Order("priority DESC, created_at DESC").Find(&outbounds).Error; err != nil {
		return nil, NewInternalError("Failed to fetch outbounds", err)
	}
	dtos := make([]dto.OutboundDTO, len(outbounds))
	for i, o := range outbounds {
		dtos[i] = toOutboundDTO(o)
	}
	return &dto.OutboundListResponse{Outbounds: dtos, Total: len(dtos)}, nil
}

func (s *OutboundService) Get(id string) (*dto.OutboundDTO, error) {
	var outbound models.Outbound
	if err := s.db.First(&outbound, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Outbound not found")
	}
	dto := toOutboundDTO(outbound)
	return &dto, nil
}

func (s *OutboundService) Create(req dto.UpsertOutboundRequest) (*dto.OutboundDTO, error) {
	otype := models.OutboundType(strings.TrimSpace(req.Type))
	if !isValidOutboundType(otype) {
		return nil, NewValidationError("不支持的出站类型")
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	outbound := models.Outbound{
		Tag:            strings.TrimSpace(req.Tag),
		Type:           otype,
		Server:         strings.TrimSpace(req.Server),
		Port:           req.Port,
		Username:       strings.TrimSpace(req.Username),
		Password:       req.Password,
		WGSecretKey:    strings.TrimSpace(req.WGSecretKey),
		WGClientPubKey: strings.TrimSpace(req.WGClientPubKey),
		WGPublicKey:    strings.TrimSpace(req.WGPublicKey),
		WGReserved:     strings.TrimSpace(req.WGReserved),
		WGLocalIPv4:    strings.TrimSpace(req.WGLocalIPv4),
		WGLocalIPv6:    strings.TrimSpace(req.WGLocalIPv6),
		WGMTU:          req.WGMTU,
		WGDNS:          strings.TrimSpace(req.WGDNS),
		TrojanPassword: req.TrojanPassword,
		TrojanSNI:      strings.TrimSpace(req.TrojanSNI),
		TrojanNetwork:  strings.TrimSpace(req.TrojanNetwork),
		UUID:           strings.TrimSpace(req.UUID),
		Flow:           strings.TrimSpace(req.Flow),
		Security:       strings.TrimSpace(req.Security),
		Network:        strings.TrimSpace(req.Network),
		HeaderType:     strings.TrimSpace(req.HeaderType),
		RequestHost:    strings.TrimSpace(req.RequestHost),
		Path:           strings.TrimSpace(req.Path),
		ServiceName:    strings.TrimSpace(req.ServiceName),
		TLS:            req.TLS,
		TLSServerName:  strings.TrimSpace(req.TLSServerName),
		TLSALPN:        strings.TrimSpace(req.TLSALPN),
		Reality:        req.Reality,
		RealityPubKey:  strings.TrimSpace(req.RealityPubKey),
		RealityShortID: strings.TrimSpace(req.RealityShortID),
		RealitySNI:     strings.TrimSpace(req.RealitySNI),
		Enabled:        enabled,
		Priority:       req.Priority,
		Remark:         strings.TrimSpace(req.Remark),
	}

	if otype == models.OutboundWireGuard && outbound.WGClientPubKey == "" && outbound.WGSecretKey != "" {
		if pub, err := utils.DeriveWGPublicKey(outbound.WGSecretKey); err == nil {
			outbound.WGClientPubKey = pub
		}
	}

	if err := s.db.Create(&outbound).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, NewConflictError("出站标签已存在")
		}
		return nil, NewInternalError("创建出站失败", err)
	}

	dto := toOutboundDTO(outbound)
	return &dto, nil
}

func (s *OutboundService) Update(id string, req dto.UpsertOutboundRequest) (*dto.OutboundDTO, error) {
	var existing models.Outbound
	if err := s.db.First(&existing, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Outbound not found")
	}

	otype := models.OutboundType(strings.TrimSpace(req.Type))
	if !isValidOutboundType(otype) {
		return nil, NewValidationError("不支持的出站类型")
	}

	if tag := strings.TrimSpace(req.Tag); tag != "" {
		existing.Tag = tag
	}
	existing.Type = otype
	existing.Server = strings.TrimSpace(req.Server)
	existing.Port = req.Port
	existing.Username = strings.TrimSpace(req.Username)
	if req.Password != "" {
		existing.Password = req.Password
	}

	if sk := strings.TrimSpace(req.WGSecretKey); sk != "" {
		existing.WGSecretKey = sk
		if cpk := strings.TrimSpace(req.WGClientPubKey); cpk != "" {
			existing.WGClientPubKey = cpk
		} else if pub, err := utils.DeriveWGPublicKey(sk); err == nil {
			existing.WGClientPubKey = pub
		}
	} else if cpk := strings.TrimSpace(req.WGClientPubKey); cpk != "" {
		existing.WGClientPubKey = cpk
	}

	existing.WGPublicKey = strings.TrimSpace(req.WGPublicKey)
	existing.WGReserved = strings.TrimSpace(req.WGReserved)
	existing.WGLocalIPv4 = strings.TrimSpace(req.WGLocalIPv4)
	existing.WGLocalIPv6 = strings.TrimSpace(req.WGLocalIPv6)
	existing.WGMTU = req.WGMTU
	existing.WGDNS = strings.TrimSpace(req.WGDNS)

	if req.TrojanPassword != "" {
		existing.TrojanPassword = req.TrojanPassword
	}
	existing.TrojanSNI = strings.TrimSpace(req.TrojanSNI)
	existing.TrojanNetwork = strings.TrimSpace(req.TrojanNetwork)

	existing.UUID = strings.TrimSpace(req.UUID)
	existing.Flow = strings.TrimSpace(req.Flow)
	existing.Security = strings.TrimSpace(req.Security)
	existing.Network = strings.TrimSpace(req.Network)
	existing.HeaderType = strings.TrimSpace(req.HeaderType)
	existing.RequestHost = strings.TrimSpace(req.RequestHost)
	existing.Path = strings.TrimSpace(req.Path)
	existing.ServiceName = strings.TrimSpace(req.ServiceName)
	existing.TLS = req.TLS
	existing.TLSServerName = strings.TrimSpace(req.TLSServerName)
	existing.TLSALPN = strings.TrimSpace(req.TLSALPN)
	existing.Reality = req.Reality
	existing.RealityPubKey = strings.TrimSpace(req.RealityPubKey)
	existing.RealityShortID = strings.TrimSpace(req.RealityShortID)
	existing.RealitySNI = strings.TrimSpace(req.RealitySNI)
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	existing.Priority = req.Priority
	existing.Remark = strings.TrimSpace(req.Remark)

	if err := s.db.Save(&existing).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, NewConflictError("出站标签已存在")
		}
		return nil, NewInternalError("更新出站失败", err)
	}

	dto := toOutboundDTO(existing)
	return &dto, nil
}

func (s *OutboundService) Delete(id string) (*dto.DeleteResponse, error) {
	result := s.db.Delete(&models.Outbound{}, "id = ?", id)
	if result.Error != nil {
		return nil, NewInternalError("Failed to delete outbound", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, NewNotFoundError("Outbound not found")
	}
	return &dto.DeleteResponse{ID: id, Deleted: true}, nil
}

func (s *OutboundService) Toggle(id string) (*dto.OutboundDTO, error) {
	var outbound models.Outbound
	if err := s.db.First(&outbound, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Outbound not found")
	}
	outbound.Enabled = !outbound.Enabled
	if err := s.db.Save(&outbound).Error; err != nil {
		return nil, NewInternalError("Failed to toggle outbound", err)
	}
	dto := toOutboundDTO(outbound)
	return &dto, nil
}

func (s *OutboundService) ImportShareLink(link string) (*dto.OutboundDTO, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return nil, NewValidationError("分享链接不能为空")
	}
	outbound, err := utils.ParseShareLink(link)
	if err != nil {
		return nil, NewValidationError("解析分享链接失败: " + err.Error())
	}

	// Disambiguate tag if already present so multiple nodes on same server can be imported cleanly
	var count int64
	s.db.Model(&models.Outbound{}).Where("tag = ?", outbound.Tag).Count(&count)
	if count > 0 {
		outbound.Tag = outbound.Tag + "-" + randomHex(2)
	}

	if err := s.db.Create(outbound).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, NewConflictError("出站标签已存在")
		}
		return nil, NewInternalError("保存导入的出站失败", err)
	}

	dto := toOutboundDTO(*outbound)
	return &dto, nil
}

func (s *OutboundService) ParseWireGuardConfig(configText string) (*dto.ParsedWireGuardConfig, error) {
	if strings.TrimSpace(configText) == "" {
		return nil, NewValidationError("WireGuard 配置内容不能为空")
	}

	parsed := parseWireGuardINI(configText)
	res := &dto.ParsedWireGuardConfig{
		PrivateKey: parsed["Interface_PrivateKey"],
		Address:    parsed["Interface_Address"],
		DNS:        parsed["Interface_DNS"],
		PublicKey:  parsed["Peer_PublicKey"],
		Endpoint:   parsed["Peer_Endpoint"],
		MTU:        1420,
	}

	if res.PrivateKey != "" {
		if pub, err := utils.DeriveWGPublicKey(res.PrivateKey); err == nil {
			res.ClientPublicKey = pub
		}
	}

	if mtuStr := parsed["Interface_MTU"]; mtuStr != "" {
		if m, err := strconv.Atoi(mtuStr); err == nil && m > 0 {
			res.MTU = m
		}
	}

	if endpoint := res.Endpoint; endpoint != "" {
		if strings.HasPrefix(endpoint, "[") {
			if idx := strings.LastIndex(endpoint, "]:"); idx != -1 {
				res.Server = endpoint[1:idx]
				res.Port, _ = strconv.Atoi(endpoint[idx+2:])
			}
		} else if idx := strings.LastIndex(endpoint, ":"); idx != -1 {
			res.Server = endpoint[:idx]
			res.Port, _ = strconv.Atoi(endpoint[idx+1:])
		}
	}

	if res.Address != "" {
		for _, addr := range strings.Split(res.Address, ",") {
			addr = strings.TrimSpace(addr)
			if strings.Contains(addr, ":") {
				res.LocalIPv6 = addr
			} else if addr != "" {
				res.LocalIPv4 = addr
			}
		}
	}

	return res, nil
}

func (s *OutboundService) GenerateWGKeys() (*dto.WGKeyPair, error) {
	priv, pub, err := utils.GenerateWGKeyPair()
	if err != nil {
		return nil, NewInternalError("生成 WireGuard 密钥失败", err)
	}
	return &dto.WGKeyPair{PrivateKey: priv, PublicKey: pub}, nil
}

// Test executes a real dial test by spawning an ephemeral Xray process.
func (s *OutboundService) Test(id string) (*dto.OutboundTestResult, error) {
	var outbound models.Outbound
	if err := s.db.First(&outbound, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Outbound not found")
	}

	res := s.testOutboundViaXray(outbound)
	return &res, nil
}

func (s *OutboundService) testOutboundViaXray(outbound models.Outbound) dto.OutboundTestResult {
	endpoint := outbound.Server
	if outbound.Port > 0 {
		endpoint = fmt.Sprintf("%s:%d", outbound.Server, outbound.Port)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return dto.OutboundTestResult{Success: false, Message: "Failed to allocate local port: " + err.Error(), Endpoint: endpoint}
	}
	proxyPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	outbound.Enabled = true
	gen := xray.NewGenerator()
	gen.SetOutbounds([]models.Outbound{outbound})
	gen.SetDirectDomainStrategy(models.GetDirectDomainStrategy(s.db))

	configJSON, err := gen.GenerateTestJSON(proxyPort)
	if err != nil {
		return dto.OutboundTestResult{Success: false, Message: "Config build failed: " + err.Error(), Endpoint: endpoint}
	}

	tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("xray_test_%s.json", outbound.ID))
	if err := os.WriteFile(tempPath, configJSON, 0600); err != nil {
		return dto.OutboundTestResult{Success: false, Message: "Write temp file failed: " + err.Error(), Endpoint: endpoint}
	}
	defer os.Remove(tempPath)

	binaryPath := "/usr/local/bin/xray"
	if s.cfg != nil && s.cfg.Xray.BinaryPath != "" {
		binaryPath = s.cfg.Xray.BinaryPath
	}
	cmd := exec.Command(binaryPath, "run", "-c", tempPath)
	if err := cmd.Start(); err != nil {
		return dto.OutboundTestResult{Success: false, Message: "Start Xray failed: " + err.Error(), Endpoint: endpoint}
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	time.Sleep(1000 * time.Millisecond)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get("http://ip-api.com/json?fields=status,message,country,isp,query")
	latency := time.Since(start).Milliseconds()

	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "deadline exceeded") || strings.Contains(errMsg, "timeout") {
			errMsg = "连接超时，请检查节点配置或服务器网络"
		} else if strings.Contains(errMsg, "connection refused") {
			errMsg = "本地代理端口连接被拒绝"
		}
		return dto.OutboundTestResult{Success: false, Message: "测试失败: " + errMsg, Endpoint: endpoint, LatencyMs: latency}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var ipInfo struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Country string `json:"country"`
			ISP     string `json:"isp"`
			Query   string `json:"query"`
		}
		if body, readErr := io.ReadAll(resp.Body); readErr == nil {
			_ = json.Unmarshal(body, &ipInfo)
		}

		location := ipInfo.Country
		if ipInfo.ISP != "" {
			location += " (" + ipInfo.ISP + ")"
		}
		if ipInfo.Status == "fail" {
			return dto.OutboundTestResult{
				Success:   true,
				Message:   "连接成功，但无法获取 IP 信息 (Rate limited)",
				LatencyMs: latency,
				Endpoint:  endpoint,
			}
		}
		return dto.OutboundTestResult{
			Success:    true,
			Message:    "连接成功",
			LatencyMs:  latency,
			Endpoint:   endpoint,
			OutboundIP: ipInfo.Query,
			Location:   location,
		}
	}

	return dto.OutboundTestResult{
		Success:   false,
		Message:   fmt.Sprintf("Unexpected HTTP status: %d", resp.StatusCode),
		LatencyMs: latency,
		Endpoint:  endpoint,
	}
}

func parseWireGuardINI(config string) map[string]string {
	result := make(map[string]string)
	currentSection := ""
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if currentSection != "" {
				key = currentSection + "_" + key
			}
			result[key] = value
		}
	}
	return result
}

func isValidOutboundType(t models.OutboundType) bool {
	switch t {
	case models.OutboundDirect, models.OutboundSOCKS5, models.OutboundWireGuard,
		models.OutboundTrojan, models.OutboundBlackhole, models.OutboundVLESS, models.OutboundVMess:
		return true
	default:
		return false
	}
}

func toOutboundDTO(o models.Outbound) dto.OutboundDTO {
	return dto.OutboundDTO{
		ID:                o.ID,
		Tag:               o.Tag,
		Type:              string(o.Type),
		Server:            o.Server,
		Port:              o.Port,
		Username:          o.Username,
		HasPassword:       o.Password != "",
		HasWGSecretKey:    o.WGSecretKey != "",
		WGClientPubKey:    o.WGClientPubKey,
		WGPublicKey:       o.WGPublicKey,
		WGReserved:        o.WGReserved,
		WGLocalIPv4:       o.WGLocalIPv4,
		WGLocalIPv6:       o.WGLocalIPv6,
		WGMTU:             o.WGMTU,
		WGDNS:             o.WGDNS,
		HasTrojanPassword: o.TrojanPassword != "",
		TrojanSNI:         o.TrojanSNI,
		TrojanNetwork:     o.TrojanNetwork,
		UUID:              o.UUID,
		Flow:              o.Flow,
		Security:          o.Security,
		Network:           o.Network,
		HeaderType:        o.HeaderType,
		RequestHost:       o.RequestHost,
		Path:              o.Path,
		ServiceName:       o.ServiceName,
		TLS:               o.TLS,
		TLSServerName:     o.TLSServerName,
		TLSALPN:           o.TLSALPN,
		Reality:           o.Reality,
		RealityPubKey:     o.RealityPubKey,
		RealityShortID:    o.RealityShortID,
		RealitySNI:        o.RealitySNI,
		Enabled:           o.Enabled,
		Priority:          o.Priority,
		Remark:            o.Remark,
		CreatedAt:         o.CreatedAt,
		UpdatedAt:         o.UpdatedAt,
	}
}
