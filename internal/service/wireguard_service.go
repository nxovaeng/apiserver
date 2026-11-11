package service

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"xray-panel-server/internal/dto"
	applogger "xray-panel-server/internal/logger"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/wireguard"
)

// WireGuardService manages kernel WireGuard server and peer lifecycles.
type WireGuardService struct {
	db  *gorm.DB
	mgr *wireguard.Manager
}

func NewWireGuardService(db *gorm.DB) *WireGuardService {
	return &WireGuardService{
		db:  db,
		mgr: wireguard.NewManager(db),
	}
}

func NewWireGuardServiceWithManager(db *gorm.DB, mgr *wireguard.Manager) *WireGuardService {
	return &WireGuardService{db: db, mgr: mgr}
}

func (s *WireGuardService) GetStatus() (*dto.WGServiceStatus, error) {
	st, err := s.mgr.GetStatus()
	if err != nil {
		return nil, NewInternalError("Failed to get WireGuard status", err)
	}
	res := toWGStatusDTO(st)
	return &res, nil
}

func (s *WireGuardService) SetupEnv() (*dto.WGSetupEnvResponse, error) {
	msg, err := wireguard.SetupEnvironment()
	if err != nil {
		return nil, NewSystemCommandError("环境初始化失败: "+err.Error()+"\n"+msg, err)
	}
	return &dto.WGSetupEnvResponse{Success: true, Message: msg}, nil
}

func (s *WireGuardService) ServiceAction(action string) (*dto.WGServiceActionResponse, error) {
	switch action {
	case "start", "stop", "restart", "enable", "disable":
	default:
		return nil, NewValidationError("不支持的服务操作，允许值: start, stop, restart, enable, disable")
	}

	if err := s.mgr.ServiceAction(action); err != nil {
		return nil, NewSystemCommandError("Service action failed: "+err.Error(), err)
	}

	st, err := s.mgr.GetStatus()
	if err != nil {
		return nil, NewInternalError("Failed to refresh WireGuard status", err)
	}

	return &dto.WGServiceActionResponse{
		Action:  action,
		Success: true,
		Status:  toWGStatusDTO(st),
	}, nil
}

func (s *WireGuardService) GetServerConfig() (*dto.WGServerConfigDTO, error) {
	cfg, err := models.GetWGServerConfig(s.db)
	if err != nil {
		return nil, NewInternalError("Failed to load WireGuard server config", err)
	}
	dto := toWGServerDTO(cfg)
	return &dto, nil
}

func (s *WireGuardService) UpdateServerConfig(req dto.UpdateWGServerRequest) (*dto.WGServerConfigDTO, error) {
	serverCfg, err := models.GetWGServerConfig(s.db)
	if err != nil {
		return nil, NewInternalError("Failed to load WireGuard server config", err)
	}

	oldPort := serverCfg.ListenPort
	oldEnableNAT := serverCfg.EnableNAT

	if req.ListenPort != 0 {
		if req.ListenPort < 1024 || req.ListenPort > 65535 {
			return nil, NewValidationError("端口范围必须在 1024 - 65535 之间")
		}
		if conflict, tag := wireguard.CheckPortConflict(s.db, req.ListenPort); conflict {
			return nil, NewConflictError(fmt.Sprintf("端口 %d 与 Xray 入站 [%s] 冲突，请更换端口或先停用该入站", req.ListenPort, tag))
		}
		serverCfg.ListenPort = req.ListenPort
	}

	if iface := strings.TrimSpace(req.InterfaceName); iface != "" {
		serverCfg.InterfaceName = iface
	}
	if addr := strings.TrimSpace(req.Address); addr != "" {
		serverCfg.Address = addr
	}
	if req.MTU > 0 {
		if req.MTU < 576 || req.MTU > 1500 {
			return nil, NewValidationError("MTU 范围必须在 576 - 1500 之间")
		}
		serverCfg.MTU = req.MTU
	}

	if privKey := strings.TrimSpace(req.PrivateKey); privKey != "" {
		pubKey, err := models.DeriveWGPublicKey(privKey)
		if err != nil {
			return nil, NewValidationError("服务端私钥无效: " + err.Error())
		}
		serverCfg.PrivateKey = privKey
		serverCfg.PublicKey = pubKey
	}

	if req.EnableNAT != nil {
		serverCfg.EnableNAT = *req.EnableNAT
	}
	if postUp := strings.TrimSpace(req.PostUp); postUp != "" {
		serverCfg.PostUp = postUp
	} else if serverCfg.EnableNAT && serverCfg.PostUp == "" {
		serverCfg.PostUp = models.DefaultPostUp("%i")
	}
	if postDown := strings.TrimSpace(req.PostDown); postDown != "" {
		serverCfg.PostDown = postDown
	} else if serverCfg.EnableNAT && serverCfg.PostDown == "" {
		serverCfg.PostDown = models.DefaultPostDown("%i")
	}
	if req.Enabled != nil {
		serverCfg.Enabled = *req.Enabled
	}

	serverCfg.UpdatedAt = time.Now()
	if err := s.db.Save(serverCfg).Error; err != nil {
		return nil, NewInternalError("保存服务端配置失败", err)
	}

	needRestart := (oldPort != serverCfg.ListenPort) || (oldEnableNAT != serverCfg.EnableNAT)
	if err := s.mgr.SyncConfig(needRestart); err != nil {
		applogger.Warn("WireGuard config sync failed: %v", err)
	}

	dto := toWGServerDTO(serverCfg)
	return &dto, nil
}

func (s *WireGuardService) ListPeers() (*dto.WGPeerListResponse, error) {
	serverCfg, err := models.GetWGServerConfig(s.db)
	if err != nil {
		return nil, NewInternalError("Failed to load WireGuard server config", err)
	}

	var peers []models.WGPeer
	if err := s.db.Order("id ASC").Find(&peers).Error; err != nil {
		return nil, NewInternalError("Failed to load WireGuard peers", err)
	}

	stats, _ := s.mgr.GetPeerRuntimeStats()
	dtos := make([]dto.WGPeerDTO, len(peers))
	for i, p := range peers {
		dtos[i] = toWGPeerDTO(p, stats)
	}

	return &dto.WGPeerListResponse{
		Peers:           dtos,
		NextAvailableIP: models.GetNextAvailableIP(s.db, serverCfg.Address),
		Total:           len(dtos),
	}, nil
}

func (s *WireGuardService) GetPeer(id uint) (*dto.WGPeerDTO, error) {
	var peer models.WGPeer
	if err := s.db.First(&peer, id).Error; err != nil {
		return nil, NewNotFoundError("WireGuard peer not found")
	}
	stats, _ := s.mgr.GetPeerRuntimeStats()
	dto := toWGPeerDTO(peer, stats)
	return &dto, nil
}

func (s *WireGuardService) CreatePeer(req dto.UpsertWGPeerRequest) (*dto.WGPeerDTO, error) {
	serverCfg, err := models.GetWGServerConfig(s.db)
	if err != nil {
		return nil, NewInternalError("Failed to load server config", err)
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, NewValidationError("客户端名称不能为空")
	}

	pubKey := strings.TrimSpace(req.PublicKey)
	privKey := strings.TrimSpace(req.PrivateKey)
	if pubKey == "" && privKey != "" {
		derived, err := models.DeriveWGPublicKey(privKey)
		if err != nil {
			return nil, NewValidationError("客户端私钥格式无效: " + err.Error())
		}
		pubKey = derived
	}
	if pubKey == "" {
		return nil, NewValidationError("客户端公钥不能为空")
	}

	allowedIPs := strings.TrimSpace(req.AllowedIPs)
	if allowedIPs == "" {
		allowedIPs = models.GetNextAvailableIP(s.db, serverCfg.Address)
	}

	keepalive := req.PersistentKeepalive
	if keepalive <= 0 {
		keepalive = 25
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	peer := models.WGPeer{
		Name:                name,
		PublicKey:           pubKey,
		PrivateKey:          privKey,
		PresharedKey:        strings.TrimSpace(req.PresharedKey),
		AllowedIPs:          allowedIPs,
		Endpoint:            strings.TrimSpace(req.Endpoint),
		PersistentKeepalive: keepalive,
		Enabled:             enabled,
	}

	if err := s.db.Create(&peer).Error; err != nil {
		return nil, NewInternalError("创建客户端失败", err)
	}

	if err := s.mgr.SyncConfig(false); err != nil {
		applogger.Warn("WireGuard config sync failed: %v", err)
	}

	stats, _ := s.mgr.GetPeerRuntimeStats()
	dto := toWGPeerDTO(peer, stats)
	return &dto, nil
}

func (s *WireGuardService) UpdatePeer(id uint, req dto.UpsertWGPeerRequest) (*dto.WGPeerDTO, error) {
	var peer models.WGPeer
	if err := s.db.First(&peer, id).Error; err != nil {
		return nil, NewNotFoundError("WireGuard peer not found")
	}

	if name := strings.TrimSpace(req.Name); name != "" {
		peer.Name = name
	}

	pubKey := strings.TrimSpace(req.PublicKey)
	privKey := strings.TrimSpace(req.PrivateKey)
	if pubKey == "" && privKey != "" {
		derived, err := models.DeriveWGPublicKey(privKey)
		if err != nil {
			return nil, NewValidationError("客户端私钥格式无效: " + err.Error())
		}
		pubKey = derived
	}
	if pubKey != "" {
		peer.PublicKey = pubKey
	}
	if privKey != "" {
		peer.PrivateKey = privKey
	}
	if psk := strings.TrimSpace(req.PresharedKey); psk != "" {
		peer.PresharedKey = psk
	}
	if allowedIPs := strings.TrimSpace(req.AllowedIPs); allowedIPs != "" {
		peer.AllowedIPs = allowedIPs
	}
	peer.Endpoint = strings.TrimSpace(req.Endpoint)
	if req.PersistentKeepalive > 0 {
		peer.PersistentKeepalive = req.PersistentKeepalive
	}
	if req.Enabled != nil {
		peer.Enabled = *req.Enabled
	}

	if err := s.db.Save(&peer).Error; err != nil {
		return nil, NewInternalError("更新客户端失败", err)
	}

	if err := s.mgr.SyncConfig(false); err != nil {
		applogger.Warn("WireGuard config sync failed: %v", err)
	}

	stats, _ := s.mgr.GetPeerRuntimeStats()
	dto := toWGPeerDTO(peer, stats)
	return &dto, nil
}

func (s *WireGuardService) DeletePeer(id uint) (*dto.DeleteResponse, error) {
	result := s.db.Delete(&models.WGPeer{}, id)
	if result.Error != nil {
		return nil, NewInternalError("删除客户端失败", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, NewNotFoundError("WireGuard peer not found")
	}

	if err := s.mgr.SyncConfig(false); err != nil {
		applogger.Warn("WireGuard config sync failed: %v", err)
	}

	return &dto.DeleteResponse{ID: fmt.Sprintf("%d", id), Deleted: true}, nil
}

func (s *WireGuardService) TogglePeer(id uint) (*dto.WGPeerDTO, error) {
	var peer models.WGPeer
	if err := s.db.First(&peer, id).Error; err != nil {
		return nil, NewNotFoundError("WireGuard peer not found")
	}
	peer.Enabled = !peer.Enabled
	if err := s.db.Save(&peer).Error; err != nil {
		return nil, NewInternalError("更新状态失败", err)
	}
	if err := s.mgr.SyncConfig(false); err != nil {
		applogger.Warn("WireGuard config sync failed: %v", err)
	}
	stats, _ := s.mgr.GetPeerRuntimeStats()
	dto := toWGPeerDTO(peer, stats)
	return &dto, nil
}

func (s *WireGuardService) ExportPeerConfig(id uint) (*dto.WGPeerExportConfigResponse, error) {
	var peer models.WGPeer
	if err := s.db.First(&peer, id).Error; err != nil {
		return nil, NewNotFoundError("WireGuard peer not found")
	}

	serverCfg, err := models.GetWGServerConfig(s.db)
	if err != nil {
		return nil, NewInternalError("Failed to load server config", err)
	}

	serverHost := resolvePublicHost(s.db)
	if serverHost == "" {
		serverHost = "<SERVER_IP>"
	}

	wgConf := s.mgr.GenerateClientWGConfig(serverCfg, &peer, serverHost)
	xrayJSON, err := s.mgr.GenerateClientXrayJSON(serverCfg, &peer, serverHost)
	if err != nil {
		return nil, NewInternalError("Failed to generate Xray WireGuard JSON", err)
	}

	return &dto.WGPeerExportConfigResponse{
		PeerID:        peer.ID,
		PeerName:      peer.Name,
		ServerHost:    serverHost,
		Endpoint:      fmt.Sprintf("%s:%d", serverHost, serverCfg.ListenPort),
		WGConf:        wgConf,
		XrayJSON:      xrayJSON,
		HasPrivateKey: peer.PrivateKey != "",
	}, nil
}

func (s *WireGuardService) GenerateKeys() (*dto.WGKeyPair, error) {
	priv, pub, err := models.GenerateWGKeyPair()
	if err != nil {
		return nil, NewInternalError("生成 WireGuard 密钥失败", err)
	}
	return &dto.WGKeyPair{PrivateKey: priv, PublicKey: pub}, nil
}

func toWGStatusDTO(st *wireguard.ServiceStatus) dto.WGServiceStatus {
	return dto.WGServiceStatus{
		IsLinux:         st.IsLinux,
		IsInstalled:     st.IsInstalled,
		IsActive:        st.IsActive,
		IsEnabled:       st.IsEnabled,
		InterfaceName:   st.InterfaceName,
		ListenPort:      st.ListenPort,
		PublicKey:       st.PublicKey,
		Address:         st.Address,
		TotalPeers:      st.TotalPeers,
		ActivePeers:     st.ActivePeers,
		OnlinePeers:     st.OnlinePeers,
		PortConflict:    st.PortConflict,
		ConflictInbound: st.ConflictInbound,
		IPv4Forwarding:  st.IPv4Forwarding,
		IPv6Forwarding:  st.IPv6Forwarding,
		EnableNAT:       st.EnableNAT,
	}
}

func toWGServerDTO(cfg *models.WGServerConfig) dto.WGServerConfigDTO {
	return dto.WGServerConfigDTO{
		ID:            cfg.ID,
		InterfaceName: cfg.InterfaceName,
		HasPrivateKey: cfg.PrivateKey != "",
		PublicKey:     cfg.PublicKey,
		ListenPort:    cfg.ListenPort,
		Address:       cfg.Address,
		MTU:           cfg.MTU,
		EnableNAT:     cfg.EnableNAT,
		PostUp:        cfg.PostUp,
		PostDown:      cfg.PostDown,
		Enabled:       cfg.Enabled,
		UpdatedAt:     cfg.UpdatedAt,
	}
}

func toWGPeerDTO(p models.WGPeer, stats map[string]wireguard.PeerRuntimeStats) dto.WGPeerDTO {
	runtimeStats := dto.WGPeerRuntimeStats{
		PublicKey:       p.PublicKey,
		HandshakeAgo:    "未连接",
		TransferRxHuman: "0 B",
		TransferTxHuman: "0 B",
		IsOnline:        false,
	}
	if st, ok := stats[p.PublicKey]; ok {
		runtimeStats = dto.WGPeerRuntimeStats{
			PublicKey:       st.PublicKey,
			Endpoint:        st.Endpoint,
			AllowedIPs:      st.AllowedIPs,
			LatestHandshake: st.LatestHandshake,
			HandshakeAgo:    st.HandshakeAgo,
			TransferRx:      st.TransferRx,
			TransferTx:      st.TransferTx,
			TransferRxHuman: st.TransferRxHuman,
			TransferTxHuman: st.TransferTxHuman,
			IsOnline:        st.IsOnline,
		}
	}

	return dto.WGPeerDTO{
		ID:                  p.ID,
		Name:                p.Name,
		PublicKey:           p.PublicKey,
		HasPrivateKey:       p.PrivateKey != "",
		HasPresharedKey:     p.PresharedKey != "",
		AllowedIPs:          p.AllowedIPs,
		Endpoint:            p.Endpoint,
		PersistentKeepalive: p.PersistentKeepalive,
		Enabled:             p.Enabled,
		Runtime:             runtimeStats,
		CreatedAt:           p.CreatedAt,
		UpdatedAt:           p.UpdatedAt,
	}
}
