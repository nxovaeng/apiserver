package service

import (
	"fmt"
	"net"
	"strings"

	"gorm.io/gorm"

	"xray-panel-server/internal/config"
	"xray-panel-server/internal/dto"
	applogger "xray-panel-server/internal/logger"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/nginx"
)

// InboundService manages Xray inbounds and Nginx reverse proxy sync.
type InboundService struct {
	db       *gorm.DB
	cfg      *config.Config
	nginxGen *nginx.ConfigGenerator
}

func NewInboundService(db *gorm.DB, cfg *config.Config, nginxGen *nginx.ConfigGenerator) *InboundService {
	return &InboundService{db: db, cfg: cfg, nginxGen: nginxGen}
}

func (s *InboundService) List() (*dto.InboundListResponse, error) {
	var inbounds []models.Inbound
	if err := s.db.Preload("Domain").Order("created_at DESC").Find(&inbounds).Error; err != nil {
		return nil, NewInternalError("Failed to fetch inbounds", err)
	}

	socketDir := s.socketDir()
	dtos := make([]dto.InboundDTO, len(inbounds))
	for i, inb := range inbounds {
		dtos[i] = toInboundDTO(inb, socketDir)
	}
	return &dto.InboundListResponse{Inbounds: dtos, Total: len(dtos)}, nil
}

func (s *InboundService) Get(id string) (*dto.InboundDTO, error) {
	var inb models.Inbound
	if err := s.db.Preload("Domain").First(&inb, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Inbound not found")
	}
	dto := toInboundDTO(inb, s.socketDir())
	return &dto, nil
}

func (s *InboundService) Create(req dto.UpsertInboundRequest) (*dto.InboundDTO, error) {
	proto := models.Protocol(strings.TrimSpace(req.Protocol))
	if proto == "" {
		proto = models.ProtocolVLESS
	}
	if !isValidInboundProtocol(proto) {
		return nil, NewValidationError("不支持的入站协议，允许值: vless, trojan, wireguard")
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	inb := models.Inbound{
		Tag:            strings.TrimSpace(req.Tag),
		Protocol:       proto,
		Listen:         strings.TrimSpace(req.Listen),
		Path:           strings.TrimSpace(req.Path),
		ServiceName:    strings.TrimSpace(req.ServiceName),
		Host:           strings.TrimSpace(req.Host),
		Mode:           strings.TrimSpace(req.Mode),
		CustomSNI:      strings.TrimSpace(req.CustomSNI),
		ConnectDomain:  strings.TrimSpace(req.ConnectDomain),
		WGSecretKey:    strings.TrimSpace(req.WGSecretKey),
		WGPublicKey:    strings.TrimSpace(req.WGPublicKey),
		WGPeerPubKey:   strings.TrimSpace(req.WGPeerPubKey),
		WGMTU:          req.WGMTU,
		WGLocalIP:      strings.TrimSpace(req.WGLocalIP),
		ExcludeFromSub: req.ExcludeFromSub,
		Enabled:        enabled,
		Remark:         strings.TrimSpace(req.Remark),
	}

	if proto == models.ProtocolWireGuard {
		if inb.WGSecretKey == "" {
			return nil, NewValidationError("WireGuard 入站需要填写私钥")
		}
		if inb.WGPublicKey == "" {
			pub, err := models.DeriveWGPublicKey(inb.WGSecretKey)
			if err != nil {
				return nil, NewValidationError("WireGuard 私钥格式无效: " + err.Error())
			}
			inb.WGPublicKey = pub
		}
		inb.Transport = models.TransportRAW
		inb.UseUDS = false
		inb.ExcludeFromSub = true
		inb.DomainID = ""
		inb.ActualDomain = ""
		if inb.Listen == "" || inb.Listen == "127.0.0.1" {
			inb.Listen = "0.0.0.0"
		}
		if inb.WGMTU <= 0 {
			inb.WGMTU = 1420
		}
		if inb.WGLocalIP == "" {
			inb.WGLocalIP = "10.0.0.1/32"
		}
		if req.RandomPort || req.Port == 0 {
			inb.Port = randomPort(51820, 61820)
		} else {
			if req.Port < 1024 || req.Port > 65535 {
				return nil, NewValidationError("端口范围必须在 1024 - 65535 之间")
			}
			inb.Port = req.Port
		}
	} else {
		transport := models.Transport(strings.TrimSpace(req.Transport))
		if transport == "" {
			transport = models.TransportXHTTP
		}
		if !isValidProxyTransport(transport) {
			return nil, NewValidationError("不支持的传输协议，允许值: xhttp, grpc, ws")
		}
		inb.Transport = transport

		useUDS := true
		if req.UseUDS != nil {
			useUDS = *req.UseUDS
		}
		inb.UseUDS = useUDS
		if inb.Listen == "" {
			inb.Listen = "127.0.0.1"
		}

		if !useUDS {
			if req.RandomPort || req.Port == 0 {
				inb.Port = randomPort(10000, 60000)
			} else if req.Port < 1024 || req.Port > 65535 {
				return nil, NewValidationError("端口范围必须在 1024 - 65535 之间")
			} else {
				inb.Port = req.Port
			}
		} else {
			inb.Port = req.Port
		}

		if (transport == models.TransportWS || transport == models.TransportXHTTP) && (req.RandomPath || inb.Path == "") {
			inb.Path = "/" + randomHex(8)
		}
		if transport == models.TransportGRPC && inb.ServiceName == "" {
			inb.ServiceName = "grpc-" + randomHex(4)
		}

		if domainID := strings.TrimSpace(req.DomainID); domainID != "" {
			actualDomain, err := s.resolveActualDomain(domainID)
			if err != nil {
				return nil, err
			}
			inb.DomainID = domainID
			inb.ActualDomain = actualDomain
		}
	}

	if err := s.db.Create(&inb).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, NewConflictError("入站标签已存在")
		}
		return nil, NewInternalError("创建入站失败", err)
	}

	if inb.DomainID != "" && s.nginxGen != nil {
		var loaded models.Inbound
		if err := s.db.Preload("Domain").First(&loaded, "id = ?", inb.ID).Error; err == nil {
			inb = loaded
			s.syncInboundNginx(&loaded)
		}
	}

	dto := toInboundDTO(inb, s.socketDir())
	return &dto, nil
}

func (s *InboundService) Update(id string, req dto.UpsertInboundRequest) (*dto.InboundDTO, error) {
	var existing models.Inbound
	if err := s.db.First(&existing, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Inbound not found")
	}

	if tag := strings.TrimSpace(req.Tag); tag != "" {
		existing.Tag = tag
	}
	if proto := strings.TrimSpace(req.Protocol); proto != "" {
		p := models.Protocol(proto)
		if !isValidInboundProtocol(p) {
			return nil, NewValidationError("不支持的入站协议，允许值: vless, trojan, wireguard")
		}
		existing.Protocol = p
	}

	existing.Path = strings.TrimSpace(req.Path)
	existing.ServiceName = strings.TrimSpace(req.ServiceName)
	existing.Host = strings.TrimSpace(req.Host)
	existing.Mode = strings.TrimSpace(req.Mode)
	existing.Remark = strings.TrimSpace(req.Remark)
	existing.ConnectDomain = strings.TrimSpace(req.ConnectDomain)
	existing.CustomSNI = strings.TrimSpace(req.CustomSNI)
	if listen := strings.TrimSpace(req.Listen); listen != "" {
		existing.Listen = listen
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}

	if existing.Protocol == models.ProtocolWireGuard {
		existing.Transport = models.TransportRAW
		existing.UseUDS = false
		existing.ExcludeFromSub = true
		existing.DomainID = ""
		existing.ActualDomain = ""

		if sk := strings.TrimSpace(req.WGSecretKey); sk != "" {
			existing.WGSecretKey = sk
			if strings.TrimSpace(req.WGPublicKey) == "" {
				pub, err := models.DeriveWGPublicKey(sk)
				if err != nil {
					return nil, NewValidationError("WireGuard 私钥格式无效: " + err.Error())
				}
				existing.WGPublicKey = pub
			}
		}
		if pk := strings.TrimSpace(req.WGPublicKey); pk != "" {
			existing.WGPublicKey = pk
		}
		existing.WGPeerPubKey = strings.TrimSpace(req.WGPeerPubKey)
		if lip := strings.TrimSpace(req.WGLocalIP); lip != "" {
			existing.WGLocalIP = lip
		}
		if req.WGMTU > 0 {
			existing.WGMTU = req.WGMTU
		}
		if req.Port > 0 {
			if req.Port < 1024 || req.Port > 65535 {
				return nil, NewValidationError("端口范围必须在 1024 - 65535 之间")
			}
			existing.Port = req.Port
		}
		if existing.Listen == "" || existing.Listen == "127.0.0.1" {
			existing.Listen = "0.0.0.0"
		}
	} else {
		if t := strings.TrimSpace(req.Transport); t != "" {
			tr := models.Transport(t)
			if !isValidProxyTransport(tr) {
				return nil, NewValidationError("不支持的传输协议，允许值: xhttp, grpc, ws")
			}
			existing.Transport = tr
		}
		if req.UseUDS != nil {
			existing.UseUDS = *req.UseUDS
		}
		if req.Port > 0 {
			if !existing.UseUDS && (req.Port < 1024 || req.Port > 65535) {
				return nil, NewValidationError("端口范围必须在 1024 - 65535 之间")
			}
			existing.Port = req.Port
		}
		existing.ExcludeFromSub = req.ExcludeFromSub
		if existing.Listen == "" {
			existing.Listen = "127.0.0.1"
		}

		if (existing.Transport == models.TransportWS || existing.Transport == models.TransportXHTTP) && (req.RandomPath || existing.Path == "") {
			existing.Path = "/" + randomHex(8)
		}
		if existing.Transport == models.TransportGRPC && existing.ServiceName == "" {
			existing.ServiceName = "grpc-" + randomHex(4)
		}

		domainID := strings.TrimSpace(req.DomainID)
		if domainID != "" {
			if domainID != existing.DomainID || existing.ActualDomain == "" {
				actualDomain, err := s.resolveActualDomain(domainID)
				if err != nil {
					return nil, err
				}
				existing.ActualDomain = actualDomain
			}
			existing.DomainID = domainID
		} else {
			existing.DomainID = ""
			existing.ActualDomain = ""
		}
	}

	if err := s.db.Save(&existing).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, NewConflictError("入站标签已存在")
		}
		return nil, NewInternalError("更新入站失败", err)
	}

	if s.nginxGen != nil {
		if err := s.nginxGen.CleanupInboundConfigs(id); err != nil {
			applogger.Warn("Failed to cleanup old Nginx configs for inbound %s: %v", id, err)
		}
		if existing.DomainID != "" {
			var reloaded models.Inbound
			if err := s.db.Preload("Domain").First(&reloaded, "id = ?", id).Error; err == nil {
				existing = reloaded
				s.syncInboundNginx(&reloaded)
			}
		}
	} else if existing.DomainID != "" {
		_ = s.db.Preload("Domain").First(&existing, "id = ?", id).Error
	}

	dto := toInboundDTO(existing, s.socketDir())
	return &dto, nil
}

func (s *InboundService) Delete(id string) (*dto.DeleteResponse, error) {
	var existing models.Inbound
	if err := s.db.First(&existing, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Inbound not found")
	}

	if s.nginxGen != nil {
		if err := s.nginxGen.CleanupInboundConfigs(id); err != nil {
			applogger.Warn("Failed to cleanup Nginx configs for inbound %s: %v", id, err)
		}
	}

	if err := s.db.Delete(&models.Inbound{}, "id = ?", id).Error; err != nil {
		return nil, NewInternalError("Failed to delete inbound", err)
	}

	return &dto.DeleteResponse{ID: id, Deleted: true}, nil
}

func (s *InboundService) Toggle(id string) (*dto.InboundDTO, error) {
	var inb models.Inbound
	if err := s.db.Preload("Domain").First(&inb, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Inbound not found")
	}
	inb.Enabled = !inb.Enabled
	if err := s.db.Save(&inb).Error; err != nil {
		return nil, NewInternalError("Failed to toggle inbound", err)
	}
	dto := toInboundDTO(inb, s.socketDir())
	return &dto, nil
}

func (s *InboundService) GetWGClientConfig(id string) (*dto.InboundWGClientConfigResponse, error) {
	var inb models.Inbound
	if err := s.db.First(&inb, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("Inbound not found")
	}
	if inb.Protocol != models.ProtocolWireGuard {
		return nil, NewValidationError("Not a WireGuard inbound")
	}

	peerIP := "10.0.0.2/32"
	if inb.WGLocalIP != "" {
		ipPart := inb.WGLocalIP
		if idx := strings.Index(ipPart, "/"); idx != -1 {
			ipPart = ipPart[:idx]
		}
		if ip := net.ParseIP(ipPart).To4(); ip != nil {
			ip[3]++
			peerIP = ip.String() + "/32"
		}
	}

	serverHost := resolvePublicHost(s.db)
	if serverHost == "" {
		serverHost = "<SERVER_IP>"
	}
	endpoint := fmt.Sprintf("%s:%d", serverHost, inb.Port)

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString("PrivateKey = <客户端私钥>\n")
	sb.WriteString(fmt.Sprintf("Address = %s\n", peerIP))
	sb.WriteString("DNS = 1.1.1.1\n\n")
	sb.WriteString("[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", inb.WGPublicKey))
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", endpoint))
	sb.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	sb.WriteString("PersistentKeepalive = 25\n")
	if inb.WGMTU > 0 {
		sb.WriteString(fmt.Sprintf("MTU = %d\n", inb.WGMTU))
	}

	return &dto.InboundWGClientConfigResponse{
		InboundID:       inb.ID,
		InboundTag:      inb.Tag,
		ServerPublicKey: inb.WGPublicKey,
		ServerHost:      serverHost,
		Port:            inb.Port,
		Endpoint:        endpoint,
		PeerIP:          peerIP,
		MTU:             inb.WGMTU,
		WGConf:          sb.String(),
	}, nil
}

func (s *InboundService) resolveActualDomain(domainID string) (string, error) {
	var domain models.Domain
	if err := s.db.First(&domain, "id = ?", domainID).Error; err != nil {
		return "", NewValidationError("关联域名不存在")
	}
	isWildcard := domain.IsWildcard || strings.HasPrefix(domain.Domain, "*.")
	if isWildcard {
		baseDomain := strings.TrimPrefix(domain.Domain, "*.")
		return generateRandomSubdomain() + "." + baseDomain, nil
	}
	return domain.Domain, nil
}

func (s *InboundService) syncInboundNginx(inb *models.Inbound) {
	if s.nginxGen == nil || inb.Domain == nil {
		return
	}
	if err := s.nginxGen.GenerateHTTPConfig([]models.Inbound{*inb}); err != nil {
		applogger.Error("Failed to generate Nginx config for inbound %s: %v", inb.Tag, err)
		return
	}
	if err := s.nginxGen.Reload(); err != nil {
		applogger.Warn("Failed to reload Nginx after inbound %s sync: %v", inb.Tag, err)
	}
}

func (s *InboundService) socketDir() string {
	if s.cfg != nil && s.cfg.Xray.SocketDir != "" {
		return s.cfg.Xray.SocketDir
	}
	return "/dev/shm"
}

func isValidInboundProtocol(p models.Protocol) bool {
	return p == models.ProtocolVLESS || p == models.ProtocolTrojan || p == models.ProtocolWireGuard
}

func isValidProxyTransport(t models.Transport) bool {
	return t == models.TransportXHTTP || t == models.TransportGRPC || t == models.TransportWS
}

func toInboundDTO(i models.Inbound, socketDir string) dto.InboundDTO {
	var domainSummary *dto.DomainSummaryDTO
	if i.Domain != nil {
		domainSummary = &dto.DomainSummaryDTO{
			ID:         i.Domain.ID,
			Domain:     i.Domain.Domain,
			Type:       string(i.Domain.Type),
			IsWildcard: i.Domain.IsWildcard,
			Enabled:    i.Domain.Enabled,
		}
	}

	sockPath := ""
	if i.UseUDS {
		sockPath = i.SocketPath(socketDir)
	}

	return dto.InboundDTO{
		ID:             i.ID,
		Tag:            i.Tag,
		Protocol:       string(i.Protocol),
		Transport:      string(i.Transport),
		Port:           i.Port,
		Listen:         i.Listen,
		DomainID:       i.DomainID,
		Domain:         domainSummary,
		Path:           i.Path,
		ServiceName:    i.ServiceName,
		Host:           i.Host,
		Mode:           i.Mode,
		ActualDomain:   i.ActualDomain,
		CustomSNI:      i.CustomSNI,
		ConnectDomain:  i.ConnectDomain,
		HasWGSecretKey: i.WGSecretKey != "",
		WGPublicKey:    i.WGPublicKey,
		WGPeerPubKey:   i.WGPeerPubKey,
		WGMTU:          i.WGMTU,
		WGLocalIP:      i.WGLocalIP,
		ExcludeFromSub: i.ExcludeFromSub,
		Enabled:        i.Enabled,
		UseUDS:         i.UseUDS,
		SocketPath:     sockPath,
		Remark:         i.Remark,
		CreatedAt:      i.CreatedAt,
		UpdatedAt:      i.UpdatedAt,
	}
}
