package v1

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/service"
)

// Handler exposes all /api/v1 JSON REST endpoints aligned with api/openapi.yaml.
type Handler struct {
	Version   string
	Tokens    *service.TokenService
	Dashboard *service.DashboardService
	Users     *service.UserService
	Inbounds  *service.InboundService
	Outbounds *service.OutboundService
	Routing   *service.RoutingService
	Domains   *service.DomainService
	WireGuard *service.WireGuardService
	System    *service.SystemService
	Tunnels   *service.CFTunnelService
	Speedtest *service.SpeedtestService
	PVPN      *service.PVPNService
}

func respondOK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, dto.SuccessResponse{Success: true, Data: data})
}

func respondCreated(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, dto.SuccessResponse{Success: true, Data: data})
}

func respondError(c *gin.Context, status int, code dto.ErrorCode, msg string, details map[string]interface{}) {
	c.JSON(status, dto.ErrorResponse{
		Success: false,
		Error: dto.ErrorDetail{
			Code:    code,
			Message: msg,
			Details: details,
		},
	})
}

func respondServiceError(c *gin.Context, err error) {
	if appErr, ok := service.AsAppError(err); ok {
		respondError(c, appErr.HTTPStatus, appErr.Code, appErr.Message, appErr.Details)
		return
	}
	respondError(c, http.StatusInternalServerError, dto.ErrInternal, err.Error(), nil)
}

// Health handles GET /api/v1/health (public).
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, dto.HealthResponse{
		Status:  "ok",
		Version: h.Version,
	})
}

// VerifyAuth handles GET /api/v1/auth/verify.
func (h *Handler) VerifyAuth(c *gin.Context) {
	val, exists := c.Get(dto.AuthContextKey)
	if !exists {
		respondError(c, http.StatusUnauthorized, dto.ErrUnauthorized, "Unauthorized", nil)
		return
	}
	authCtx, ok := val.(*service.AuthContext)
	if !ok || authCtx == nil {
		respondError(c, http.StatusUnauthorized, dto.ErrUnauthorized, "Unauthorized", nil)
		return
	}
	respondOK(c, h.Tokens.Verify(authCtx))
}

// ListTokens handles GET /api/v1/tokens.
func (h *Handler) ListTokens(c *gin.Context) {
	res, err := h.Tokens.List()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// CreateToken handles POST /api/v1/tokens.
func (h *Handler) CreateToken(c *gin.Context) {
	var req dto.CreateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Tokens.Create(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondCreated(c, res)
}

// DeleteToken handles DELETE /api/v1/tokens/:id.
func (h *Handler) DeleteToken(c *gin.Context) {
	purge := c.Query("purge") == "true"
	res, err := h.Tokens.RevokeOrDelete(c.Param("id"), purge)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetDashboard handles GET /api/v1/dashboard.
func (h *Handler) GetDashboard(c *gin.Context) {
	res, err := h.Dashboard.GetDashboard()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ListUsers handles GET /api/v1/users.
func (h *Handler) ListUsers(c *gin.Context) {
	res, err := h.Users.List(c.Query("q"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetUser handles GET /api/v1/users/:id.
func (h *Handler) GetUser(c *gin.Context) {
	res, err := h.Users.Get(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// CreateUser handles POST /api/v1/users.
func (h *Handler) CreateUser(c *gin.Context) {
	var req dto.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Users.Create(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondCreated(c, res)
}

// UpdateUser handles PUT /api/v1/users/:id.
func (h *Handler) UpdateUser(c *gin.Context) {
	var req dto.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Users.Update(c.Param("id"), req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// DeleteUser handles DELETE /api/v1/users/:id.
func (h *Handler) DeleteUser(c *gin.Context) {
	res, err := h.Users.Delete(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ToggleUser handles POST /api/v1/users/:id/toggle.
func (h *Handler) ToggleUser(c *gin.Context) {
	res, err := h.Users.Toggle(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ResetUserTraffic handles POST /api/v1/users/:id/reset-traffic.
func (h *Handler) ResetUserTraffic(c *gin.Context) {
	res, err := h.Users.ResetTraffic(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ListInbounds handles GET /api/v1/inbounds.
func (h *Handler) ListInbounds(c *gin.Context) {
	res, err := h.Inbounds.List()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetInbound handles GET /api/v1/inbounds/:id.
func (h *Handler) GetInbound(c *gin.Context) {
	res, err := h.Inbounds.Get(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// CreateInbound handles POST /api/v1/inbounds.
func (h *Handler) CreateInbound(c *gin.Context) {
	var req dto.UpsertInboundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Inbounds.Create(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondCreated(c, res)
}

// UpdateInbound handles PUT /api/v1/inbounds/:id.
func (h *Handler) UpdateInbound(c *gin.Context) {
	var req dto.UpsertInboundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Inbounds.Update(c.Param("id"), req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// DeleteInbound handles DELETE /api/v1/inbounds/:id.
func (h *Handler) DeleteInbound(c *gin.Context) {
	res, err := h.Inbounds.Delete(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ToggleInbound handles POST /api/v1/inbounds/:id/toggle.
func (h *Handler) ToggleInbound(c *gin.Context) {
	res, err := h.Inbounds.Toggle(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetInboundWGClient handles GET /api/v1/inbounds/:id/wg-client.
func (h *Handler) GetInboundWGClient(c *gin.Context) {
	res, err := h.Inbounds.GetWGClientConfig(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ListOutbounds handles GET /api/v1/outbounds.
func (h *Handler) ListOutbounds(c *gin.Context) {
	res, err := h.Outbounds.List()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetOutbound handles GET /api/v1/outbounds/:id.
func (h *Handler) GetOutbound(c *gin.Context) {
	res, err := h.Outbounds.Get(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// CreateOutbound handles POST /api/v1/outbounds.
func (h *Handler) CreateOutbound(c *gin.Context) {
	var req dto.UpsertOutboundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Outbounds.Create(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondCreated(c, res)
}

// UpdateOutbound handles PUT /api/v1/outbounds/:id.
func (h *Handler) UpdateOutbound(c *gin.Context) {
	var req dto.UpsertOutboundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Outbounds.Update(c.Param("id"), req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// DeleteOutbound handles DELETE /api/v1/outbounds/:id.
func (h *Handler) DeleteOutbound(c *gin.Context) {
	res, err := h.Outbounds.Delete(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ToggleOutbound handles POST /api/v1/outbounds/:id/toggle.
func (h *Handler) ToggleOutbound(c *gin.Context) {
	res, err := h.Outbounds.Toggle(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// TestOutbound handles POST /api/v1/outbounds/:id/test.
func (h *Handler) TestOutbound(c *gin.Context) {
	res, err := h.Outbounds.Test(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ImportOutbound handles POST /api/v1/outbounds/import.
func (h *Handler) ImportOutbound(c *gin.Context) {
	var req dto.ImportShareLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Outbounds.ImportShareLink(req.Link)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondCreated(c, res)
}

// ParseWireGuardOutbound handles POST /api/v1/outbounds/parse-wireguard.
func (h *Handler) ParseWireGuardOutbound(c *gin.Context) {
	var req dto.ParseWireGuardConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Outbounds.ParseWireGuardConfig(req.Config)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GenerateOutboundWGKeys handles POST /api/v1/outbounds/generate-wg-keys.
func (h *Handler) GenerateOutboundWGKeys(c *gin.Context) {
	res, err := h.Outbounds.GenerateWGKeys()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ListRouting handles GET /api/v1/routing.
func (h *Handler) ListRouting(c *gin.Context) {
	res, err := h.Routing.List()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetRouting handles GET /api/v1/routing/:id.
func (h *Handler) GetRouting(c *gin.Context) {
	res, err := h.Routing.Get(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// CreateRouting handles POST /api/v1/routing.
func (h *Handler) CreateRouting(c *gin.Context) {
	var req dto.UpsertRoutingRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Routing.Create(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondCreated(c, res)
}

// UpdateRouting handles PUT /api/v1/routing/:id.
func (h *Handler) UpdateRouting(c *gin.Context) {
	var req dto.UpsertRoutingRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Routing.Update(c.Param("id"), req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// DeleteRouting handles DELETE /api/v1/routing/:id.
func (h *Handler) DeleteRouting(c *gin.Context) {
	res, err := h.Routing.Delete(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ToggleRouting handles POST /api/v1/routing/:id/toggle.
func (h *Handler) ToggleRouting(c *gin.Context) {
	res, err := h.Routing.Toggle(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ImportRoutingPreset handles POST /api/v1/routing/preset/:preset.
func (h *Handler) ImportRoutingPreset(c *gin.Context) {
	res, err := h.Routing.ImportPreset(c.Param("preset"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetGeoData handles GET /api/v1/routing/geodata.
func (h *Handler) GetGeoData(c *gin.Context) {
	respondOK(c, h.Routing.GetGeoData())
}

// ListDomains handles GET /api/v1/domains.
func (h *Handler) ListDomains(c *gin.Context) {
	res, err := h.Domains.List()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetDomain handles GET /api/v1/domains/:id.
func (h *Handler) GetDomain(c *gin.Context) {
	res, err := h.Domains.Get(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// CreateDomain handles POST /api/v1/domains.
func (h *Handler) CreateDomain(c *gin.Context) {
	var req dto.UpsertDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Domains.Create(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondCreated(c, res)
}

// UpdateDomain handles PUT /api/v1/domains/:id.
func (h *Handler) UpdateDomain(c *gin.Context) {
	var req dto.UpsertDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Domains.Update(c.Param("id"), req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// DeleteDomain handles DELETE /api/v1/domains/:id.
func (h *Handler) DeleteDomain(c *gin.Context) {
	res, err := h.Domains.Delete(c.Param("id"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ScanCerts handles GET /api/v1/domains/scan-certs.
func (h *Handler) ScanCerts(c *gin.Context) {
	res, err := h.Domains.ScanCertificates()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ScanImportCerts handles POST /api/v1/domains/scan-import.
func (h *Handler) ScanImportCerts(c *gin.Context) {
	res, err := h.Domains.ScanAndImportCertificates()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ImportSingleCert handles POST /api/v1/domains/import-cert.
func (h *Handler) ImportSingleCert(c *gin.Context) {
	var req dto.ImportCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Domains.ImportSingleCertificate(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// UploadDomainCert handles POST /api/v1/domains/upload-cert.
func (h *Handler) UploadDomainCert(c *gin.Context) {
	var req dto.UploadCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Domains.UploadCertificate(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// IssueDomainCert handles POST /api/v1/domains/issue-cert.
func (h *Handler) IssueDomainCert(c *gin.Context) {
	var req dto.IssueCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Domains.IssueCertificate(c.Request.Context(), req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetWGStatus handles GET /api/v1/wireguard/status.
func (h *Handler) GetWGStatus(c *gin.Context) {
	res, err := h.WireGuard.GetStatus()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// SetupWGEnv handles POST /api/v1/wireguard/setup-env.
func (h *Handler) SetupWGEnv(c *gin.Context) {
	res, err := h.WireGuard.SetupEnv()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// WGServiceAction handles POST /api/v1/wireguard/service/:action.
func (h *Handler) WGServiceAction(c *gin.Context) {
	res, err := h.WireGuard.ServiceAction(c.Param("action"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetWGServer handles GET /api/v1/wireguard/server.
func (h *Handler) GetWGServer(c *gin.Context) {
	res, err := h.WireGuard.GetServerConfig()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// UpdateWGServer handles PUT /api/v1/wireguard/server.
func (h *Handler) UpdateWGServer(c *gin.Context) {
	var req dto.UpdateWGServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.WireGuard.UpdateServerConfig(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ListWGPeers handles GET /api/v1/wireguard/peers.
func (h *Handler) ListWGPeers(c *gin.Context) {
	res, err := h.WireGuard.ListPeers()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

func parseUintID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid peer ID", nil)
		return 0, false
	}
	return uint(id), true
}

// GetWGPeer handles GET /api/v1/wireguard/peers/:id.
func (h *Handler) GetWGPeer(c *gin.Context) {
	id, ok := parseUintID(c)
	if !ok {
		return
	}
	res, err := h.WireGuard.GetPeer(id)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// CreateWGPeer handles POST /api/v1/wireguard/peers.
func (h *Handler) CreateWGPeer(c *gin.Context) {
	var req dto.UpsertWGPeerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.WireGuard.CreatePeer(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondCreated(c, res)
}

// UpdateWGPeer handles PUT /api/v1/wireguard/peers/:id.
func (h *Handler) UpdateWGPeer(c *gin.Context) {
	id, ok := parseUintID(c)
	if !ok {
		return
	}
	var req dto.UpsertWGPeerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.WireGuard.UpdatePeer(id, req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// DeleteWGPeer handles DELETE /api/v1/wireguard/peers/:id.
func (h *Handler) DeleteWGPeer(c *gin.Context) {
	id, ok := parseUintID(c)
	if !ok {
		return
	}
	res, err := h.WireGuard.DeletePeer(id)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ToggleWGPeer handles POST /api/v1/wireguard/peers/:id/toggle.
func (h *Handler) ToggleWGPeer(c *gin.Context) {
	id, ok := parseUintID(c)
	if !ok {
		return
	}
	res, err := h.WireGuard.TogglePeer(id)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ExportWGPeerConfig handles GET /api/v1/wireguard/peers/:id/config.
func (h *Handler) ExportWGPeerConfig(c *gin.Context) {
	id, ok := parseUintID(c)
	if !ok {
		return
	}
	res, err := h.WireGuard.ExportPeerConfig(id)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GenerateWGKeys handles POST /api/v1/wireguard/generate-keys.
func (h *Handler) GenerateWGKeys(c *gin.Context) {
	res, err := h.WireGuard.GenerateKeys()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetXrayStatus handles GET /api/v1/xray/status.
func (h *Handler) GetXrayStatus(c *gin.Context) {
	respondOK(c, h.System.GetXrayStatus())
}

// RestartXray handles POST /api/v1/xray/restart.
func (h *Handler) RestartXray(c *gin.Context) {
	res, err := h.System.RestartXray()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetXrayConfig handles GET /api/v1/xray/config.
func (h *Handler) GetXrayConfig(c *gin.Context) {
	res, err := h.System.GetXrayConfigPreview()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ApplyXrayConfig handles POST /api/v1/xray/apply.
func (h *Handler) ApplyXrayConfig(c *gin.Context) {
	var req dto.XrayApplyRequest
	if c.Request.ContentLength > 0 {
		_ = c.ShouldBindJSON(&req)
	}
	if c.Query("force") == "true" || c.Query("force") == "1" {
		req.Force = true
	}
	if c.Query("hot") == "true" || c.Query("hot") == "1" {
		req.Hot = true
	}
	res, err := h.System.ApplyXrayConfig(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetSettings handles GET /api/v1/settings.
func (h *Handler) GetSettings(c *gin.Context) {
	res, err := h.System.GetSettings()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// UpdateSettings handles PUT /api/v1/settings.
func (h *Handler) UpdateSettings(c *gin.Context) {
	var req dto.UpdateSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.System.UpdateSettings(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// RestartPanel handles POST /api/v1/panel/restart.
func (h *Handler) RestartPanel(c *gin.Context) {
	respondOK(c, h.System.RestartPanel())
}

// ApplySubscriptionNginx handles POST /api/v1/subscription/nginx.
func (h *Handler) ApplySubscriptionNginx(c *gin.Context) {
	res, err := h.System.ApplySubscriptionNginx()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// DisableSubscriptionNginx handles DELETE /api/v1/subscription/nginx.
func (h *Handler) DisableSubscriptionNginx(c *gin.Context) {
	res, err := h.System.DisableSubscriptionNginx()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ApplyAPINginx handles POST /api/v1/panel/nginx.
func (h *Handler) ApplyAPINginx(c *gin.Context) {
	res, err := h.System.ApplyAPINginx()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// DisableAPINginx handles DELETE /api/v1/panel/nginx.
func (h *Handler) DisableAPINginx(c *gin.Context) {
	res, err := h.System.DisableAPINginx()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetCFTunnelStatus handles GET /api/v1/tunnels/cf/status.
func (h *Handler) GetCFTunnelStatus(c *gin.Context) {
	respondOK(c, h.Tunnels.GetStatus(c.Request.Context()))
}

// GetSpeedtestStatus handles GET /api/v1/speedtest.
func (h *Handler) GetSpeedtestStatus(c *gin.Context) {
	res, err := h.Speedtest.GetStatus()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// UpdateSpeedtest handles PUT /api/v1/speedtest.
func (h *Handler) UpdateSpeedtest(c *gin.Context) {
	var req dto.UpdateSpeedtestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Speedtest.UpdateSettings(req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// StartSpeedtest handles POST /api/v1/speedtest/start.
func (h *Handler) StartSpeedtest(c *gin.Context) {
	res, err := h.Speedtest.Start()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// StopSpeedtest handles POST /api/v1/speedtest/stop.
func (h *Handler) StopSpeedtest(c *gin.Context) {
	res, err := h.Speedtest.Stop()
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// InstallCFTunnel handles POST /api/v1/tunnels/cf/install.
func (h *Handler) InstallCFTunnel(c *gin.Context) {
	res, err := h.Tunnels.InstallBinary(c.Request.Context())
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// SetupCFTunnel handles POST /api/v1/tunnels/cf/setup.
func (h *Handler) SetupCFTunnel(c *gin.Context) {
	var req dto.CFTunnelSetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "Invalid request: "+err.Error(), nil)
		return
	}
	res, err := h.Tunnels.SetupTunnel(c.Request.Context(), req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// CFTunnelServiceAction handles POST /api/v1/tunnels/cf/service/:action.
func (h *Handler) CFTunnelServiceAction(c *gin.Context) {
	res, err := h.Tunnels.ServiceAction(c.Request.Context(), c.Param("action"))
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetLogs handles GET /api/v1/logs.
func (h *Handler) GetLogs(c *gin.Context) {
	svcName := c.DefaultQuery("service", "xray")
	lines, _ := strconv.Atoi(c.DefaultQuery("lines", "100"))
	res, err := h.System.GetLogs(svcName, lines)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// StreamLogs handles GET /api/v1/logs/stream (SSE).
func (h *Handler) StreamLogs(c *gin.Context) {
	svcName := c.DefaultQuery("service", "xray")
	lines, _ := strconv.Atoi(c.DefaultQuery("lines", "100"))

	initial, err := h.System.GetLogs(svcName, lines)
	if err != nil {
		respondServiceError(c, err)
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Status(http.StatusOK)

	writeEvent := func(payload *dto.LogsResponse) {
		b, err := json.Marshal(payload)
		if err != nil {
			return
		}
		_, _ = c.Writer.WriteString("event: log\ndata: " + string(b) + "\n\n")
		c.Writer.Flush()
	}

	writeEvent(initial)
	lastContent := initial.Content

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-ticker.C:
			next, err := h.System.GetLogs(svcName, lines)
			if err != nil {
				continue
			}
			if next.Content != lastContent {
				lastContent = next.Content
				writeEvent(next)
			} else {
				_, _ = c.Writer.WriteString(": heartbeat\n\n")
				c.Writer.Flush()
			}
		}
	}
}

// ===== Proton VPN Wireproxy =====

// GetPVPNStatus handles GET /api/v1/pvpn/status.
func (h *Handler) GetPVPNStatus(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	res, err := h.PVPN.GetStatus(c.Request.Context())
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetPVPNCountries handles GET /api/v1/pvpn/countries.
func (h *Handler) GetPVPNCountries(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	res, err := h.PVPN.GetCountries(c.Request.Context())
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetPVPNServers handles GET /api/v1/pvpn/servers.
func (h *Handler) GetPVPNServers(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	country := c.Query("country")
	res, err := h.PVPN.GetServers(c.Request.Context(), country)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ConnectPVPN handles POST /api/v1/pvpn/connect.
func (h *Handler) ConnectPVPN(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	var req dto.PVPNConnectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, dto.ErrValidation, "无效的连接请求参数", nil)
		return
	}
	res, err := h.PVPN.Connect(c.Request.Context(), req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// DisconnectPVPN handles POST /api/v1/pvpn/disconnect.
func (h *Handler) DisconnectPVPN(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	res, err := h.PVPN.Disconnect(c.Request.Context())
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// PVPNServiceAction handles POST /api/v1/pvpn/service/:action.
func (h *Handler) PVPNServiceAction(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	action := c.Param("action")
	res, err := h.PVPN.ServiceAction(c.Request.Context(), action)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// InstallPVPN handles POST /api/v1/pvpn/install.
func (h *Handler) InstallPVPN(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	res, err := h.PVPN.Install(c.Request.Context())
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// EnsurePVPNOutbound handles POST /api/v1/pvpn/ensure-outbound.
func (h *Handler) EnsurePVPNOutbound(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	res, err := h.PVPN.EnsureOutbound(c.Request.Context())
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// GetPVPNConfig handles GET /api/v1/pvpn/config.
func (h *Handler) GetPVPNConfig(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	res, err := h.PVPN.GetConfig(c.Request.Context())
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// UpdatePVPNConfig handles PUT /api/v1/pvpn/config.
func (h *Handler) UpdatePVPNConfig(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	var req dto.PVPNConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondServiceError(c, service.NewValidationError("无效的配置请求参数: "+err.Error()))
		return
	}
	res, err := h.PVPN.UpdateConfig(c.Request.Context(), req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// LoginPVPN handles POST /api/v1/pvpn/login.
func (h *Handler) LoginPVPN(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	var req dto.PVPNLoginRequest
	_ = c.ShouldBindJSON(&req)
	res, err := h.PVPN.Login(c.Request.Context(), req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}

// ImportPVPNsession handles POST /api/v1/pvpn/session.
func (h *Handler) ImportPVPNsession(c *gin.Context) {
	if h.PVPN == nil {
		respondServiceError(c, service.NewInternalError("PVPN service not configured", nil))
		return
	}
	var req dto.PVPNImportSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondServiceError(c, service.NewValidationError("无效的 Session 数据: "+err.Error()))
		return
	}
	res, err := h.PVPN.ImportSession(c.Request.Context(), req)
	if err != nil {
		respondServiceError(c, err)
		return
	}
	respondOK(c, res)
}
