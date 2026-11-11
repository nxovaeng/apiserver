package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	v1 "xray-panel-server/internal/api/v1"
	"xray-panel-server/internal/config"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/nginx"
	"xray-panel-server/internal/service"
)

// Server encapsulates the headless Gin API engine, services, and background workers.
type Server struct {
	config      *config.Config
	db          *gorm.DB
	router      *gin.Engine
	nginxGen    *nginx.ConfigGenerator
	version     string
	authLimiter *SlidingWindowLimiter
	subLimiter  *SlidingWindowLimiter
	subSvc      *service.SubscriptionService
	v1Handler   *v1.Handler
	stopCh      chan struct{}
	stopOnce    sync.Once
}

// NewServer constructs a configured Server ready for Run() or HTTP testing.
func NewServer(cfg *config.Config, db *gorm.DB, version string) *Server {
	if !cfg.Server.Debug {
		gin.SetMode(gin.ReleaseMode)
	}
	if version == "" {
		version = "0.1.0"
	}

	nginxGen := nginx.NewGenerator(cfg.Nginx.ConfigDir, cfg.Nginx.StreamDir)
	nginxGen.SetDB(db)
	nginxGen.SetSocketDir(cfg.Xray.SocketDir)
	nginxGen.SetPanelListen(cfg.Server.Listen)
	if cfg.Nginx.ReloadCmd != "" {
		nginxGen.SetReloadCmd(cfg.Nginx.ReloadCmd)
	}

	tokenSvc := service.NewTokenService(db, cfg, version)
	userSvc := service.NewUserService(db)
	inboundSvc := service.NewInboundService(db, cfg, nginxGen)
	outboundSvc := service.NewOutboundService(db, cfg)
	routingSvc := service.NewRoutingService(db, cfg)
	domainSvc := service.NewDomainService(db, cfg)
	wgSvc := service.NewWireGuardService(db)
	sysSvc := service.NewSystemService(db, cfg, nginxGen)
	dashSvc := service.NewDashboardService(db, sysSvc)
	subSvc := service.NewSubscriptionService(db)
	tunnelSvc := service.NewCFTunnelService(db, cfg)

	failLimit := cfg.Auth.FailLimit
	if failLimit <= 0 {
		failLimit = 15
	}
	failWin := time.Duration(cfg.Auth.FailWindowMinutes) * time.Minute
	if failWin <= 0 {
		failWin = 5 * time.Minute
	}

	router := gin.New()
	router.Use(gin.Recovery())
	if cfg.Server.Debug {
		router.Use(gin.Logger())
	}

	s := &Server{
		config:      cfg,
		db:          db,
		router:      router,
		nginxGen:    nginxGen,
		version:     version,
		authLimiter: NewSlidingWindowLimiter(failLimit, failWin),
		subLimiter:  NewSlidingWindowLimiter(30, time.Minute),
		subSvc:      subSvc,
		stopCh:      make(chan struct{}),
		v1Handler: &v1.Handler{
			Version:   version,
			Tokens:    tokenSvc,
			Dashboard: dashSvc,
			Users:     userSvc,
			Inbounds:  inboundSvc,
			Outbounds: outboundSvc,
			Routing:   routingSvc,
			Domains:   domainSvc,
			WireGuard: wgSvc,
			System:    sysSvc,
			Tunnels:   tunnelSvc,
		},
	}

	s.setupRoutes()
	return s
}

// Handler returns the underlying http.Handler for tests and custom listeners.
func (s *Server) Handler() http.Handler {
	return s.router
}

// Run starts background workers and serves HTTP traffic on the configured listen address.
func (s *Server) Run() error {
	s.startTrafficSync()
	s.startMonthlyTrafficReset()
	return s.router.Run(s.config.Server.Listen)
}

// Stop signals background workers to exit.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

func (s *Server) setupRoutes() {
	// Security headers
	s.router.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	})

	// Public health probe
	s.router.GET("/api/v1/health", s.v1Handler.Health)

	// Protected /api/v1 routes (Bearer Token required)
	apiV1 := s.router.Group("/api/v1")
	apiV1.Use(BearerAuthMiddleware(s.v1Handler.Tokens, s.authLimiter))
	{
		// Auth & Tokens
		apiV1.GET("/auth/verify", s.v1Handler.VerifyAuth)
		apiV1.GET("/tokens", s.v1Handler.ListTokens)
		apiV1.POST("/tokens", s.v1Handler.CreateToken)
		apiV1.DELETE("/tokens/:id", s.v1Handler.DeleteToken)

		// Dashboard
		apiV1.GET("/dashboard", s.v1Handler.GetDashboard)

		// Users
		apiV1.GET("/users", s.v1Handler.ListUsers)
		apiV1.POST("/users", s.v1Handler.CreateUser)
		apiV1.GET("/users/:id", s.v1Handler.GetUser)
		apiV1.PUT("/users/:id", s.v1Handler.UpdateUser)
		apiV1.DELETE("/users/:id", s.v1Handler.DeleteUser)
		apiV1.POST("/users/:id/toggle", s.v1Handler.ToggleUser)
		apiV1.POST("/users/:id/reset-traffic", s.v1Handler.ResetUserTraffic)

		// Inbounds
		apiV1.GET("/inbounds", s.v1Handler.ListInbounds)
		apiV1.POST("/inbounds", s.v1Handler.CreateInbound)
		apiV1.GET("/inbounds/:id", s.v1Handler.GetInbound)
		apiV1.PUT("/inbounds/:id", s.v1Handler.UpdateInbound)
		apiV1.DELETE("/inbounds/:id", s.v1Handler.DeleteInbound)
		apiV1.POST("/inbounds/:id/toggle", s.v1Handler.ToggleInbound)
		apiV1.GET("/inbounds/:id/wg-client", s.v1Handler.GetInboundWGClient)

		// Outbounds
		apiV1.GET("/outbounds", s.v1Handler.ListOutbounds)
		apiV1.POST("/outbounds", s.v1Handler.CreateOutbound)
		apiV1.POST("/outbounds/import", s.v1Handler.ImportOutbound)
		apiV1.POST("/outbounds/parse-wireguard", s.v1Handler.ParseWireGuardOutbound)
		apiV1.POST("/outbounds/generate-wg-keys", s.v1Handler.GenerateOutboundWGKeys)
		apiV1.GET("/outbounds/:id", s.v1Handler.GetOutbound)
		apiV1.PUT("/outbounds/:id", s.v1Handler.UpdateOutbound)
		apiV1.DELETE("/outbounds/:id", s.v1Handler.DeleteOutbound)
		apiV1.POST("/outbounds/:id/toggle", s.v1Handler.ToggleOutbound)
		apiV1.POST("/outbounds/:id/test", s.v1Handler.TestOutbound)

		// Routing
		apiV1.GET("/routing", s.v1Handler.ListRouting)
		apiV1.POST("/routing", s.v1Handler.CreateRouting)
		apiV1.GET("/routing/geodata", s.v1Handler.GetGeoData)
		apiV1.POST("/routing/preset/:preset", s.v1Handler.ImportRoutingPreset)
		apiV1.GET("/routing/:id", s.v1Handler.GetRouting)
		apiV1.PUT("/routing/:id", s.v1Handler.UpdateRouting)
		apiV1.DELETE("/routing/:id", s.v1Handler.DeleteRouting)
		apiV1.POST("/routing/:id/toggle", s.v1Handler.ToggleRouting)

		// Domains & Certificates
		apiV1.GET("/domains", s.v1Handler.ListDomains)
		apiV1.POST("/domains", s.v1Handler.CreateDomain)
		apiV1.GET("/domains/scan-certs", s.v1Handler.ScanCerts)
		apiV1.POST("/domains/scan-import", s.v1Handler.ScanImportCerts)
		apiV1.POST("/domains/import-cert", s.v1Handler.ImportSingleCert)
		apiV1.POST("/domains/upload-cert", s.v1Handler.UploadDomainCert)
		apiV1.POST("/domains/issue-cert", s.v1Handler.IssueDomainCert)
		apiV1.GET("/domains/:id", s.v1Handler.GetDomain)
		apiV1.PUT("/domains/:id", s.v1Handler.UpdateDomain)
		apiV1.DELETE("/domains/:id", s.v1Handler.DeleteDomain)

		// Subscription & API Nginx reverse proxy and Cloudflare Tunnel
		apiV1.POST("/subscription/nginx", s.v1Handler.ApplySubscriptionNginx)
		apiV1.DELETE("/subscription/nginx", s.v1Handler.DisableSubscriptionNginx)
		apiV1.POST("/panel/nginx", s.v1Handler.ApplyAPINginx)
		apiV1.DELETE("/panel/nginx", s.v1Handler.DisableAPINginx)
		apiV1.GET("/tunnels/cf/status", s.v1Handler.GetCFTunnelStatus)
		apiV1.POST("/tunnels/cf/install", s.v1Handler.InstallCFTunnel)
		apiV1.POST("/tunnels/cf/setup", s.v1Handler.SetupCFTunnel)
		apiV1.POST("/tunnels/cf/service/:action", s.v1Handler.CFTunnelServiceAction)

		// WireGuard
		apiV1.GET("/wireguard/status", s.v1Handler.GetWGStatus)
		apiV1.POST("/wireguard/setup-env", s.v1Handler.SetupWGEnv)
		apiV1.POST("/wireguard/service/:action", s.v1Handler.WGServiceAction)
		apiV1.GET("/wireguard/server", s.v1Handler.GetWGServer)
		apiV1.PUT("/wireguard/server", s.v1Handler.UpdateWGServer)
		apiV1.GET("/wireguard/peers", s.v1Handler.ListWGPeers)
		apiV1.POST("/wireguard/peers", s.v1Handler.CreateWGPeer)
		apiV1.GET("/wireguard/peers/:id", s.v1Handler.GetWGPeer)
		apiV1.PUT("/wireguard/peers/:id", s.v1Handler.UpdateWGPeer)
		apiV1.DELETE("/wireguard/peers/:id", s.v1Handler.DeleteWGPeer)
		apiV1.POST("/wireguard/peers/:id/toggle", s.v1Handler.ToggleWGPeer)
		apiV1.GET("/wireguard/peers/:id/config", s.v1Handler.ExportWGPeerConfig)
		apiV1.POST("/wireguard/generate-keys", s.v1Handler.GenerateWGKeys)

		// Xray, Settings, Panel & Logs
		apiV1.GET("/xray/status", s.v1Handler.GetXrayStatus)
		apiV1.POST("/xray/restart", s.v1Handler.RestartXray)
		apiV1.GET("/xray/config", s.v1Handler.GetXrayConfig)
		apiV1.POST("/xray/apply", s.v1Handler.ApplyXrayConfig)
		apiV1.GET("/settings", s.v1Handler.GetSettings)
		apiV1.PUT("/settings", s.v1Handler.UpdateSettings)
		apiV1.POST("/panel/restart", s.v1Handler.RestartPanel)
		apiV1.GET("/logs", s.v1Handler.GetLogs)
		apiV1.GET("/logs/stream", s.v1Handler.StreamLogs)
	}

	// Dynamic subscription route matcher (takes effect immediately when sub_path setting changes)
	s.router.NoRoute(s.handleDynamicNoRoute)
}

func (s *Server) handleDynamicNoRoute(c *gin.Context) {
	if c.Request.Method != http.MethodGet {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Success: false,
			Error: dto.ErrorDetail{
				Code:    dto.ErrNotFound,
				Message: "Route not found",
			},
		})
		return
	}

	subPrefix := models.GetSubPath(s.db)
	reqPath := c.Request.URL.Path

	prefixWithSlash := subPrefix + "/"
	if !strings.HasPrefix(reqPath, prefixWithSlash) {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Success: false,
			Error: dto.ErrorDetail{
				Code:    dto.ErrNotFound,
				Message: "Route not found",
			},
		})
		return
	}

	rest := strings.TrimPrefix(reqPath, prefixWithSlash)
	rest = strings.Trim(rest, "/")
	if rest == "" {
		c.String(http.StatusNotFound, "Subscription not found")
		return
	}

	segments := strings.Split(rest, "/")
	if len(segments) > 2 {
		c.String(http.StatusNotFound, "Subscription not found")
		return
	}

	if !s.subLimiter.RecordAndAllow(c.ClientIP()) {
		c.String(http.StatusTooManyRequests, "Rate limit exceeded")
		return
	}

	userSubPath := segments[0]
	format := "base64"
	if len(segments) == 2 {
		format = segments[1]
	}

	out, err := s.subSvc.Generate(userSubPath, format)
	if err != nil {
		if appErr, ok := service.AsAppError(err); ok {
			c.String(appErr.HTTPStatus, appErr.Message)
			return
		}
		c.String(http.StatusInternalServerError, "Failed to generate subscription")
		return
	}

	c.Header("Subscription-Userinfo", out.UserInfo)
	c.Header("Profile-Update-Interval", "24")
	c.Header("Profile-Title", out.ProfileName)
	if out.Disposition != "" {
		c.Header("Content-Disposition", out.Disposition)
	}

	if out.JSONBody != nil {
		c.JSON(http.StatusOK, dto.SuccessResponse{
			Success: true,
			Data:    out.JSONBody,
		})
		return
	}

	c.Data(http.StatusOK, out.ContentType, []byte(out.TextBody))
}
