package dto

import "time"

// DeleteResponse represents the standard deletion result.
type DeleteResponse struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// ===== Health & Auth & Tokens =====

type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

type AuthVerifyResponse struct {
	Valid            bool   `json:"valid"`
	TokenID          string `json:"token_id"`
	TokenName        string `json:"token_name"`
	TokenPrefix      string `json:"token_prefix"`
	Version          string `json:"version"`
	ServerPublicHost string `json:"server_public_host"`
	SubDomain        string `json:"sub_domain"`
	SubPath          string `json:"sub_path"`
	PanelTitle       string `json:"panel_title"`
}

type APITokenDTO struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Revoked     bool       `json:"revoked"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	LastIP      string     `json:"last_ip"`
	CreatedAt   time.Time  `json:"created_at"`
}

type TokenListResponse struct {
	Tokens []APITokenDTO `json:"tokens"`
	Total  int           `json:"total"`
}

type CreateTokenRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=64"`
	ExpiresDays *int   `json:"expires_days"`
}

type CreateTokenResponse struct {
	Token          APITokenDTO `json:"token"`
	PlaintextToken string      `json:"plaintext_token"`
}

type TokenDeleteResponse struct {
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
	Deleted bool   `json:"deleted"`
}

// ===== Dashboard =====

type DashboardCounts struct {
	Total  int64 `json:"total"`
	Active int64 `json:"active"`
}

type DashboardTraffic struct {
	UsersTrafficUsedBytes int64  `json:"users_traffic_used_bytes"`
	MonthlyNetSentBytes   uint64 `json:"monthly_net_sent_bytes"`
	MonthlyNetRecvBytes   uint64 `json:"monthly_net_recv_bytes"`
	MonthlyNetTotalBytes  uint64 `json:"monthly_net_total_bytes"`
	BaselineMonth         string `json:"baseline_month"`
}

type DashboardSystemMetrics struct {
	Hostname        string  `json:"hostname"`
	OS              string  `json:"os"`
	Platform        string  `json:"platform"`
	UptimeSeconds   uint64  `json:"uptime_seconds"`
	GoVersion       string  `json:"go_version"`
	CPUModel        string  `json:"cpu_model"`
	CPUCores        int     `json:"cpu_cores"`
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	MemTotalBytes   uint64  `json:"mem_total_bytes"`
	MemUsedBytes    uint64  `json:"mem_used_bytes"`
	MemFreeBytes    uint64  `json:"mem_free_bytes"`
	MemPercent      float64 `json:"mem_percent"`
	DiskTotalBytes  uint64  `json:"disk_total_bytes"`
	DiskUsedBytes   uint64  `json:"disk_used_bytes"`
	DiskFreeBytes   uint64  `json:"disk_free_bytes"`
	DiskPercent     float64 `json:"disk_percent"`
}

type DashboardServices struct {
	XrayActive           bool   `json:"xray_active"`
	XrayStatus           string `json:"xray_status"`
	WireguardInstalled   bool   `json:"wireguard_installed"`
	WireguardActive      bool   `json:"wireguard_active"`
	WireguardInterface   string `json:"wireguard_interface"`
	WireguardOnlinePeers int    `json:"wireguard_online_peers"`
	WireguardTotalPeers  int    `json:"wireguard_total_peers"`
}

type DashboardResponse struct {
	Users        DashboardCounts        `json:"users"`
	Inbounds     DashboardCounts        `json:"inbounds"`
	Outbounds    DashboardCounts        `json:"outbounds"`
	Domains      DashboardCounts        `json:"domains"`
	RoutingRules DashboardCounts        `json:"routing_rules"`
	Traffic      DashboardTraffic       `json:"traffic"`
	System       DashboardSystemMetrics `json:"system"`
	Services     DashboardServices      `json:"services"`
}

// ===== Users =====

type UserSubURLs struct {
	Base64       string `json:"base64"`
	Plain        string `json:"plain"`
	JSON         string `json:"json"`
	YAML         string `json:"yaml"`
	RelativePath string `json:"relative_path"`
}

type UserDTO struct {
	ID                    string      `json:"id"`
	UUID                  string      `json:"uuid"`
	Name                  string      `json:"name"`
	Email                 string      `json:"email"`
	TrafficLimitBytes     int64       `json:"traffic_limit_bytes"`
	TrafficUsedBytes      int64       `json:"traffic_used_bytes"`
	RemainingTrafficBytes int64       `json:"remaining_traffic_bytes"`
	TrafficResetAt        *time.Time  `json:"traffic_reset_at"`
	ExpiryDate            *time.Time  `json:"expiry_date"`
	RemainingDays         int         `json:"remaining_days"`
	Enabled               bool        `json:"enabled"`
	IsActive              bool        `json:"is_active"`
	SubPath               string      `json:"sub_path"`
	SubURLs               UserSubURLs `json:"sub_urls"`
	Note                  string      `json:"note"`
	WGPubKey              string      `json:"wg_pub_key"`
	CreatedAt             time.Time   `json:"created_at"`
	UpdatedAt             time.Time   `json:"updated_at"`
}

type UserListResponse struct {
	Users []UserDTO `json:"users"`
	Total int       `json:"total"`
}

type CreateUserRequest struct {
	Name              string     `json:"name" binding:"required,min=1"`
	Email             string     `json:"email"`
	UUID              string     `json:"uuid"`
	TrafficLimitBytes int64      `json:"traffic_limit_bytes"`
	ExpiryDate        *time.Time `json:"expiry_date"`
	ExpireDays        *int       `json:"expire_days"`
	Enabled           *bool      `json:"enabled"`
	Note              string     `json:"note"`
	WGPubKey          string     `json:"wg_pub_key"`
}

type UpdateUserRequest struct {
	Name              string     `json:"name" binding:"required,min=1"`
	Email             string     `json:"email"`
	UUID              string     `json:"uuid"`
	TrafficLimitBytes int64      `json:"traffic_limit_bytes"`
	ExpiryDate        *time.Time `json:"expiry_date"`
	Enabled           *bool      `json:"enabled"`
	Note              string     `json:"note"`
	WGPubKey          string     `json:"wg_pub_key"`
}

// ===== Inbounds =====

type DomainSummaryDTO struct {
	ID         string `json:"id"`
	Domain     string `json:"domain"`
	Type       string `json:"type"`
	IsWildcard bool   `json:"is_wildcard"`
	Enabled    bool   `json:"enabled"`
}

type InboundDTO struct {
	ID             string            `json:"id"`
	Tag            string            `json:"tag"`
	Protocol       string            `json:"protocol"`
	Transport      string            `json:"transport"`
	Port           int               `json:"port"`
	Listen         string            `json:"listen"`
	DomainID       string            `json:"domain_id"`
	Domain         *DomainSummaryDTO `json:"domain"`
	Path           string            `json:"path"`
	ServiceName    string            `json:"service_name"`
	Host           string            `json:"host"`
	Mode           string            `json:"mode"`
	ActualDomain   string            `json:"actual_domain"`
	CustomSNI      string            `json:"custom_sni"`
	ConnectDomain  string            `json:"connect_domain"`
	HasWGSecretKey bool              `json:"has_wg_secret_key"`
	WGPublicKey    string            `json:"wg_public_key"`
	WGPeerPubKey   string            `json:"wg_peer_pub_key"`
	WGMTU          int               `json:"wg_mtu"`
	WGLocalIP      string            `json:"wg_local_ip"`
	ExcludeFromSub bool              `json:"exclude_from_sub"`
	Enabled        bool              `json:"enabled"`
	UseUDS         bool              `json:"use_uds"`
	SocketPath     string            `json:"socket_path"`
	Remark         string            `json:"remark"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

type InboundListResponse struct {
	Inbounds []InboundDTO `json:"inbounds"`
	Total    int          `json:"total"`
}

type UpsertInboundRequest struct {
	Tag            string `json:"tag"`
	Protocol       string `json:"protocol"`
	Transport      string `json:"transport"`
	Port           int    `json:"port"`
	Listen         string `json:"listen"`
	DomainID       string `json:"domain_id"`
	Path           string `json:"path"`
	ServiceName    string `json:"service_name"`
	Host           string `json:"host"`
	Mode           string `json:"mode"`
	CustomSNI      string `json:"custom_sni"`
	ConnectDomain  string `json:"connect_domain"`
	WGSecretKey    string `json:"wg_secret_key"`
	WGPublicKey    string `json:"wg_public_key"`
	WGPeerPubKey   string `json:"wg_peer_pub_key"`
	WGMTU          int    `json:"wg_mtu"`
	WGLocalIP      string `json:"wg_local_ip"`
	ExcludeFromSub bool   `json:"exclude_from_sub"`
	UseUDS         *bool  `json:"use_uds"`
	Enabled        *bool  `json:"enabled"`
	RandomPort     bool   `json:"random_port"`
	RandomPath     bool   `json:"random_path"`
	Remark         string `json:"remark"`
}

type InboundWGClientConfigResponse struct {
	InboundID       string `json:"inbound_id"`
	InboundTag      string `json:"inbound_tag"`
	ServerPublicKey string `json:"server_public_key"`
	ServerHost      string `json:"server_host"`
	Port            int    `json:"port"`
	Endpoint        string `json:"endpoint"`
	PeerIP          string `json:"peer_ip"`
	MTU             int    `json:"mtu"`
	WGConf          string `json:"wg_conf"`
}

// ===== Outbounds =====

type OutboundDTO struct {
	ID                string    `json:"id"`
	Tag               string    `json:"tag"`
	Type              string    `json:"type"`
	Server            string    `json:"server"`
	Port              int       `json:"port"`
	Username          string    `json:"username"`
	HasPassword       bool      `json:"has_password"`
	HasWGSecretKey    bool      `json:"has_wg_secret_key"`
	WGClientPubKey    string    `json:"wg_client_pub_key"`
	WGPublicKey       string    `json:"wg_public_key"`
	WGReserved        string    `json:"wg_reserved"`
	WGLocalIPv4       string    `json:"wg_local_ipv4"`
	WGLocalIPv6       string    `json:"wg_local_ipv6"`
	WGMTU             int       `json:"wg_mtu"`
	WGDNS             string    `json:"wg_dns"`
	HasTrojanPassword bool      `json:"has_trojan_password"`
	TrojanSNI         string    `json:"trojan_sni"`
	TrojanNetwork     string    `json:"trojan_network"`
	UUID              string    `json:"uuid"`
	Flow              string    `json:"flow"`
	Security          string    `json:"security"`
	Network           string    `json:"network"`
	HeaderType        string    `json:"header_type"`
	RequestHost       string    `json:"request_host"`
	Path              string    `json:"path"`
	ServiceName       string    `json:"service_name"`
	TLS               bool      `json:"tls"`
	TLSServerName     string    `json:"tls_server_name"`
	TLSALPN           string    `json:"tls_alpn"`
	Reality           bool      `json:"reality"`
	RealityPubKey     string    `json:"reality_pubkey"`
	RealityShortID    string    `json:"reality_short_id"`
	RealitySNI        string    `json:"reality_sni"`
	Enabled           bool      `json:"enabled"`
	Priority          int       `json:"priority"`
	Remark            string    `json:"remark"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type OutboundListResponse struct {
	Outbounds []OutboundDTO `json:"outbounds"`
	Total     int           `json:"total"`
}

type UpsertOutboundRequest struct {
	Tag            string `json:"tag"`
	Type           string `json:"type" binding:"required"`
	Server         string `json:"server"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	WGSecretKey    string `json:"wg_secret_key"`
	WGClientPubKey string `json:"wg_client_pub_key"`
	WGPublicKey    string `json:"wg_public_key"`
	WGReserved     string `json:"wg_reserved"`
	WGLocalIPv4    string `json:"wg_local_ipv4"`
	WGLocalIPv6    string `json:"wg_local_ipv6"`
	WGMTU          int    `json:"wg_mtu"`
	WGDNS          string `json:"wg_dns"`
	TrojanPassword string `json:"trojan_password"`
	TrojanSNI      string `json:"trojan_sni"`
	TrojanNetwork  string `json:"trojan_network"`
	UUID           string `json:"uuid"`
	Flow           string `json:"flow"`
	Security       string `json:"security"`
	Network        string `json:"network"`
	HeaderType     string `json:"header_type"`
	RequestHost    string `json:"request_host"`
	Path           string `json:"path"`
	ServiceName    string `json:"service_name"`
	TLS            bool   `json:"tls"`
	TLSServerName  string `json:"tls_server_name"`
	TLSALPN        string `json:"tls_alpn"`
	Reality        bool   `json:"reality"`
	RealityPubKey  string `json:"reality_pubkey"`
	RealityShortID string `json:"reality_short_id"`
	RealitySNI     string `json:"reality_sni"`
	Enabled        *bool  `json:"enabled"`
	Priority       int    `json:"priority"`
	Remark         string `json:"remark"`
}

type ImportShareLinkRequest struct {
	Link string `json:"link" binding:"required"`
}

type ParseWireGuardConfigRequest struct {
	Config string `json:"config" binding:"required"`
}

type ParsedWireGuardConfig struct {
	PrivateKey      string `json:"private_key"`
	ClientPublicKey string `json:"client_public_key"`
	PublicKey       string `json:"public_key"`
	Endpoint        string `json:"endpoint"`
	Server          string `json:"server"`
	Port            int    `json:"port"`
	Address         string `json:"address"`
	LocalIPv4       string `json:"local_ipv4"`
	LocalIPv6       string `json:"local_ipv6"`
	DNS             string `json:"dns"`
	MTU             int    `json:"mtu"`
}

type OutboundTestResult struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	LatencyMs  int64  `json:"latency_ms,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	OutboundIP string `json:"outbound_ip,omitempty"`
	Location   string `json:"location,omitempty"`
}

type WGKeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// ===== Routing =====

type RoutingRuleDTO struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	InboundTag  string    `json:"inbound_tag"`
	Domains     string    `json:"domains"`
	IPs         string    `json:"ips"`
	GeoSiteTags string    `json:"geosite_tags"`
	GeoIPCodes  string    `json:"geoip_codes"`
	Protocols   string    `json:"protocols"`
	OutboundTag string    `json:"outbound_tag"`
	Priority    int       `json:"priority"`
	Enabled     bool      `json:"enabled"`
	Remark      string    `json:"remark"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type RoutingRuleListResponse struct {
	Rules []RoutingRuleDTO `json:"rules"`
	Total int              `json:"total"`
}

type UpsertRoutingRuleRequest struct {
	Name        string `json:"name" binding:"required"`
	Type        string `json:"type" binding:"required"`
	InboundTag  string `json:"inbound_tag"`
	Domains     string `json:"domains"`
	IPs         string `json:"ips"`
	GeoSiteTags string `json:"geosite_tags"`
	GeoIPCodes  string `json:"geoip_codes"`
	Protocols   string `json:"protocols"`
	OutboundTag string `json:"outbound_tag" binding:"required"`
	Priority    int    `json:"priority"`
	Enabled     *bool  `json:"enabled"`
	Remark      string `json:"remark"`
}

type ImportPresetResponse struct {
	Preset        string           `json:"preset"`
	ImportedCount int              `json:"imported_count"`
	SkippedCount  int              `json:"skipped_count"`
	Rules         []RoutingRuleDTO `json:"rules"`
}

type GeoDataInfo struct {
	GeoSiteAvailable bool     `json:"geosite_available"`
	GeoIPAvailable   bool     `json:"geoip_available"`
	GeoSiteTags      []string `json:"geosite_tags"`
	GeoIPCodes       []string `json:"geoip_codes"`
}

// ===== Domains & Certificates =====

type DomainDTO struct {
	ID             string     `json:"id"`
	Domain         string     `json:"domain"`
	Type           string     `json:"type"`
	IsWildcard     bool       `json:"is_wildcard"`
	CertPath       string     `json:"cert_path"`
	KeyPath        string     `json:"key_path"`
	Enabled        bool       `json:"enabled"`
	HasCert        bool       `json:"has_cert"`
	CertExpiryDate *time.Time `json:"cert_expiry_date"`
	DaysToExpiry   *int       `json:"days_to_expiry"`
	CertIssuer     string     `json:"cert_issuer"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type DomainListResponse struct {
	Domains []DomainDTO `json:"domains"`
	Total   int         `json:"total"`
}

type UpsertDomainRequest struct {
	Domain     string `json:"domain" binding:"required"`
	Type       string `json:"type"`
	IsWildcard bool   `json:"is_wildcard"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path"`
	Enabled    *bool  `json:"enabled"`
}

type CertificateInfo struct {
	Domain       string    `json:"domain"`
	Domains      []string  `json:"domains"`
	CertPath     string    `json:"cert_path"`
	KeyPath      string    `json:"key_path"`
	ExpiryDate   time.Time `json:"expiry_date"`
	DaysToExpiry int       `json:"days_to_expiry"`
	Status       string    `json:"status"`
	Issuer       string    `json:"issuer"`
	IsWildcard   bool      `json:"is_wildcard"`
	Exists       bool      `json:"exists"`
}

type ScanCertificatesResponse struct {
	CertDir      string            `json:"cert_dir"`
	Certificates []CertificateInfo `json:"certificates"`
	Count        int               `json:"count"`
}

type ScanImportCertificatesResponse struct {
	CertDir       string      `json:"cert_dir"`
	ImportedCount int         `json:"imported_count"`
	UpdatedCount  int         `json:"updated_count"`
	SkippedCount  int         `json:"skipped_count"`
	Errors        []string    `json:"errors"`
	Domains       []DomainDTO `json:"domains"`
}

type ImportCertRequest struct {
	Domain   string `json:"domain" binding:"required"`
	CertPath string `json:"cert_path" binding:"required"`
	KeyPath  string `json:"key_path" binding:"required"`
}

type UploadCertRequest struct {
	Domain  string `json:"domain" binding:"required"`
	Type    string `json:"type"`
	CertPEM string `json:"cert_pem" binding:"required"`
	KeyPEM  string `json:"key_pem" binding:"required"`
	Enabled *bool  `json:"enabled"`
}

type IssueCertRequest struct {
	Domain          string `json:"domain" binding:"required"`
	IncludeWildcard bool   `json:"include_wildcard"`
	Type            string `json:"type"`
	Provider        string `json:"provider" binding:"required"` // cf | luadns
	CFToken         string `json:"cf_token"`
	CFKey           string `json:"cf_key"`
	CFEmail         string `json:"cf_email"`
	CFZoneID        string `json:"cf_zone_id"`
	LuaKey          string `json:"lua_key"`
	LuaEmail        string `json:"lua_email"`
	CAServer        string `json:"ca_server"` // letsencrypt | zerossl
	Email           string `json:"email"`
	Force           bool   `json:"force"`
}

type IssueCertResponse struct {
	Domain         DomainDTO `json:"domain"`
	Provider       string    `json:"provider"`
	CAServer       string    `json:"ca_server"`
	ReusedExisting bool      `json:"reused_existing"`
	Output         string    `json:"output"`
}

// ===== WireGuard =====

type WGServiceStatus struct {
	IsLinux         bool   `json:"is_linux"`
	IsInstalled     bool   `json:"is_installed"`
	IsActive        bool   `json:"is_active"`
	IsEnabled       bool   `json:"is_enabled"`
	InterfaceName   string `json:"interface_name"`
	ListenPort      int    `json:"listen_port"`
	PublicKey       string `json:"public_key"`
	Address         string `json:"address"`
	TotalPeers      int    `json:"total_peers"`
	ActivePeers     int    `json:"active_peers"`
	OnlinePeers     int    `json:"online_peers"`
	PortConflict    bool   `json:"port_conflict"`
	ConflictInbound string `json:"conflict_inbound"`
	IPv4Forwarding  bool   `json:"ipv4_forwarding"`
	IPv6Forwarding  bool   `json:"ipv6_forwarding"`
	EnableNAT       bool   `json:"enable_nat"`
}

type WGSetupEnvResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type WGServiceActionResponse struct {
	Action  string          `json:"action"`
	Success bool            `json:"success"`
	Status  WGServiceStatus `json:"status"`
}

type WGServerConfigDTO struct {
	ID            uint      `json:"id"`
	InterfaceName string    `json:"interface_name"`
	HasPrivateKey bool      `json:"has_private_key"`
	PublicKey     string    `json:"public_key"`
	ListenPort    int       `json:"listen_port"`
	Address       string    `json:"address"`
	MTU           int       `json:"mtu"`
	EnableNAT     bool      `json:"enable_nat"`
	PostUp        string    `json:"post_up"`
	PostDown      string    `json:"post_down"`
	Enabled       bool      `json:"enabled"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type UpdateWGServerRequest struct {
	InterfaceName string `json:"interface_name"`
	ListenPort    int    `json:"listen_port"`
	Address       string `json:"address"`
	MTU           int    `json:"mtu"`
	PrivateKey    string `json:"private_key"`
	EnableNAT     *bool  `json:"enable_nat"`
	PostUp        string `json:"post_up"`
	PostDown      string `json:"post_down"`
	Enabled       *bool  `json:"enabled"`
}

type WGPeerRuntimeStats struct {
	PublicKey       string     `json:"public_key"`
	Endpoint        string     `json:"endpoint"`
	AllowedIPs      string     `json:"allowed_ips"`
	LatestHandshake *time.Time `json:"latest_handshake"`
	HandshakeAgo    string     `json:"handshake_ago"`
	TransferRx      int64      `json:"transfer_rx"`
	TransferTx      int64      `json:"transfer_tx"`
	TransferRxHuman string     `json:"transfer_rx_human"`
	TransferTxHuman string     `json:"transfer_tx_human"`
	IsOnline        bool       `json:"is_online"`
}

type WGPeerDTO struct {
	ID                  uint               `json:"id"`
	Name                string             `json:"name"`
	PublicKey           string             `json:"public_key"`
	HasPrivateKey       bool               `json:"has_private_key"`
	HasPresharedKey     bool               `json:"has_preshared_key"`
	AllowedIPs          string             `json:"allowed_ips"`
	Endpoint            string             `json:"endpoint"`
	PersistentKeepalive int                `json:"persistent_keepalive"`
	Enabled             bool               `json:"enabled"`
	Runtime             WGPeerRuntimeStats `json:"runtime"`
	CreatedAt           time.Time          `json:"created_at"`
	UpdatedAt           time.Time          `json:"updated_at"`
}

type WGPeerListResponse struct {
	Peers           []WGPeerDTO `json:"peers"`
	NextAvailableIP string      `json:"next_available_ip"`
	Total           int         `json:"total"`
}

type UpsertWGPeerRequest struct {
	Name                string `json:"name" binding:"required"`
	PublicKey           string `json:"public_key"`
	PrivateKey          string `json:"private_key"`
	PresharedKey        string `json:"preshared_key"`
	AllowedIPs          string `json:"allowed_ips"`
	Endpoint            string `json:"endpoint"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
	Enabled             *bool  `json:"enabled"`
}

type WGPeerExportConfigResponse struct {
	PeerID        uint   `json:"peer_id"`
	PeerName      string `json:"peer_name"`
	ServerHost    string `json:"server_host"`
	Endpoint      string `json:"endpoint"`
	WGConf        string `json:"wg_conf"`
	XrayJSON      string `json:"xray_json"`
	HasPrivateKey bool   `json:"has_private_key"`
}

// ===== Xray, Settings, Panel & Logs =====

type XrayStatusResponse struct {
	Status string `json:"status"`
	Active bool   `json:"active"`
}

type XrayRestartResponse struct {
	Restarted bool   `json:"restarted"`
	Status    string `json:"status"`
	Active    bool   `json:"active"`
}

type XrayConfigResponse struct {
	Config map[string]interface{} `json:"config"`
	Raw    string                 `json:"raw"`
}

type XrayApplyResponse struct {
	Applied   bool   `json:"applied"`
	Method    string `json:"method"`
	ConfigLen int    `json:"config_len"`
	Message   string `json:"message"`
}

type SettingsDTO struct {
	PanelTitle              string `json:"panel_title"`
	SubDomain               string `json:"sub_domain"`
	SubPath                 string `json:"sub_path"`
	SubNginxEnabled         bool   `json:"sub_nginx_enabled"`
	APIDomain               string `json:"api_domain"`
	APINginxEnabled         bool   `json:"api_nginx_enabled"`
	ServerPublicHost        string `json:"server_public_host"`
	XrayLogLevel            string `json:"xray_log_level"`
	EnableTrafficStats      bool   `json:"enable_traffic_stats"`
	EnableSniffing          bool   `json:"enable_sniffing"`
	DefaultTrafficLimit     int64  `json:"default_traffic_limit"`
	DefaultExpireDays       int    `json:"default_expire_days"`
	DirectDomainStrategy    string `json:"direct_domain_strategy"`
	MonthlyNetBaselineSent  string `json:"monthly_net_baseline_sent"`
	MonthlyNetBaselineRecv  string `json:"monthly_net_baseline_recv"`
	MonthlyNetBaselineMonth string `json:"monthly_net_baseline_month"`
}

type UpdateSettingsRequest struct {
	PanelTitle           *string `json:"panel_title"`
	SubDomain            *string `json:"sub_domain"`
	SubPath              *string `json:"sub_path"`
	SubNginxEnabled      *bool   `json:"sub_nginx_enabled"`
	APIDomain            *string `json:"api_domain"`
	APINginxEnabled      *bool   `json:"api_nginx_enabled"`
	ServerPublicHost     *string `json:"server_public_host"`
	XrayLogLevel         *string `json:"xray_log_level"`
	EnableTrafficStats   *bool   `json:"enable_traffic_stats"`
	EnableSniffing       *bool   `json:"enable_sniffing"`
	DefaultTrafficLimit  *int64  `json:"default_traffic_limit"`
	DefaultExpireDays    *int    `json:"default_expire_days"`
	DirectDomainStrategy *string `json:"direct_domain_strategy"`
}

type SubscriptionNginxResponse struct {
	Enabled           bool   `json:"enabled"`
	Domain            string `json:"domain"`
	SubPath           string `json:"sub_path"`
	ConfigPath        string `json:"config_path"`
	MatchedCertDomain string `json:"matched_cert_domain"`
	Reloaded          bool   `json:"reloaded"`
	Message           string `json:"message"`
}

type APINginxResponse struct {
	Enabled           bool   `json:"enabled"`
	Domain            string `json:"domain"`
	DirectURL         string `json:"direct_url"`
	ConfigPath        string `json:"config_path"`
	MatchedCertDomain string `json:"matched_cert_domain"`
	Reloaded          bool   `json:"reloaded"`
	Message           string `json:"message"`
}

// ===== Cloudflare Tunnel =====

type CFTunnelStatus struct {
	IsLinux             bool   `json:"is_linux"`
	Installed           bool   `json:"installed"`
	BinaryPath          string `json:"binary_path"`
	Version             string `json:"version"`
	ServiceInstalled    bool   `json:"service_installed"`
	Active              bool   `json:"active"`
	Enabled             bool   `json:"enabled"`
	Status              string `json:"status"`
	PanelListen         string `json:"panel_listen"`
	SubDomain           string `json:"sub_domain"`
	SubPath             string `json:"sub_path"`
	RecommendedService  string `json:"recommended_service"`
	RecommendedPathRule string `json:"recommended_path_rule"`
}

type CFTunnelSetupRequest struct {
	TunnelToken string `json:"tunnel_token" binding:"required"`
}

type CFTunnelInstallResponse struct {
	Installed  bool   `json:"installed"`
	BinaryPath string `json:"binary_path"`
	Version    string `json:"version"`
	Message    string `json:"message"`
}

type CFTunnelActionResponse struct {
	Action  string         `json:"action"`
	Success bool           `json:"success"`
	Status  CFTunnelStatus `json:"status"`
	Message string         `json:"message"`
}

type PanelRestartResponse struct {
	Restarting bool   `json:"restarting"`
	Message    string `json:"message"`
}

type LogsResponse struct {
	Service string `json:"service"`
	Lines   int    `json:"lines"`
	Content string `json:"content"`
}

// ===== Subscriptions =====

type SubscriptionUserSummary struct {
	Name             string `json:"name"`
	Email            string `json:"email"`
	UUID             string `json:"uuid"`
	Upload           int64  `json:"upload"`
	Download         int64  `json:"download"`
	Total            int64  `json:"total"`
	Expire           int64  `json:"expire"`
	TrafficUsed      int64  `json:"traffic_used"`
	TrafficLimit     int64  `json:"traffic_limit"`
	RemainingDays    int    `json:"remaining_days"`
	RemainingTraffic int64  `json:"remaining_traffic"`
	IsActive         bool   `json:"is_active"`
}

type SubscriptionJSONResponse struct {
	Links []string                `json:"links"`
	Count int                     `json:"count"`
	User  SubscriptionUserSummary `json:"user"`
}
