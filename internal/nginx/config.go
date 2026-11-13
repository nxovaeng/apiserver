package nginx

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gorm.io/gorm"

	applogger "xray-panel-server/internal/logger"
	"xray-panel-server/internal/models"
)

const ManagedHeader = "# Managed by Xray Panel"

// ConfigGenerator handles generating Nginx configurations.
type ConfigGenerator struct {
	configDir        string
	streamDir        string
	reloadCmd        string
	testCmd          string
	db               *gorm.DB
	socketDir        string
	panelListen      string
	speedtestFileDir string
}

// NewGenerator creates a new Nginx config generator.
func NewGenerator(configDir, streamDir string) *ConfigGenerator {
	return &ConfigGenerator{
		configDir:        configDir,
		streamDir:        streamDir,
		reloadCmd:        "systemctl reload nginx",
		testCmd:          "nginx -t",
		socketDir:        "/dev/shm",
		panelListen:      "127.0.0.1:8082",
		speedtestFileDir: "/var/www/speedtest",
	}
}

func (g *ConfigGenerator) ConfigDir() string {
	return g.configDir
}

func (g *ConfigGenerator) SetDB(db *gorm.DB) {
	g.db = db
}

func (g *ConfigGenerator) SetSpeedtestFileDir(dir string) {
	if dir != "" {
		g.speedtestFileDir = dir
	}
}

func (g *ConfigGenerator) SpeedtestFileDir() string {
	if g.speedtestFileDir != "" {
		return g.speedtestFileDir
	}
	return "/var/www/speedtest"
}

func (g *ConfigGenerator) SetReloadCmd(cmd string) {
	if cmd != "" {
		g.reloadCmd = cmd
	}
}

// SetTestCmd overrides the Nginx config syntax verification command (default "nginx -t").
func (g *ConfigGenerator) SetTestCmd(cmd string) {
	g.testCmd = strings.TrimSpace(cmd)
}

func (g *ConfigGenerator) SetSocketDir(dir string) {
	if dir != "" {
		g.socketDir = dir
	}
}

func (g *ConfigGenerator) SetPanelListen(addr string) {
	if addr != "" {
		g.panelListen = addr
	}
}

func (g *ConfigGenerator) panelTarget() string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(g.panelListen))
	if err != nil || port == "" {
		return "127.0.0.1:8082"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// Reload reloads Nginx configuration.
func (g *ConfigGenerator) Reload() error {
	parts := strings.Fields(g.reloadCmd)
	if len(parts) == 0 {
		return fmt.Errorf("empty reload command")
	}
	cmd := exec.Command(parts[0], parts[1:]...)
	return cmd.Run()
}

func (g *ConfigGenerator) recordConfig(inboundID, domain, configPath, configType string) error {
	if g.db == nil {
		return nil
	}

	var existing models.NginxConfig
	result := g.db.Where("inbound_id = ? AND config_path = ?", inboundID, configPath).First(&existing)
	if result.Error == nil {
		existing.Domain = domain
		existing.ConfigType = configType
		return g.db.Save(&existing).Error
	}

	cfg := &models.NginxConfig{
		InboundID:  inboundID,
		Domain:     domain,
		ConfigPath: configPath,
		ConfigType: configType,
		IsManaged:  true,
	}
	return g.db.Create(cfg).Error
}

// CleanupInboundConfigs removes managed Nginx configs for a specific inbound.
func (g *ConfigGenerator) CleanupInboundConfigs(inboundID string) error {
	if g.db == nil {
		return nil
	}

	var configs []models.NginxConfig
	if err := g.db.Where("inbound_id = ?", inboundID).Find(&configs).Error; err != nil {
		return err
	}

	for _, cfg := range configs {
		if cfg.IsManaged && g.isManagedFile(cfg.ConfigPath) {
			_ = os.Remove(cfg.ConfigPath)
		}
	}

	return g.db.Where("inbound_id = ?", inboundID).Delete(&models.NginxConfig{}).Error
}

func (g *ConfigGenerator) isManagedFile(filename string) bool {
	file, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		return strings.Contains(scanner.Text(), ManagedHeader)
	}
	return false
}

func (g *ConfigGenerator) writeConfig(filename string, content string) error {
	if dir := filepath.Dir(filename); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	if _, err := os.Stat(filename); err == nil {
		if !g.isManagedFile(filename) {
			return fmt.Errorf("file %s exists and is not managed by Xray Panel", filename)
		}
	}

	fullContent := fmt.Sprintf("%s\n%s", ManagedHeader, content)
	return os.WriteFile(filename, []byte(fullContent), 0644)
}

// GeneratePanelConfig generates Nginx reverse proxy config for the panel API itself.
func (g *ConfigGenerator) GeneratePanelConfig(domain, certPath, keyPath, listenAddr string) error {
	parts := strings.Split(listenAddr, ":")
	port := parts[len(parts)-1]

	data := panelTmplData{
		Domain:   domain,
		CertPath: certPath,
		KeyPath:  keyPath,
		Port:     port,
	}

	var buf bytes.Buffer
	if err := panelConfigTmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute panel template: %w", err)
	}

	filename := filepath.Join(g.configDir, fmt.Sprintf("%s.conf", domain))
	return g.writeConfig(filename, buf.String())
}

// SpeedtestConfigPath is the managed nginx config file for the speedtest
// origin (one file per VPS, not recorded in the NginxConfig table: the
// speedtest settings row is the source of truth).
func (g *ConfigGenerator) SpeedtestConfigPath() string {
	return filepath.Join(g.configDir, "speedtest.conf")
}

// WriteSpeedtestConfig renders the speedtest origin server block (serves
// the 50MB test file under subpath, everything else 404) and writes it as
// a managed file, then validates the nginx config. If certPath and keyPath are provided,
// it configures HTTPS (port 443 ssl with http2) with HTTP-to-HTTPS redirect. Call Reload afterwards.
func (g *ConfigGenerator) WriteSpeedtestConfig(domain, subpath, filePath, certPath, keyPath string) error {
	var content string
	if certPath != "" && keyPath != "" {
		content = fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name %s;

    ssl_certificate %s;
    ssl_certificate_key %s;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    gzip off;

    access_log /var/log/nginx/speedtest.access.log;
    error_log /var/log/nginx/speedtest.error.log;

    location = %s/50mb.bin {
        alias %s;
        gzip off;
        add_header Cache-Control "no-store";
        add_header Access-Control-Allow-Origin "*";
    }

    location / {
        return 404;
    }
}
`, domain, domain, certPath, keyPath, subpath, filePath)
	} else {
		content = fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;

    gzip off;

    access_log /var/log/nginx/speedtest.access.log;
    error_log /var/log/nginx/speedtest.error.log;

    location = %s/50mb.bin {
        alias %s;
        gzip off;
        add_header Cache-Control "no-store";
        add_header Access-Control-Allow-Origin "*";
    }

    location / {
        return 404;
    }
}
`, domain, subpath, filePath)
	}
	if err := g.writeConfig(g.SpeedtestConfigPath(), content); err != nil {
		return err
	}
	return g.TestConfig()
}

// RemoveSpeedtestConfig deletes the managed speedtest config file (if any)
// and validates the remaining nginx config. Call Reload afterwards.
func (g *ConfigGenerator) RemoveSpeedtestConfig() error {
	path := g.SpeedtestConfigPath()
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	if !g.isManagedFile(path) {
		return fmt.Errorf("file %s exists and is not managed by Xray Panel", path)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return g.TestConfig()
}

// GenerateHTTPConfig generates Nginx HTTP server blocks for enabled inbounds with domains.
func (g *ConfigGenerator) GenerateHTTPConfig(inbounds []models.Inbound) error {
	domainInbounds := make(map[string][]models.Inbound)
	for _, i := range inbounds {
		if i.Domain != nil {
			domain := i.Domain.Domain
			if i.ActualDomain != "" {
				domain = i.ActualDomain
			}
			domainInbounds[domain] = append(domainInbounds[domain], i)
		}
	}

	for domain, grp := range domainInbounds {
		conf := g.buildServerBlock(domain, grp)
		filename := filepath.Join(g.configDir, fmt.Sprintf("%s.conf", domain))

		if err := g.writeConfig(filename, conf); err != nil {
			return err
		}

		for _, inbound := range grp {
			if err := g.recordConfig(inbound.ID, domain, filename, "http"); err != nil {
				applogger.Warn("failed to record nginx config for inbound %s: %v", inbound.ID, err)
			}
		}
	}

	return nil
}

func (g *ConfigGenerator) buildServerBlock(domain string, inbounds []models.Inbound) string {
	data := inboundsTmplData{
		Domain: domain,
	}

	if g.db != nil {
		if models.GetSubNginxEnabled(g.db) {
			subDom := models.GetSubDomain(g.db)
			if subDom != "" && strings.EqualFold(domain, subDom) {
				data.SubPath = models.GetSubPath(g.db)
				data.PanelTarget = g.panelTarget()
			}
		}
		if models.GetAPINginxEnabled(g.db) {
			apiDom := models.GetAPIDomain(g.db)
			if apiDom != "" && strings.EqualFold(domain, apiDom) {
				data.ExposeAPI = true
				data.PanelTarget = g.panelTarget()
			}
		}
		if models.GetSettingValue(g.db, "speedtest_enabled", "false") == "true" {
			speedDom := strings.TrimSpace(models.GetSettingValue(g.db, "speedtest_domain", ""))
			if speedDom != "" && strings.EqualFold(domain, speedDom) {
				subPath := models.GetSettingValue(g.db, "speedtest_subpath", "/speedtest")
				if !strings.HasPrefix(subPath, "/") {
					subPath = "/" + subPath
				}
				data.SpeedtestSubPath = strings.TrimRight(subPath, "/")
				data.SpeedtestFilePath = filepath.Join(g.SpeedtestFileDir(), "50mb.bin")
			}
		}
	}

	if len(inbounds) > 0 && inbounds[0].Domain != nil {
		d := inbounds[0].Domain
		data.HasCert = true
		data.CertPath = d.CertPath
		data.KeyPath = d.KeyPath
	}

	var locations []inboundLocationData
	for _, i := range inbounds {
		var grpcUpstream, httpUpstream string
		if i.UseUDS {
			sockPath := i.SocketPath(g.socketDir)
			grpcUpstream = fmt.Sprintf("grpc://unix:%s", sockPath)
			httpUpstream = fmt.Sprintf("http://unix:%s", sockPath)
		} else {
			grpcUpstream = fmt.Sprintf("grpc://127.0.0.1:%d", i.Port)
			httpUpstream = fmt.Sprintf("http://127.0.0.1:%d", i.Port)
		}

		loc := inboundLocationData{
			Tag:          i.Tag,
			ActualDomain: i.ActualDomain,
			IsGRPC:       i.IsGRPC(),
			IsXHTTP:      i.IsXHTTP(),
			IsWS:         i.IsWS(),
			ServiceName:  i.ServiceName,
			Path:         i.Path,
		}

		if loc.IsGRPC {
			loc.Upstream = grpcUpstream
		} else if loc.IsXHTTP || loc.IsWS {
			loc.Upstream = httpUpstream
		}
		locations = append(locations, loc)
	}
	data.Inbounds = locations

	var buf bytes.Buffer
	if err := inboundsConfigTmpl.Execute(&buf, data); err != nil {
		return ""
	}

	return buf.String()
}

// EndpointProxySpec describes standalone HTTPS Nginx reverse proxy routing for a domain.
type EndpointProxySpec struct {
	Domain    string
	CertPath  string
	KeyPath   string
	SubPath   string
	ExposeAPI bool
}

// SyncEndpointProxies writes standalone endpoint proxy configs (API and/or subscription) for desired domains
// and cleans up any previously managed endpoint configs that are no longer desired (or now shared by an inbound).
func (g *ConfigGenerator) SyncEndpointProxies(desired map[string]EndpointProxySpec) (map[string]string, error) {
	if g.db != nil {
		var existing []models.NginxConfig
		if err := g.db.Where("config_type IN ?", []string{"subscription", "api", "endpoint"}).Find(&existing).Error; err == nil {
			for _, cfg := range existing {
				keep := false
				for dom := range desired {
					if strings.EqualFold(cfg.Domain, dom) {
						keep = true
						break
					}
				}
				if !keep {
					if cfg.IsManaged && g.isManagedFile(cfg.ConfigPath) {
						_ = os.Remove(cfg.ConfigPath)
					}
					_ = g.db.Delete(&cfg).Error
				}
			}
		}
	}

	written := make(map[string]string, len(desired))
	for _, spec := range desired {
		filename := filepath.Join(g.configDir, fmt.Sprintf("%s.conf", spec.Domain))
		subPath := ""
		if spec.SubPath != "" {
			subPath = models.NormalizeSubPath(spec.SubPath)
		}
		data := subTmplData{
			Domain:      spec.Domain,
			CertPath:    spec.CertPath,
			KeyPath:     spec.KeyPath,
			SubPath:     subPath,
			ExposeAPI:   spec.ExposeAPI,
			PanelTarget: g.panelTarget(),
		}
		if g.db != nil && models.GetSettingValue(g.db, "speedtest_enabled", "false") == "true" {
			speedDom := strings.TrimSpace(models.GetSettingValue(g.db, "speedtest_domain", ""))
			if speedDom != "" && strings.EqualFold(spec.Domain, speedDom) {
				sub := models.GetSettingValue(g.db, "speedtest_subpath", "/speedtest")
				if !strings.HasPrefix(sub, "/") {
					sub = "/" + sub
				}
				data.SpeedtestSubPath = strings.TrimRight(sub, "/")
				data.SpeedtestFilePath = filepath.Join(g.SpeedtestFileDir(), "50mb.bin")
			}
		}

		var buf bytes.Buffer
		if err := subConfigTmpl.Execute(&buf, data); err != nil {
			return nil, fmt.Errorf("failed to execute endpoint nginx template for %s: %w", spec.Domain, err)
		}
		if err := g.writeConfig(filename, buf.String()); err != nil {
			return nil, err
		}
		if err := g.recordConfig("", spec.Domain, filename, "endpoint"); err != nil {
			applogger.Warn("failed to record endpoint nginx config for %s: %v", spec.Domain, err)
		}
		written[strings.ToLower(spec.Domain)] = filename
	}
	return written, nil
}

// GenerateSubscriptionConfig generates a standalone subscription-only Nginx HTTPS server config
// for domain if no active inbound config already owns that domain, cleaning up stale subscription files.
func (g *ConfigGenerator) GenerateSubscriptionConfig(domain, subPath, certPath, keyPath string, sharedWithInbound bool) (string, error) {
	if err := g.CleanupSubscriptionConfigsExcept(domain, sharedWithInbound); err != nil {
		applogger.Warn("cleanup stale subscription nginx configs failed: %v", err)
	}

	filename := filepath.Join(g.configDir, fmt.Sprintf("%s.conf", domain))
	if sharedWithInbound {
		return filename, nil
	}

	written, err := g.SyncEndpointProxies(map[string]EndpointProxySpec{
		strings.ToLower(domain): {
			Domain:   domain,
			CertPath: certPath,
			KeyPath:  keyPath,
			SubPath:  subPath,
		},
	})
	if err != nil {
		return "", err
	}
	return written[strings.ToLower(domain)], nil
}

// CleanupSubscriptionConfigsExcept removes managed standalone endpoint/subscription Nginx configs.
func (g *ConfigGenerator) CleanupSubscriptionConfigsExcept(keepDomain string, removeAllForKeep bool) error {
	if g.db == nil {
		return nil
	}
	var configs []models.NginxConfig
	if err := g.db.Where("config_type IN ?", []string{"subscription", "api", "endpoint"}).Find(&configs).Error; err != nil {
		return err
	}
	for _, cfg := range configs {
		if keepDomain != "" && !removeAllForKeep && strings.EqualFold(cfg.Domain, keepDomain) {
			continue
		}
		if !removeAllForKeep || !strings.EqualFold(cfg.Domain, keepDomain) {
			if cfg.IsManaged && g.isManagedFile(cfg.ConfigPath) {
				_ = os.Remove(cfg.ConfigPath)
			}
		}
		_ = g.db.Delete(&cfg).Error
	}
	return nil
}

// CleanupSubscriptionConfigs removes all managed standalone endpoint Nginx configs.
func (g *ConfigGenerator) CleanupSubscriptionConfigs() error {
	return g.CleanupSubscriptionConfigsExcept("", false)
}

// TestConfig validates nginx syntax when running against system Nginx config or an explicit test command.
// When using a non-system temp directory (or reload/test mocked to "true"/"none"), host /etc/nginx/nginx.conf is skipped.
func (g *ConfigGenerator) TestConfig() error {
	testCmd := strings.TrimSpace(g.testCmd)
	if testCmd == "" || testCmd == "true" || testCmd == "none" {
		return nil
	}
	if testCmd == "nginx -t" {
		// Never run system `nginx -t` (which touches /etc/nginx/nginx.conf and /run/nginx.pid)
		// during tests using temporary directories or mocked reload commands.
		if strings.TrimSpace(g.reloadCmd) == "true" || filepath.Clean(g.configDir) != "/etc/nginx/conf.d" {
			return nil
		}
		if _, err := exec.LookPath("nginx"); err != nil {
			return nil
		}
	}
	parts := strings.Fields(testCmd)
	if len(parts) == 0 {
		return nil
	}
	out, err := exec.Command(parts[0], parts[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
