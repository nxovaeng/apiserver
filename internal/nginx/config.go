package nginx

import (
	"bufio"
	"bytes"
	"fmt"
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
	configDir string
	streamDir string
	reloadCmd string
	db        *gorm.DB
	socketDir string
}

// NewGenerator creates a new Nginx config generator.
func NewGenerator(configDir, streamDir string) *ConfigGenerator {
	return &ConfigGenerator{
		configDir: configDir,
		streamDir: streamDir,
		reloadCmd: "systemctl reload nginx",
		socketDir: "/dev/shm",
	}
}

func (g *ConfigGenerator) SetDB(db *gorm.DB) {
	g.db = db
}

func (g *ConfigGenerator) SetReloadCmd(cmd string) {
	if cmd != "" {
		g.reloadCmd = cmd
	}
}

func (g *ConfigGenerator) SetSocketDir(dir string) {
	if dir != "" {
		g.socketDir = dir
	}
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
