package service

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gorm.io/gorm"

	"xray-panel-server/internal/config"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/nginx"
)

// Speedtest file constants. The size is fixed at 50 MiB to match the cfst
// strategy (FILE_SIZE_MB=50 in config.env.example): the client probes
// download this file and rank candidates by effective speed.
const (
	speedtestFileName = "50mb.bin"
	speedtestFileSize = 50 * 1024 * 1024
)

// SpeedtestService manages the speedtest origin on this VPS: the 50MB test
// file plus its nginx server block. The origin is off by default and only
// serves while started from the client, so the test address is not
// exposed (and cannot be abused for bandwidth) outside a test round. The
// subpath is configurable for the same reason: a random subpath makes the
// URL unguessable.
//
// The probing and DNS updates stay on the client (the Python cfst scripts);
// this service only prepares what the probes download.
type SpeedtestService struct {
	db       *gorm.DB
	cfg      *config.Config
	nginxGen *nginx.ConfigGenerator
}

func NewSpeedtestService(db *gorm.DB, cfg *config.Config, nginxGen *nginx.ConfigGenerator) *SpeedtestService {
	return &SpeedtestService{db: db, cfg: cfg, nginxGen: nginxGen}
}

func (s *SpeedtestService) fileDir() string {
	if s.cfg != nil && s.cfg.Speedtest.FileDir != "" {
		return s.cfg.Speedtest.FileDir
	}
	return "/var/www/speedtest"
}

func (s *SpeedtestService) filePath() string {
	return filepath.Join(s.fileDir(), speedtestFileName)
}

func (s *SpeedtestService) get(key, fallback string) string {
	return models.GetSettingValue(s.db, key, fallback)
}

func (s *SpeedtestService) setEnabled(enabled bool) error {
	val := "false"
	if enabled {
		val = "true"
	}
	return upsertSettingKV(s.db, "speedtest_enabled", val)
}

// normalizeSpeedtestSubpath cleans a user-supplied subpath: leading slash,
// no trailing slash, no ".." or empty segments, safe characters only.
// Empty input means the default "/speedtest".
func normalizeSpeedtestSubpath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "/speedtest", nil
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "", NewValidationError("subpath 不能是根路径 /")
	}
	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", NewValidationError("subpath 不能包含空段或 ..")
		}
		for _, ch := range seg {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
				return "", NewValidationError("subpath 只能包含字母、数字及 - _ . ~")
			}
		}
	}
	return p, nil
}

func validateSpeedtestDomain(domain string) error {
	if domain == "" {
		return NewValidationError("请先设置测速域名（如 jp-speed.example.com）")
	}
	if !domainRegex.MatchString(domain) {
		return NewValidationError("测速域名格式不正确")
	}
	return nil
}

// GetStatus returns the current speedtest origin state.
func (s *SpeedtestService) GetStatus() (*dto.SpeedtestStatus, error) {
	enabled := s.get("speedtest_enabled", "false") == "true"
	domain := strings.TrimSpace(s.get("speedtest_domain", ""))
	subpath, _ := normalizeSpeedtestSubpath(s.get("speedtest_subpath", "/speedtest"))

	st := &dto.SpeedtestStatus{
		Enabled: enabled,
		Domain:  domain,
		SubPath: subpath,
	}
	if fi, err := os.Stat(s.filePath()); err == nil {
		st.FileExists = true
		st.FileSize = fi.Size()
	}
	if enabled && domain != "" {
		st.URL = fmt.Sprintf("https://%s%s/%s", domain, subpath, speedtestFileName)
		st.ConfigPath = s.nginxGen.SpeedtestConfigPath()
	}
	return st, nil
}

// ensureTestFile creates the 50MB random (incompressible) test file when it
// is missing or has the wrong size. Existing correct files are kept.
func (s *SpeedtestService) ensureTestFile() error {
	path := s.filePath()
	if fi, err := os.Stat(path); err == nil && fi.Size() == speedtestFileSize {
		return nil
	}
	if err := os.MkdirAll(s.fileDir(), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.CopyN(f, rand.Reader, speedtestFileSize); err != nil {
		return err
	}
	return f.Sync()
}

// applyNginx writes the speedtest server block and reloads nginx.
func (s *SpeedtestService) applyNginx(domain, subpath string) error {
	if err := s.nginxGen.WriteSpeedtestConfig(domain, subpath, s.filePath()); err != nil {
		return err
	}
	return s.nginxGen.Reload()
}

// removeNginx deletes the speedtest server block and reloads nginx.
func (s *SpeedtestService) removeNginx() error {
	if err := s.nginxGen.RemoveSpeedtestConfig(); err != nil {
		return err
	}
	return s.nginxGen.Reload()
}

// UpdateSettings saves the speedtest domain/subpath. When the origin is
// enabled the nginx config is rewritten with the new values and reloaded,
// so a subpath change takes effect immediately.
func (s *SpeedtestService) UpdateSettings(req dto.UpdateSpeedtestRequest) (*dto.SpeedtestStatus, error) {
	enabled := s.get("speedtest_enabled", "false") == "true"
	domain := strings.TrimSpace(s.get("speedtest_domain", ""))
	subpath, _ := normalizeSpeedtestSubpath(s.get("speedtest_subpath", "/speedtest"))

	if req.Domain != nil {
		domain = strings.TrimSpace(*req.Domain)
		if domain != "" {
			if err := validateSpeedtestDomain(domain); err != nil {
				return nil, err
			}
		}
	}
	if req.SubPath != nil {
		p, err := normalizeSpeedtestSubpath(*req.SubPath)
		if err != nil {
			return nil, err
		}
		subpath = p
	}

	if err := upsertSettingKV(s.db, "speedtest_domain", domain); err != nil {
		return nil, err
	}
	if err := upsertSettingKV(s.db, "speedtest_subpath", subpath); err != nil {
		return nil, err
	}

	if enabled {
		if err := validateSpeedtestDomain(domain); err != nil {
			return nil, err
		}
		if err := s.applyNginx(domain, subpath); err != nil {
			return nil, err
		}
	}
	return s.GetStatus()
}

// Start enables the speedtest origin: creates the test file, writes the
// nginx server block, reloads nginx and marks the origin enabled.
func (s *SpeedtestService) Start() (*dto.SpeedtestStatus, error) {
	domain := strings.TrimSpace(s.get("speedtest_domain", ""))
	if err := validateSpeedtestDomain(domain); err != nil {
		return nil, err
	}
	subpath, _ := normalizeSpeedtestSubpath(s.get("speedtest_subpath", "/speedtest"))

	if err := s.ensureTestFile(); err != nil {
		return nil, NewInternalError("创建测速文件失败", err)
	}
	if err := s.applyNginx(domain, subpath); err != nil {
		return nil, NewInternalError("应用测速 nginx 配置失败", err)
	}
	if err := s.setEnabled(true); err != nil {
		return nil, err
	}
	return s.GetStatus()
}

// Stop disables the speedtest origin: removes the nginx server block,
// reloads nginx and marks the origin disabled. The test file stays on
// disk so the next Start is instant; without a route it cannot be fetched.
func (s *SpeedtestService) Stop() (*dto.SpeedtestStatus, error) {
	if err := s.removeNginx(); err != nil {
		return nil, NewInternalError("移除测速 nginx 配置失败", err)
	}
	if err := s.setEnabled(false); err != nil {
		return nil, err
	}
	return s.GetStatus()
}
