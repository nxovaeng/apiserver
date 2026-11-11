package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"gorm.io/gorm"

	"xray-panel-server/internal/config"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
)

// TunnelCmdRunner abstracts OS command execution & lookups for unit testing.
type TunnelCmdRunner interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, name string, args ...string) (string, error)
	FileExists(path string) bool
}

type defaultTunnelRunner struct{}

func (defaultTunnelRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (defaultTunnelRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (defaultTunnelRunner) FileExists(path string) bool {
	return fileExists(path)
}

// CFTunnelService manages optional Cloudflare Tunnel (cloudflared) installation and systemd service.
type CFTunnelService struct {
	db         *gorm.DB
	cfg        *config.Config
	runner     TunnelCmdRunner
	binaryDest string
	httpClient *http.Client
}

func NewCFTunnelService(db *gorm.DB, cfg *config.Config) *CFTunnelService {
	return &CFTunnelService{
		db:         db,
		cfg:        cfg,
		runner:     defaultTunnelRunner{},
		binaryDest: "/usr/local/bin/cloudflared",
		httpClient: &http.Client{Timeout: 90 * time.Second},
	}
}

func (s *CFTunnelService) SetRunner(r TunnelCmdRunner) {
	if r != nil {
		s.runner = r
	}
}

func (s *CFTunnelService) SetBinaryDest(path string) {
	if path != "" {
		s.binaryDest = path
	}
}

func (s *CFTunnelService) findBinary() (string, bool) {
	if p, err := s.runner.LookPath("cloudflared"); err == nil && p != "" {
		return p, true
	}
	for _, cand := range []string{s.binaryDest, "/usr/local/bin/cloudflared", "/usr/bin/cloudflared"} {
		if cand != "" && s.runner.FileExists(cand) {
			return cand, true
		}
	}
	return "", false
}

func (s *CFTunnelService) panelHTTPTarget() (string, string) {
	listen := "127.0.0.1:8082"
	if s.cfg != nil && s.cfg.Server.Listen != "" {
		listen = s.cfg.Server.Listen
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil || port == "" {
		return listen, "http://127.0.0.1:8082"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return listen, "http://" + net.JoinHostPort(host, port)
}

func (s *CFTunnelService) GetStatus(ctx context.Context) dto.CFTunnelStatus {
	binPath, installed := s.findBinary()
	version := ""
	if installed {
		if out, err := s.runner.Run(ctx, binPath, "--version"); err == nil {
			version = strings.TrimSpace(out)
		}
	}

	svcInstalled := s.runner.FileExists("/etc/systemd/system/cloudflared.service") ||
		s.runner.FileExists("/lib/systemd/system/cloudflared.service") ||
		s.runner.FileExists("/etc/systemd/system/cloudflared-update.service")

	active := false
	enabled := false
	statusText := "not_installed"
	if installed {
		statusText = "stopped"
		if stOut, err := s.runner.Run(ctx, "systemctl", "is-active", "cloudflared"); err == nil || stOut != "" {
			st := strings.TrimSpace(stOut)
			if st != "" {
				statusText = st
				active = st == "active"
			}
		}
		if enOut, err := s.runner.Run(ctx, "systemctl", "is-enabled", "cloudflared"); err == nil {
			enabled = strings.TrimSpace(enOut) == "enabled"
			svcInstalled = true
		}
	}

	panelListen, recService := s.panelHTTPTarget()
	subPath := models.GetSubPath(s.db)
	return dto.CFTunnelStatus{
		IsLinux:             runtime.GOOS == "linux",
		Installed:           installed,
		BinaryPath:          binPath,
		Version:             version,
		ServiceInstalled:    svcInstalled,
		Active:              active,
		Enabled:             enabled,
		Status:              statusText,
		PanelListen:         panelListen,
		SubDomain:           models.GetSubDomain(s.db),
		SubPath:             subPath,
		RecommendedService:  recService,
		RecommendedPathRule: subPath + "/*",
	}
}

func (s *CFTunnelService) InstallBinary(ctx context.Context) (*dto.CFTunnelInstallResponse, error) {
	if runtime.GOOS != "linux" {
		return nil, NewValidationError("仅支持在 Linux 服务端自动安装 cloudflared")
	}

	if existing, ok := s.findBinary(); ok {
		ver, _ := s.runner.Run(ctx, existing, "--version")
		return &dto.CFTunnelInstallResponse{
			Installed:  true,
			BinaryPath: existing,
			Version:    strings.TrimSpace(ver),
			Message:    "检测到已安装 cloudflared",
		}, nil
	}

	var cfArch string
	switch runtime.GOARCH {
	case "amd64":
		cfArch = "amd64"
	case "arm64":
		cfArch = "arm64"
	default:
		return nil, NewValidationError("暂不支持当前 CPU 架构自动安装 cloudflared: " + runtime.GOARCH)
	}

	dlURL := fmt.Sprintf("https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-%s", cfArch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return nil, NewInternalError("创建下载请求失败", err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, NewSystemCommandError("下载 cloudflared 失败: "+err.Error(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, NewSystemCommandError(fmt.Sprintf("下载 cloudflared 返回状态码 %d", resp.StatusCode), nil)
	}

	tmpPath := s.binaryDest + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return nil, NewSystemCommandError("创建 cloudflared 临时文件失败: "+err.Error(), err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, NewSystemCommandError("写入 cloudflared 失败: "+err.Error(), err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, NewSystemCommandError("关闭 cloudflared 文件失败: "+err.Error(), err)
	}
	if err := os.Rename(tmpPath, s.binaryDest); err != nil {
		_ = os.Remove(tmpPath)
		return nil, NewSystemCommandError("安装 cloudflared 失败: "+err.Error(), err)
	}

	ver, _ := s.runner.Run(ctx, s.binaryDest, "--version")
	return &dto.CFTunnelInstallResponse{
		Installed:  true,
		BinaryPath: s.binaryDest,
		Version:    strings.TrimSpace(ver),
		Message:    "cloudflared 安装成功",
	}, nil
}

func (s *CFTunnelService) SetupTunnel(ctx context.Context, req dto.CFTunnelSetupRequest) (*dto.CFTunnelActionResponse, error) {
	token := normalizeCloudflaredToken(req.TunnelToken)
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return nil, NewValidationError("Tunnel Token 格式无效，请粘贴 Cloudflare Zero Trust 提供的 Token")
	}

	binPath, installed := s.findBinary()
	if !installed {
		return nil, NewValidationError("尚未安装 cloudflared，请先点击「一键安装 cloudflared」")
	}

	// Uninstall existing systemd service cleanly if already registered before reinstalling new token
	_, _ = s.runner.Run(ctx, "systemctl", "stop", "cloudflared")
	_, _ = s.runner.Run(ctx, binPath, "service", "uninstall")

	out, err := s.runner.Run(ctx, binPath, "service", "install", token)
	safeOut := redactSecrets(out, []string{token})
	if err != nil {
		return nil, NewSystemCommandError("注册 Cloudflare Tunnel 服务失败: "+safeOut, err)
	}

	_, _ = s.runner.Run(ctx, "systemctl", "enable", "cloudflared")
	if startOut, startErr := s.runner.Run(ctx, "systemctl", "restart", "cloudflared"); startErr != nil {
		return nil, NewSystemCommandError("启动 cloudflared 服务失败: "+redactSecrets(startOut, []string{token}), startErr)
	}

	return &dto.CFTunnelActionResponse{
		Action:  "setup",
		Success: true,
		Status:  s.GetStatus(ctx),
		Message: "Cloudflare Tunnel 已配置并启动",
	}, nil
}

func (s *CFTunnelService) ServiceAction(ctx context.Context, action string) (*dto.CFTunnelActionResponse, error) {
	switch action {
	case "start", "stop", "restart":
		out, err := s.runner.Run(ctx, "systemctl", action, "cloudflared")
		if err != nil {
			return nil, NewSystemCommandError("执行 cloudflared "+action+" 失败: "+out, err)
		}
	case "uninstall":
		_, _ = s.runner.Run(ctx, "systemctl", "stop", "cloudflared")
		if binPath, ok := s.findBinary(); ok {
			if out, err := s.runner.Run(ctx, binPath, "service", "uninstall"); err != nil {
				return nil, NewSystemCommandError("卸载 cloudflared 服务失败: "+out, err)
			}
		}
	default:
		return nil, NewValidationError("不支持的 Cloudflare Tunnel 操作，允许值: start, stop, restart, uninstall")
	}

	return &dto.CFTunnelActionResponse{
		Action:  action,
		Success: true,
		Status:  s.GetStatus(ctx),
		Message: "操作 " + action + " 执行完成",
	}, nil
}

func normalizeCloudflaredToken(raw string) string {
	s := strings.TrimSpace(raw)
	for _, prefix := range []string{
		"sudo cloudflared service install",
		"cloudflared service install",
	} {
		if strings.HasPrefix(s, prefix) {
			s = strings.TrimSpace(strings.TrimPrefix(s, prefix))
		}
	}
	s = strings.Trim(s, `"'`)
	return strings.TrimSpace(s)
}
