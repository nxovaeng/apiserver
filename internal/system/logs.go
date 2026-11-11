package system

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Known service log targets.
const (
	LogSourceXray      = "xray"
	LogSourcePanel     = "panel"
	LogSourceWireguard = "wireguard"
	LogSourceNginx     = "nginx"
)

// IsValidLogSource reports whether the given log service name is supported.
func IsValidLogSource(service string) bool {
	switch service {
	case LogSourceXray, LogSourcePanel, LogSourceWireguard, LogSourceNginx:
		return true
	default:
		return false
	}
}

// GetServiceLogs retrieves the latest lines of logs for a given service.
func GetServiceLogs(service string, lines int) (string, error) {
	if lines <= 0 {
		lines = 100
	}
	if lines > 1000 {
		lines = 1000
	}

	if runtime.GOOS == "linux" {
		journalOut, err := getJournalLogs(service, lines)
		if err == nil && len(strings.TrimSpace(journalOut)) > 0 {
			return journalOut, nil
		}

		fileOut, fileErr := getFileLogs(service, lines)
		if fileErr == nil && len(strings.TrimSpace(fileOut)) > 0 {
			return fileOut, nil
		}

		if err != nil && fileErr != nil {
			return fmt.Sprintf("暂无日志输出或读取失败: [journalctl 提示: %v] [文件日志提示: %v]", err, fileErr), nil
		}
		return "暂无日志记录（服务运行正常或尚未产生新日志）", nil
	}

	fileOut, err := getFileLogs(service, lines)
	if err == nil && len(strings.TrimSpace(fileOut)) > 0 {
		return fileOut, nil
	}
	return fmt.Sprintf("非 Linux 系统仅支持本地日志文件读取。当前服务 [%s] 暂未发现本地日志文件。", service), nil
}

func getJournalLogs(service string, lines int) (string, error) {
	var unit string
	switch service {
	case LogSourceXray:
		unit = "xray"
	case LogSourcePanel:
		unit = "xray-panel-server"
	case LogSourceWireguard:
		unit = "wg-quick@wg0"
	case LogSourceNginx:
		unit = "nginx"
	default:
		unit = service
	}

	cmd := exec.Command("journalctl", "-u", unit, "-n", fmt.Sprintf("%d", lines), "--no-pager", "-o", "short-iso")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func getFileLogs(service string, lines int) (string, error) {
	var candidates []string
	switch service {
	case LogSourceXray:
		candidates = []string{
			"/var/log/xray/access.log",
			"/var/log/xray/error.log",
			"/usr/local/var/log/xray/error.log",
		}
	case LogSourcePanel:
		candidates = []string{
			"/opt/xray-panel/logs/panel.log",
			"/var/log/xray-panel/panel.log",
			"logs/panel.log",
		}
	case LogSourceNginx:
		candidates = []string{
			"/var/log/nginx/error.log",
			"/var/log/nginx/access.log",
		}
	case LogSourceWireguard:
		cmd := exec.Command("dmesg", "-T")
		out, err := cmd.Output()
		if err == nil {
			all := string(out)
			var wgLines []string
			for _, l := range strings.Split(all, "\n") {
				if strings.Contains(strings.ToLower(l), "wireguard") {
					wgLines = append(wgLines, l)
				}
			}
			if len(wgLines) > 0 {
				if len(wgLines) > lines {
					wgLines = wgLines[len(wgLines)-lines:]
				}
				return strings.Join(wgLines, "\n"), nil
			}
		}
	}

	for _, path := range candidates {
		if data, err := readLastLines(path, lines); err == nil && len(strings.TrimSpace(data)) > 0 {
			return data, nil
		}
	}
	return "", fmt.Errorf("no log file found for service %s", service)
}

func readLastLines(path string, count int) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	return strings.Join(lines, "\n"), nil
}
