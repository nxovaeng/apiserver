package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for xray-panel-server.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Auth     AuthConfig     `yaml:"auth"`
	Log      LogConfig      `yaml:"log"`
	Database DatabaseConfig `yaml:"database"`
	Xray     XrayConfig     `yaml:"xray"`
	Nginx    NginxConfig    `yaml:"nginx"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Listen string `yaml:"listen"`
	Debug  bool   `yaml:"debug"`
}

// AuthConfig holds static Bearer API token authentication settings.
type AuthConfig struct {
	BootstrapTokens   []string `yaml:"bootstrap_tokens"`
	FailLimit         int      `yaml:"fail_limit"`
	FailWindowMinutes int      `yaml:"fail_window_minutes"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level      string `yaml:"level"`
	File       string `yaml:"file"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
	Compress   bool   `yaml:"compress"`
}

// DatabaseConfig holds SQLite database settings.
type DatabaseConfig struct {
	Path string `yaml:"path"`
}

// XrayConfig holds Xray core settings.
type XrayConfig struct {
	BinaryPath string `yaml:"binary_path"`
	ConfigPath string `yaml:"config_path"`
	AssetsPath string `yaml:"assets_path"`
	APIPort    int    `yaml:"api_port"`
	SocketDir  string `yaml:"socket_dir"`
}

// NginxConfig holds Nginx settings.
type NginxConfig struct {
	ConfigDir string `yaml:"config_dir"`
	StreamDir string `yaml:"stream_dir"`
	ReloadCmd string `yaml:"reload_cmd"`
	TestCmd   string `yaml:"test_cmd"`
	CertDir   string `yaml:"cert_dir"`
}

// Load reads configuration from a YAML file and applies safe defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Auth.FailLimit <= 0 {
		c.Auth.FailLimit = 15
	}
	if c.Auth.FailWindowMinutes <= 0 {
		c.Auth.FailWindowMinutes = 5
	}
	if c.Xray.BinaryPath == "" {
		c.Xray.BinaryPath = "/usr/local/bin/xray"
	}
	if c.Xray.ConfigPath == "" {
		c.Xray.ConfigPath = "/usr/local/etc/xray/config.json"
	}
	if c.Xray.AssetsPath == "" {
		c.Xray.AssetsPath = "/usr/local/share/xray"
	}
	if c.Xray.APIPort <= 0 {
		c.Xray.APIPort = 10085
	}
	if c.Xray.SocketDir == "" {
		c.Xray.SocketDir = "/dev/shm"
	}
	if c.Nginx.ReloadCmd == "" {
		c.Nginx.ReloadCmd = "systemctl reload nginx"
	}
	if c.Nginx.TestCmd == "" {
		c.Nginx.TestCmd = "nginx -t"
	}
	if c.Nginx.CertDir == "" {
		c.Nginx.CertDir = "/root/.acme.sh"
	}
}

// Validate checks configuration values for obvious problems.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Server.Listen) == "" {
		return fmt.Errorf("server.listen 不能为空")
	}
	if strings.TrimSpace(c.Database.Path) == "" {
		return fmt.Errorf("database.path 不能为空")
	}
	for i, tok := range c.Auth.BootstrapTokens {
		if strings.TrimSpace(tok) == "" {
			return fmt.Errorf("auth.bootstrap_tokens[%d] 不能为空", i)
		}
	}
	return nil
}

// Default returns default server configuration.
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Listen: "127.0.0.1:8082",
			Debug:  false,
		},
		Auth: AuthConfig{
			BootstrapTokens:   []string{},
			FailLimit:         15,
			FailWindowMinutes: 5,
		},
		Log: LogConfig{
			Level:      "info",
			File:       "/opt/xray-panel/logs/panel.log",
			MaxSize:    100,
			MaxBackups: 7,
			MaxAge:     30,
			Compress:   true,
		},
		Database: DatabaseConfig{
			Path: "/opt/xray-panel/data/panel.db",
		},
		Xray: XrayConfig{
			BinaryPath: "/usr/local/bin/xray",
			ConfigPath: "/usr/local/etc/xray/config.json",
			AssetsPath: "/usr/local/share/xray",
			APIPort:    10085,
			SocketDir:  "/dev/shm",
		},
		Nginx: NginxConfig{
			ConfigDir: "/etc/nginx/conf.d",
			StreamDir: "/etc/nginx/stream.d",
			ReloadCmd: "systemctl reload nginx",
			TestCmd:   "nginx -t",
			CertDir:   "/root/.acme.sh",
		},
	}
}
