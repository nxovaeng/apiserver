package database

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gorml "gorm.io/gorm/logger"

	"xray-panel-server/internal/config"
	applogger "xray-panel-server/internal/logger"
	"xray-panel-server/internal/models"
)

// Init initializes the SQLite database connection.
// The database directory is created with 0700 and the database file itself is
// chmodded to 0600, because it stores secrets (API token hashes, WireGuard
// private keys, outbound passwords). ":memory:" databases are exempt.
func Init(dbPath string) (*gorm.DB, error) {
	if dbPath != ":memory:" {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		// MkdirAll does not tighten an already-existing directory.
		if err := os.Chmod(dir, 0700); err != nil {
			return nil, err
		}
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gorml.Default.LogMode(gorml.Silent),
	})
	if err != nil {
		return nil, err
	}

	if dbPath != ":memory:" {
		if err := os.Chmod(dbPath, 0600); err != nil {
			return nil, err
		}
	}

	return db, nil
}

// Migrate runs auto-migrations for all server models.
func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&models.APIToken{},
		&models.User{},
		&models.Domain{},
		&models.Inbound{},
		&models.Outbound{},
		&models.RoutingRule{},
		&models.NginxConfig{},
		&models.Setting{},
		&models.WGServerConfig{},
		&models.WGPeer{},
	); err != nil {
		return err
	}

	// Reality 入站已移除：停用历史上建的 reality 域名。行保留在库里（可手动删除
	// 或改建为 direct/cdn），仅不再参与启用逻辑。AutoMigrate 不删列，残留的
	// server_name/fingerprint/short_id/private_key/public_key 列随之成为孤儿列。
	if res := db.Model(&models.Domain{}).Where("type = ?", "reality").Update("enabled", false); res.Error != nil {
		return res.Error
	} else if res.RowsAffected > 0 {
		applogger.Warn("已停用 %d 个历史 Reality 域名（入站 Reality 已移除），请手动删除或改建为 direct/cdn", res.RowsAffected)
	}

	return nil
}

// SeedResult reports whether an initial API token was seeded during Seed.
type SeedResult struct {
	InitialTokenPlaintext string
	InitialTokenPrefix    string
}

// Seed populates default settings, routing rules, WireGuard config, and an initial API token when empty.
// If an initial API token is generated, its plaintext is returned in SeedResult and printed once to stdout
// (never written to log files).
func Seed(db *gorm.DB, cfg *config.Config) (*SeedResult, error) {
	res := &SeedResult{}

	// 1. Seed initial API token if no tokens exist and no static bootstrap tokens are configured
	var tokenCount int64
	if err := db.Model(&models.APIToken{}).Count(&tokenCount).Error; err != nil {
		return nil, err
	}
	hasBootstrap := cfg != nil && len(cfg.Auth.BootstrapTokens) > 0
	if tokenCount == 0 && !hasBootstrap {
		raw, prefix, hash, salt, err := models.GenerateAPIToken()
		if err != nil {
			return nil, err
		}
		tok := &models.APIToken{
			Name:        "default",
			TokenPrefix: prefix,
			TokenHash:   hash,
			Salt:        salt,
		}
		if err := db.Create(tok).Error; err != nil {
			return nil, err
		}
		res.InitialTokenPlaintext = raw
		res.InitialTokenPrefix = prefix

		applogger.Info("已创建默认静态 API Token (name=default, prefix=%s)", prefix)
		// Print plaintext ONLY to stdout once, never to log files
		fmt.Printf("\n========================================\n")
		fmt.Printf("🔑 初始 API Token 已生成 (仅显示一次，请立即保存):\n")
		fmt.Printf("   %s\n", raw)
		fmt.Printf("========================================\n\n")
	}

	// 2. Default Server-mode settings (create missing keys without overwriting existing values)
	for _, s := range models.DefaultSettings() {
		var existing models.Setting
		if err := db.Where("key = ?", s.Key).First(&existing).Error; err != nil {
			if err := db.Create(&s).Error; err != nil {
				return nil, err
			}
			applogger.Info("新增默认配置项: %s = %s", s.Key, s.Value)
		}
	}

	// 3. Default routing rules
	var ruleCount int64
	if err := db.Model(&models.RoutingRule{}).Count(&ruleCount).Error; err != nil {
		return nil, err
	}
	if ruleCount == 0 {
		for _, r := range models.DefaultRoutingRules() {
			rule := r
			if err := db.Create(&rule).Error; err != nil {
				return nil, err
			}
		}
	}

	// 4. Default WireGuard server configuration
	if _, err := models.GetWGServerConfig(db); err != nil {
		applogger.Error("Failed to initialize default WireGuard server configuration: %v", err)
	}

	return res, nil
}
