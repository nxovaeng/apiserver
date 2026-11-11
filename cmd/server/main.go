package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"gorm.io/gorm"

	"xray-panel-server/internal/api"
	"xray-panel-server/internal/config"
	"xray-panel-server/internal/database"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/logger"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/nginx"
	"xray-panel-server/internal/service"
)

var (
	Version   = "0.1.0"
	BuildTime = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		runServer(nil)
		return
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("xray-panel-server version %s (build: %s)\n", Version, BuildTime)
	case "server", "start", "run":
		runServer(os.Args[2:])
	case "token":
		cmdToken(os.Args[2:])
	case "nginx":
		cmdNginx(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		if os.Args[1] != "" && os.Args[1][0] == '-' {
			runServer(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`xray-panel-server v%s - Headless Xray Panel API Server

Usage:
  xray-panel-server [command] [flags]

Commands:
  server, start, run    Start the headless API server (default)
  token                 Manage static Bearer API tokens (create / list / revoke)
  nginx                 Manage Nginx reverse proxy configs (sync / reload / panel)
  version               Show version information
  help                  Show help information

Examples:
  xray-panel-server server --config /opt/xray-panel/config.yaml
  xray-panel-server token create --name "macbook" --days 365
  xray-panel-server token list
  xray-panel-server token revoke --id <token-id>
  xray-panel-server nginx sync
  xray-panel-server nginx reload
  xray-panel-server nginx panel -d panel.example.com -cert /path/cert.pem -key /path/key.pem
`, Version)
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := fs.String("config", "", "配置文件路径")
	_ = fs.Parse(args)

	cfg, db := initSystem(*configPath)

	if err := database.Migrate(db); err != nil {
		logger.Fatal("数据库迁移失败: %v", err)
	}

	if _, err := database.Seed(db, cfg); err != nil {
		logger.Fatal("数据库初始化失败: %v", err)
	}

	// 证书续期 worker：每天检查一次证书过期时间，30 天内过期的按原签发
	// 路径自动续期（见 internal/service/lego_acme.go）。失败只记日志，
	// 不阻塞启动、不影响其它任务。
	domainSvc := service.NewDomainService(db, cfg)
	domainSvc.StartCertRenewalWorker(context.Background(), service.CertRenewalInterval)

	logger.Info("正在启动 xray-panel-server v%s，监听地址: %s", Version, cfg.Server.Listen)
	srv := api.NewServer(cfg, db, Version)
	if err := srv.Run(); err != nil {
		logger.Fatal("服务器启动失败: %v", err)
	}
}

func cmdToken(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: xray-panel-server token [create|list|revoke] [flags]")
		os.Exit(1)
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "create":
		fs := flag.NewFlagSet("token create", flag.ExitOnError)
		name := fs.String("name", "", "Token 名称 (必需)")
		days := fs.Int("days", 0, "有效天数 (0 表示永久)")
		configPath := fs.String("config", "", "配置文件路径")
		_ = fs.Parse(rest)

		if *name == "" {
			fmt.Fprintln(os.Stderr, "错误: --name 是必需参数")
			os.Exit(1)
		}

		cfg, db := initCLI(*configPath)
		_ = database.Migrate(db)

		tokSvc := service.NewTokenService(db, cfg, Version)
		var expPtr *int
		if *days > 0 {
			expPtr = days
		}
		res, err := tokSvc.Create(dto.CreateTokenRequest{Name: *name, ExpiresDays: expPtr})
		if err != nil {
			fmt.Fprintf(os.Stderr, "创建 Token 失败: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("ID:     %s\n", res.Token.ID)
		fmt.Printf("Name:   %s\n", res.Token.Name)
		fmt.Printf("Prefix: %s\n", res.Token.TokenPrefix)
		if res.Token.ExpiresAt != nil {
			fmt.Printf("Expiry: %s\n", res.Token.ExpiresAt.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Println("Expiry: never")
		}
		fmt.Printf("Token:  %s\n", res.PlaintextToken)
		fmt.Println("⚠️ 请立即保存此明文 Token，系统不会再次展示。")

	case "list":
		fs := flag.NewFlagSet("token list", flag.ExitOnError)
		configPath := fs.String("config", "", "配置文件路径")
		_ = fs.Parse(rest)

		cfg, db := initCLI(*configPath)
		_ = database.Migrate(db)

		tokSvc := service.NewTokenService(db, cfg, Version)
		res, err := tokSvc.List()
		if err != nil {
			fmt.Fprintf(os.Stderr, "查询 Token 失败: %v\n", err)
			os.Exit(1)
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tPREFIX\tREVOKED\tEXPIRES_AT\tLAST_IP\tLAST_USED_AT")
		for _, t := range res.Tokens {
			exp := "never"
			if t.ExpiresAt != nil {
				exp = t.ExpiresAt.Format("2006-01-02")
			}
			lastUsed := "-"
			if t.LastUsedAt != nil {
				lastUsed = t.LastUsedAt.Format("2006-01-02 15:04")
			}
			lastIP := t.LastIP
			if lastIP == "" {
				lastIP = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\t%s\t%s\n",
				t.ID, t.Name, t.TokenPrefix, t.Revoked, exp, lastIP, lastUsed)
		}
		_ = w.Flush()

	case "revoke":
		fs := flag.NewFlagSet("token revoke", flag.ExitOnError)
		id := fs.String("id", "", "Token ID (必需)")
		purge := fs.Bool("purge", false, "彻底删除记录（默认仅标记吊销）")
		configPath := fs.String("config", "", "配置文件路径")
		_ = fs.Parse(rest)

		if *id == "" {
			fmt.Fprintln(os.Stderr, "错误: --id 是必需参数")
			os.Exit(1)
		}

		cfg, db := initCLI(*configPath)
		_ = database.Migrate(db)

		tokSvc := service.NewTokenService(db, cfg, Version)
		res, err := tokSvc.RevokeOrDelete(*id, *purge)
		if err != nil {
			fmt.Fprintf(os.Stderr, "吊销 Token 失败: %v\n", err)
			os.Exit(1)
		}
		if res.Deleted {
			fmt.Printf("Token %s 已彻底删除\n", res.ID)
		} else {
			fmt.Printf("Token %s 已吊销\n", res.ID)
		}

	default:
		fmt.Fprintf(os.Stderr, "未知 token 子命令: %s\n", sub)
		os.Exit(1)
	}
}

func cmdNginx(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: xray-panel-server nginx [sync|reload|panel] [flags]")
		os.Exit(1)
	}

	action := args[0]
	rest := args[1:]

	switch action {
	case "sync":
		fs := flag.NewFlagSet("nginx sync", flag.ExitOnError)
		configPath := fs.String("config", "", "配置文件路径")
		_ = fs.Parse(rest)

		cfg, db := initSystem(*configPath)
		ng := nginx.NewGenerator(cfg.Nginx.ConfigDir, cfg.Nginx.StreamDir)
		ng.SetDB(db)
		ng.SetSocketDir(cfg.Xray.SocketDir)
		ng.SetPanelListen(cfg.Server.Listen)

		var inbounds []models.Inbound
		if err := db.Preload("Domain").Where("enabled = ?", true).Find(&inbounds).Error; err != nil {
			logger.Fatal("查询入站配置失败: %v", err)
		}
		if err := ng.GenerateHTTPConfig(inbounds); err != nil {
			logger.Fatal("生成 Nginx 配置失败: %v", err)
		}
		fmt.Println("Nginx 配置已同步生成")

	case "reload":
		fs := flag.NewFlagSet("nginx reload", flag.ExitOnError)
		configPath := fs.String("config", "", "配置文件路径")
		_ = fs.Parse(rest)

		cfg, _ := initSystem(*configPath)
		ng := nginx.NewGenerator(cfg.Nginx.ConfigDir, cfg.Nginx.StreamDir)
		if cfg.Nginx.ReloadCmd != "" {
			ng.SetReloadCmd(cfg.Nginx.ReloadCmd)
		}
		if err := ng.Reload(); err != nil {
			logger.Fatal("重载 Nginx 失败: %v", err)
		}
		fmt.Println("Nginx 已重载")

	case "panel":
		fs := flag.NewFlagSet("nginx panel", flag.ExitOnError)
		domain := fs.String("d", "", "面板域名 (必需)")
		domainLong := fs.String("domain", "", "面板域名 (必需)")
		certPath := fs.String("cert", "", "SSL 证书路径 (必需)")
		keyPath := fs.String("key", "", "SSL 密钥路径 (必需)")
		configPath := fs.String("config", "", "配置文件路径")
		_ = fs.Parse(rest)

		dom := *domain
		if dom == "" {
			dom = *domainLong
		}
		if dom == "" || *certPath == "" || *keyPath == "" {
			fmt.Fprintln(os.Stderr, "错误: 域名、证书路径和密钥路径都是必需的")
			os.Exit(1)
		}

		cfg, _ := initSystem(*configPath)
		ng := nginx.NewGenerator(cfg.Nginx.ConfigDir, cfg.Nginx.StreamDir)
		if err := ng.GeneratePanelConfig(dom, *certPath, *keyPath, cfg.Server.Listen); err != nil {
			logger.Fatal("生成面板 Nginx 配置失败: %v", err)
		}
		fmt.Println("面板 Nginx 配置已生成")

	default:
		fmt.Fprintf(os.Stderr, "未知 nginx 操作: %s\n", action)
		os.Exit(1)
	}
}

func initSystem(configPath string) (*config.Config, *gorm.DB) {
	return initWithLogOverride(configPath, false)
}

func initCLI(configPath string) (*config.Config, *gorm.DB) {
	return initWithLogOverride(configPath, true)
}

func initWithLogOverride(configPath string, quiet bool) (*config.Config, *gorm.DB) {
	explicit := configPath != ""
	if !explicit {
		foundPath, found := resolveDefaultConfigPath()
		if !found {
			// install.sh guarantees a real config at /opt/xray-panel/config.yaml
			// (write_config creates it, chmod 600, and systemd runs with
			// --config pointing at it). A missing config therefore means the
			// server was never installed, not that defaults should apply.
			log.Fatalf("未找到配置文件 (已查找 conf/config.yaml 与 /opt/xray-panel/config.yaml)，请先运行 scripts/install.sh 安装，或用 --config 指定配置文件路径")
		}
		configPath = foundPath
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		if explicit {
			log.Fatalf("无法加载 --config 指定的配置文件 (%s)，请检查路径与文件内容: %v", configPath, err)
		}
		log.Fatalf("无法加载配置文件 (%s)，请检查文件内容: %v", configPath, err)
	}

	logCfg := cfg.Log
	if quiet {
		logCfg.Level = "error"
		logCfg.File = ""
	}
	if err := logger.Init(&logCfg); err != nil {
		log.Fatalf("初始化日志失败: %v", err)
	}

	db, err := database.Init(cfg.Database.Path)
	if err != nil {
		logger.Fatal("初始化数据库失败: %v", err)
	}

	return cfg, db
}

// resolveDefaultConfigPath returns the first existing candidate config path.
// conf/config.yaml.example is deliberately NOT a candidate: it is documentation,
// never a live configuration.
func resolveDefaultConfigPath() (string, bool) {
	candidates := []string{
		"conf/config.yaml",
		"/opt/xray-panel/config.yaml",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, true
		}
	}
	return "", false
}
