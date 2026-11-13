package service_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-panel-server/internal/database"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/nginx"
	"xray-panel-server/internal/service"
)

func setupSpeedtest(t *testing.T) (*service.SpeedtestService, string) {
	t.Helper()
	db, cfg, tmpDir := setupTestEnv(t)
	if _, err := database.Seed(db, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Speedtest.FileDir = filepath.Join(tmpDir, "speedtest")
	nginxGen := nginx.NewGenerator(cfg.Nginx.ConfigDir, cfg.Nginx.StreamDir)
	nginxGen.SetReloadCmd("true")
	return service.NewSpeedtestService(db, cfg, nginxGen), tmpDir
}

func TestSpeedtestStartStop(t *testing.T) {
	svc, tmpDir := setupSpeedtest(t)

	st, err := svc.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled || st.Domain != "" || st.SubPath != "/speedtest" || st.FileExists {
		t.Fatalf("initial status = %+v", st)
	}

	// Cannot start without a domain.
	if _, err := svc.Start(); err == nil {
		t.Fatalf("Start without a domain must fail")
	}

	// Save domain + a non-default (unguessable) subpath.
	st, err = svc.UpdateSettings(dto.UpdateSpeedtestRequest{
		Domain:  strPtr("jp-speed.example.com"),
		SubPath: strPtr("/x7f9k2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Domain != "jp-speed.example.com" || st.SubPath != "/x7f9k2" {
		t.Fatalf("settings not saved: %+v", st)
	}
	if st.URL != "" {
		t.Fatalf("URL must be empty while stopped, got %q", st.URL)
	}

	// Start: file + nginx config appear, URL is exposed.
	st, err = svc.Start()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Enabled || !st.FileExists || st.FileSize != 50*1024*1024 {
		t.Fatalf("started status = %+v", st)
	}
	if st.URL != "https://jp-speed.example.com/x7f9k2/50mb.bin" {
		t.Fatalf("URL = %q", st.URL)
	}
	confPath := filepath.Join(tmpDir, "nginx", "conf.d", "speedtest.conf")
	conf, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("nginx config missing: %v", err)
	}
	for _, want := range []string{"server_name jp-speed.example.com;", "location = /x7f9k2/50mb.bin", "Managed by Xray Panel"} {
		if !strings.Contains(string(conf), want) {
			t.Fatalf("nginx config missing %q:\n%s", want, conf)
		}
	}

	// Changing the subpath while enabled rewrites the config in place.
	st, err = svc.UpdateSettings(dto.UpdateSpeedtestRequest{SubPath: strPtr("/z3q8w")})
	if err != nil {
		t.Fatal(err)
	}
	if st.URL != "https://jp-speed.example.com/z3q8w/50mb.bin" {
		t.Fatalf("URL after subpath change = %q", st.URL)
	}
	conf, err = os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "location = /z3q8w/50mb.bin") || strings.Contains(string(conf), "/x7f9k2/") {
		t.Fatalf("nginx config not rewritten for new subpath:\n%s", conf)
	}

	// Stop: config removed, origin disabled, file kept for a fast restart.
	st, err = svc.Stop()
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled || st.URL != "" || st.ConfigPath != "" {
		t.Fatalf("stopped status = %+v", st)
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Fatalf("nginx config must be removed after Stop")
	}
	if fi, err := os.Stat(filepath.Join(tmpDir, "speedtest", "50mb.bin")); err != nil || fi.Size() != 50*1024*1024 {
		t.Fatalf("test file must stay on disk after Stop: %v", err)
	}

	// Starting again reuses the existing file.
	if _, err := svc.Start(); err != nil {
		t.Fatal(err)
	}
}

func TestSpeedtestValidation(t *testing.T) {
	svc, _ := setupSpeedtest(t)

	for _, bad := range []string{"../x", "/a/../b", "/a b", "no-leading-slash-is-ok-but-check", "/"} {
		_, err := svc.UpdateSettings(dto.UpdateSpeedtestRequest{SubPath: strPtr(bad)})
		if bad == "no-leading-slash-is-ok-but-check" {
			// Missing leading slash is auto-fixed, not an error.
			if err != nil {
				t.Errorf("subpath %q must be auto-fixed, got error: %v", bad, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("subpath %q must be rejected", bad)
		}
	}

	for _, bad := range []string{"not a domain", "http://jp-speed.example.com", "jp-speed", ""} {
		_, err := svc.UpdateSettings(dto.UpdateSpeedtestRequest{Domain: strPtr(bad)})
		if bad == "" {
			// Clearing the domain is allowed; Start will refuse later.
			if err != nil {
				t.Errorf("clearing domain must be allowed, got: %v", err)
			}
			continue
		}
		if err == nil {
			t.Errorf("domain %q must be rejected", bad)
		}
	}
}

func TestSpeedtestHTTPSConfig(t *testing.T) {
	_, tmpDir := setupSpeedtest(t)
	db, cfg, _ := setupTestEnv(t)
	if _, err := database.Seed(db, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Speedtest.FileDir = filepath.Join(tmpDir, "speedtest")
	nginxGen := nginx.NewGenerator(filepath.Join(tmpDir, "nginx", "conf.d"), filepath.Join(tmpDir, "nginx", "stream.d"))
	nginxGen.SetReloadCmd("true")
	svc := service.NewSpeedtestService(db, cfg, nginxGen)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")
	_ = os.WriteFile(certPath, []byte("CERT"), 0644)
	_ = os.WriteFile(keyPath, []byte("KEY"), 0600)

	// Insert domain with certificate
	dom := models.Domain{
		Domain:   "speed.example.com",
		CertPath: certPath,
		KeyPath:  keyPath,
		Enabled:  true,
	}
	db.Create(&dom)

	_, err := svc.UpdateSettings(dto.UpdateSpeedtestRequest{
		Domain:  strPtr("speed.example.com"),
		SubPath: strPtr("/speedtest"),
	})
	if err != nil {
		t.Fatal(err)
	}

	st, err := svc.Start()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Enabled {
		t.Fatalf("expected enabled")
	}

	confPath := filepath.Join(tmpDir, "nginx", "conf.d", "speedtest.conf")
	confBytes, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	confStr := string(confBytes)

	// Verify HTTPS directives
	for _, expected := range []string{
		"listen 443 ssl;",
		"server_name speed.example.com;",
		"ssl_certificate " + certPath,
		"ssl_certificate_key " + keyPath,
		"return 301 https://$host$request_uri;",
		"location = /speedtest/50mb.bin",
		"Access-Control-Allow-Origin",
	} {
		if !strings.Contains(confStr, expected) {
			t.Errorf("expected nginx conf to contain %q, but got:\n%s", expected, confStr)
		}
	}
}
