package nginx

import (
	"bytes"
	"strings"
	"testing"
)

func TestPanelConfigTmpl(t *testing.T) {
	data := panelTmplData{
		Domain:   "panel.example.com",
		CertPath: "/etc/ssl/panel.crt",
		KeyPath:  "/etc/ssl/panel.key",
		Port:     "8082",
	}

	var buf bytes.Buffer
	if err := panelConfigTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("failed to execute panelConfigTmpl: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "ssl http2") {
		t.Errorf("expected no deprecated 'ssl http2' in output")
	}
	if !strings.Contains(output, "listen 443 ssl;") || !strings.Contains(output, "http2 on;") {
		t.Errorf("expected modern ssl + http2 directives")
	}
	if !strings.Contains(output, "proxy_pass http://127.0.0.1:8082;") {
		t.Errorf("expected proxy_pass in output")
	}
}

func TestInboundsConfigTmpl(t *testing.T) {
	data := inboundsTmplData{
		Domain:   "node.example.com",
		HasCert:  true,
		CertPath: "/etc/ssl/node.crt",
		KeyPath:  "/etc/ssl/node.key",
		Inbounds: []inboundLocationData{
			{
				Tag:         "vless-grpc",
				IsGRPC:      true,
				ServiceName: "mygrpc",
				Upstream:    "grpc://127.0.0.1:10001",
			},
			{
				Tag:      "vless-ws",
				IsWS:     true,
				Path:     "/ws-path",
				Upstream: "http://127.0.0.1:10002",
			},
		},
	}

	var buf bytes.Buffer
	if err := inboundsConfigTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("failed to execute inboundsConfigTmpl: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "location /mygrpc") || !strings.Contains(output, "location /ws-path") {
		t.Errorf("expected grpc and ws locations in output")
	}
}

func TestSubConfigTmplExposesOnlySubPath(t *testing.T) {
	data := subTmplData{
		Domain:      "sub.example.com",
		CertPath:    "/etc/ssl/sub.crt",
		KeyPath:     "/etc/ssl/sub.key",
		SubPath:     "/d",
		PanelTarget: "127.0.0.1:8082",
	}

	var buf bytes.Buffer
	if err := subConfigTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("failed to execute subConfigTmpl: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "location ^~ /d/") {
		t.Errorf("expected subscription prefix location in output: %s", out)
	}
	if !strings.Contains(out, "proxy_pass http://127.0.0.1:8082;") {
		t.Errorf("expected loopback proxy_pass in output: %s", out)
	}
	if !strings.Contains(out, "return 404;") {
		t.Errorf("expected default location / to return 404 so /api is never exposed")
	}
}

func TestAPIConfigTmplExposesAPIWithSSEAndBlocksRoot(t *testing.T) {
	data := subTmplData{
		Domain:      "api.example.com",
		CertPath:    "/etc/ssl/api.crt",
		KeyPath:     "/etc/ssl/api.key",
		ExposeAPI:   true,
		PanelTarget: "127.0.0.1:8082",
	}

	var buf bytes.Buffer
	if err := subConfigTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("failed to execute subConfigTmpl for API: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "location ^~ /api/v1/") {
		t.Errorf("expected /api/v1/ location in output: %s", out)
	}
	if !strings.Contains(out, "proxy_buffering off;") || !strings.Contains(out, "proxy_read_timeout 1h;") {
		t.Errorf("expected SSE proxy directives in API Nginx config: %s", out)
	}
	if strings.Contains(out, "location ^~ /d/") {
		t.Errorf("did not expect subscription location when SubPath is empty: %s", out)
	}
	if !strings.Contains(out, "return 404;") {
		t.Errorf("expected default root to return 404")
	}
}

func TestConfigGeneratorTestConfigBehavior(t *testing.T) {
	tmpDir := t.TempDir()
	gen := NewGenerator(tmpDir, tmpDir)

	// Temp dir with default "nginx -t" must skip host /etc/nginx/nginx.conf check
	if err := gen.TestConfig(); err != nil {
		t.Fatalf("expected temp dir TestConfig to skip host nginx -t safely, got: %v", err)
	}

	// Explicit failing command must return error
	gen.SetTestCmd("false")
	if err := gen.TestConfig(); err == nil {
		t.Fatalf("expected failing explicit testCmd to return error")
	}

	// Explicit "true" passes
	gen.SetTestCmd("true")
	if err := gen.TestConfig(); err != nil {
		t.Fatalf("expected 'true' testCmd to succeed, got: %v", err)
	}
}
