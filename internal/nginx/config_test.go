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
