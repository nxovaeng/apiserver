package nginx

import "text/template"

type panelTmplData struct {
	Domain   string
	CertPath string
	KeyPath  string
	Port     string
}

type inboundLocationData struct {
	Tag          string
	ActualDomain string
	IsGRPC       bool
	IsXHTTP      bool
	IsWS         bool
	ServiceName  string
	Path         string
	Upstream     string
}

type inboundsTmplData struct {
	Domain            string
	HasCert           bool
	CertPath          string
	KeyPath           string
	SubPath           string
	ExposeAPI         bool
	PanelTarget       string
	SpeedtestSubPath  string
	SpeedtestFilePath string
	Inbounds          []inboundLocationData
}

type subTmplData struct {
	Domain            string
	CertPath          string
	KeyPath           string
	SubPath           string
	ExposeAPI         bool
	PanelTarget       string
	SpeedtestSubPath  string
	SpeedtestFilePath string
}

const panelConfigTmplStr = `server {
    listen 80;
    listen [::]:80;
    server_name {{.Domain}};
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name {{.Domain}};

    ssl_certificate {{.CertPath}};
    ssl_certificate_key {{.KeyPath}};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://127.0.0.1:{{.Port}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
`

const inboundsConfigTmplStr = `server {
    listen 80;
    listen [::]:80;
    server_name {{.Domain}};
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name {{.Domain}};
{{if .HasCert}}
    ssl_certificate {{.CertPath}};
    ssl_certificate_key {{.KeyPath}};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;{{end}}
{{range .Inbounds}}
{{if .IsGRPC}}    # gRPC: {{.Tag}}{{if .ActualDomain}} (subdomain: {{.ActualDomain}}){{end}}
    location /{{.ServiceName}} {
        if ($content_type !~ "application/grpc") {
            return 404;
        }
        grpc_pass {{.Upstream}};
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
{{else if .IsXHTTP}}    # XHTTP: {{.Tag}}{{if .ActualDomain}} (subdomain: {{.ActualDomain}}){{end}}
    location {{.Path}} {
        proxy_pass {{.Upstream}};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_request_buffering off;
        client_max_body_size 0;
        client_body_timeout 2h;
        proxy_read_timeout 2h;
        proxy_send_timeout 2h;
        keepalive_timeout 2h;
    }{{else if .IsWS}}    # WebSocket: {{.Tag}}{{if .ActualDomain}} (subdomain: {{.ActualDomain}}){{end}}
    location {{.Path}} {
        proxy_redirect off;
        proxy_pass {{.Upstream}};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
{{end}}{{end}}{{if .ExposeAPI}}
    # Control-plane API reverse proxy (HTTPS / CDN compatible, SSE buffering disabled)
    location ^~ /api/v1/ {
        proxy_pass http://{{.PanelTarget}};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
        client_max_body_size 32m;
    }
{{end}}{{if .SubPath}}
    # Public subscription proxy (only subscription prefix exposed; /api remains private unless ExposeAPI is enabled)
    location ^~ {{.SubPath}}/ {
        proxy_pass http://{{.PanelTarget}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
{{end}}{{if .SpeedtestFilePath}}
    # Speedtest origin 50MB file
    location = {{.SpeedtestSubPath}}/50mb.bin {
        alias {{.SpeedtestFilePath}};
        gzip off;
        add_header Cache-Control "no-store";
        add_header Access-Control-Allow-Origin "*";
    }
{{end}}
    location / {
        root /var/www/html;
        index index.html;
        try_files $uri $uri/ =404;
    }
}
`

const subConfigTmplStr = `server {
    listen 80;
    listen [::]:80;
    server_name {{.Domain}};
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name {{.Domain}};

    ssl_certificate {{.CertPath}};
    ssl_certificate_key {{.KeyPath}};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
{{if .ExposeAPI}}
    # Control-plane API reverse proxy (HTTPS / CDN compatible, SSE buffering disabled)
    location ^~ /api/v1/ {
        proxy_pass http://{{.PanelTarget}};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
        client_max_body_size 32m;
    }
{{end}}{{if .SubPath}}
    # Public subscription endpoint proxy
    location ^~ {{.SubPath}}/ {
        proxy_pass http://{{.PanelTarget}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
{{end}}{{if .SpeedtestFilePath}}
    # Speedtest origin 50MB file
    location = {{.SpeedtestSubPath}}/50mb.bin {
        alias {{.SpeedtestFilePath}};
        gzip off;
        add_header Cache-Control "no-store";
        add_header Access-Control-Allow-Origin "*";
    }
{{end}}
    location / {
        return 404;
    }
}
`

var (
	panelConfigTmpl    = template.Must(template.New("panel").Parse(panelConfigTmplStr))
	inboundsConfigTmpl = template.Must(template.New("inbounds").Parse(inboundsConfigTmplStr))
	subConfigTmpl      = template.Must(template.New("subscription").Parse(subConfigTmplStr))
)
