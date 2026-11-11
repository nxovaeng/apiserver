package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"xray-panel-server/internal/models"
)

// ParseShareLink parses a vmess://, vless://, or trojan:// share link and returns an Outbound.
func ParseShareLink(link string) (*models.Outbound, error) {
	link = strings.TrimSpace(link)
	if strings.HasPrefix(link, "vmess://") {
		return parseVMess(link)
	}
	if strings.HasPrefix(link, "vless://") {
		return parseURLFormat(link, models.OutboundVLESS)
	}
	if strings.HasPrefix(link, "trojan://") {
		return parseURLFormat(link, models.OutboundTrojan)
	}
	return nil, fmt.Errorf("不支持或无效的分享链接格式")
}

func parseVMess(link string) (*models.Outbound, error) {
	b64 := strings.TrimPrefix(link, "vmess://")
	if m := len(b64) % 4; m != 0 {
		b64 += strings.Repeat("=", 4-m)
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("VMess Base64 解码失败: %v", err)
		}
	}

	var payload struct {
		V    string      `json:"v"`
		Ps   string      `json:"ps"`
		Add  string      `json:"add"`
		Port interface{} `json:"port"`
		Id   string      `json:"id"`
		Aid  interface{} `json:"aid"`
		Scy  string      `json:"scy"`
		Net  string      `json:"net"`
		Type string      `json:"type"`
		Host string      `json:"host"`
		Path string      `json:"path"`
		Tls  string      `json:"tls"`
		Sni  string      `json:"sni"`
		Alpn string      `json:"alpn"`
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("VMess JSON 解析失败: %v", err)
	}

	outbound := &models.Outbound{
		Type:          models.OutboundVMess,
		Tag:           "vmess-" + payload.Add,
		Remark:        payload.Ps,
		Server:        payload.Add,
		UUID:          payload.Id,
		Security:      payload.Scy,
		Network:       payload.Net,
		HeaderType:    payload.Type,
		RequestHost:   payload.Host,
		Path:          payload.Path,
		TLS:           payload.Tls == "tls",
		TLSServerName: payload.Sni,
		TLSALPN:       payload.Alpn,
		Enabled:       true,
	}

	if outbound.Security == "" {
		outbound.Security = "auto"
	}

	switch v := payload.Port.(type) {
	case float64:
		outbound.Port = int(v)
	case string:
		if p, err := strconv.Atoi(v); err == nil {
			outbound.Port = p
		}
	}

	return outbound, nil
}

func parseURLFormat(link string, outboundType models.OutboundType) (*models.Outbound, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("URL 解析失败: %v", err)
	}

	outbound := &models.Outbound{
		Type:    outboundType,
		Server:  u.Hostname(),
		Remark:  u.Fragment,
		Enabled: true,
	}

	if portStr := u.Port(); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			outbound.Port = p
		}
	}

	if outboundType == models.OutboundVLESS {
		outbound.UUID = u.User.Username()
	} else if outboundType == models.OutboundTrojan {
		outbound.TrojanPassword = u.User.Username()
	}

	q := u.Query()
	outbound.Network = q.Get("type")
	outbound.Flow = q.Get("flow")
	outbound.Security = q.Get("encryption")
	if outbound.Security == "" && outboundType == models.OutboundVLESS {
		outbound.Security = "none"
	}

	if sec := q.Get("security"); sec == "tls" || sec == "reality" {
		outbound.TLS = true
		if sec == "reality" {
			outbound.Reality = true
			outbound.RealityPubKey = q.Get("pbk")
			outbound.RealityShortID = q.Get("sid")
			outbound.RealitySNI = q.Get("sni")
		} else {
			outbound.TLSServerName = q.Get("sni")
			outbound.TLSALPN = q.Get("alpn")
		}
	}

	outbound.Path = q.Get("path")
	outbound.RequestHost = q.Get("host")
	outbound.HeaderType = q.Get("headerType")
	outbound.ServiceName = q.Get("serviceName")
	outbound.Tag = string(outboundType) + "-" + outbound.Server

	return outbound, nil
}
