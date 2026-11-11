package service

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"math/big"
	"net"
	"strings"

	"gorm.io/gorm"

	"xray-panel-server/internal/models"
)

func resolvePublicHost(db *gorm.DB) string {
	if host := models.GetServerPublicHost(db); host != "" {
		return cleanHost(host)
	}
	if sub := models.GetSubDomain(db); sub != "" {
		return cleanHost(sub)
	}
	return ""
}

func cleanHost(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if idx := strings.Index(raw, "/"); idx != -1 {
		raw = raw[:idx]
	}
	if strings.Contains(raw, ":") {
		if h, _, err := net.SplitHostPort(raw); err == nil {
			return h
		}
	}
	return raw
}

func randomHex(numBytes int) string {
	buf := make([]byte, numBytes)
	_, _ = cryptorand.Read(buf)
	return hex.EncodeToString(buf)
}

func randomPort(min, max int) int {
	if max <= min {
		return min
	}
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return int(n.Int64()) + min
}

func generateRandomSubdomain() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	lengthBig, _ := cryptorand.Int(cryptorand.Reader, big.NewInt(3))
	length := int(lengthBig.Int64()) + 6

	b := make([]byte, length)
	maxIdx := big.NewInt(int64(len(charset)))
	for i := range b {
		n, _ := cryptorand.Int(cryptorand.Reader, maxIdx)
		b[i] = charset[n.Int64()]
	}
	return string(b)
}
