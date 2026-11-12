package cfprefer_test

import (
	"testing"

	"xray-panel-server/internal/cfprefer"
)

func TestIsCloudflareIPv4(t *testing.T) {
	inRange := []string{
		"104.16.0.1", "104.23.255.255", // 104.16.0.0/13
		"104.24.0.1", "104.27.255.255", // 104.24.0.0/14
		"172.64.0.1", "172.71.255.255", // 172.64.0.0/13
		"131.0.72.5",   // 131.0.72.0/22
		"103.21.244.1", // 103.21.244.0/22
		"173.245.48.1", // 173.245.48.0/20
		"162.158.0.1",  // 162.158.0.0/15
	}
	for _, ip := range inRange {
		if !cfprefer.IsCloudflareIPv4(ip) {
			t.Errorf("%s must be in a Cloudflare range", ip)
		}
	}

	outOfRange := []string{
		"8.8.8.8", "1.1.1.1",
		"104.15.255.255", // just below 104.16.0.0/13
		"104.28.0.1",     // just above 104.24.0.0/14
		"172.63.255.255", // just below 172.64.0.0/13
		"172.72.0.1",     // just above 172.64.0.0/13
		"2001:db8::1",    // IPv6 is not an IPv4 range
		"not-an-ip",
		"",
	}
	for _, ip := range outOfRange {
		if cfprefer.IsCloudflareIPv4(ip) {
			t.Errorf("%q must not be in a Cloudflare range", ip)
		}
	}
}
