package cfprefer

import "net/netip"

// CloudflareIPv4Ranges is DEFAULT_CF_V4_RANGES from resolve_candidates.py:
// the official Cloudflare IPv4 ranges, used to reject hijacked or
// non-Cloudflare IPs resolved from community CNAMEs or APIs.
var CloudflareIPv4Ranges = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var cfPrefixes []netip.Prefix

func init() {
	for _, r := range CloudflareIPv4Ranges {
		if p, err := netip.ParsePrefix(r); err == nil {
			cfPrefixes = append(cfPrefixes, p)
		}
	}
}

// IsCloudflareIPv4 reports whether ip belongs to an official Cloudflare
// IPv4 range. Invalid strings and IPv6 addresses return false.
func IsCloudflareIPv4(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return false
	}
	for _, p := range cfPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
