package proton

// Session represents a stored Proton VPN session.
type Session struct {
	AccessToken   string `json:"accessToken"`
	RefreshToken  string `json:"refreshToken,omitempty"`
	UID           string `json:"uid"`
	UserID        string `json:"userId,omitempty"`
	MaxTier       int    `json:"maxTier"`
	WGPrivateKey  string `json:"wgPrivateKey,omitempty"`
	WGCertificate string `json:"wgCertificate,omitempty"`
	CertExpiresAt int64  `json:"certExpiresAt,omitempty"`
	AuthMode      string `json:"authMode"`
	UpdatedAt     int64  `json:"updatedAt"`
}

// Server represents a Proton VPN server entry.
type Server struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Country         string  `json:"country"`
	City            string  `json:"city,omitempty"`
	Tier            int     `json:"tier"`
	Score           float64 `json:"score"`
	Load            int     `json:"load"`
	EntryIP         string  `json:"entryIp"`
	X25519PublicKey string  `json:"x25519PublicKey"`
	EndpointPort    int     `json:"endpointPort"`
}

// CountrySummary represents aggregated country stats.
type CountrySummary struct {
	Code       string `json:"code"`
	Count      int    `json:"count"`
	LowestLoad int    `json:"lowestLoad"`
	AvgLoad    int    `json:"avgLoad"`
}
