package proton

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is an HTTP client for Proton VPN API.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a new Proton API Client.
func NewClient(baseURL string, timeout time.Duration) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = ProtonAPIBaseURL
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		baseURL:    strings.TrimRight(baseURL, "/"),
	}
}

// SetHTTPClient overrides http.Client for tests.
func (c *Client) SetHTTPClient(hc *http.Client) {
	if hc != nil {
		c.httpClient = hc
	}
}

// CaptchaChallenge holds details when Proton API requires human verification.
type CaptchaChallenge struct {
	Code      int      `json:"code"`
	Error     string   `json:"error"`
	Token     string   `json:"token"`
	WebURL    string   `json:"web_url"`
	Methods   []string `json:"methods"`
	ExpiresAt int64    `json:"expires_at"`
	AnonToken string   `json:"anon_token,omitempty"`
	AnonUID   string   `json:"anon_uid,omitempty"`
}

func parseCaptchaChallenge(body []byte, anonToken, anonUID string) *CaptchaChallenge {
	if len(body) == 0 {
		return nil
	}
	var res struct {
		Code    int    `json:"Code"`
		Error   string `json:"Error"`
		Details struct {
			HumanVerificationToken   string   `json:"HumanVerificationToken"`
			HumanVerificationMethods []string `json:"HumanVerificationMethods"`
			WebUrl                   string   `json:"WebUrl"`
			ExpiresAt                int64    `json:"ExpiresAt"`
		} `json:"Details"`
	}
	if err := json.Unmarshal(body, &res); err == nil {
		if res.Code == 9001 || res.Code == 12087 || res.Details.WebUrl != "" {
			return &CaptchaChallenge{
				Code:      res.Code,
				Error:     res.Error,
				Token:     res.Details.HumanVerificationToken,
				WebURL:    res.Details.WebUrl,
				Methods:   res.Details.HumanVerificationMethods,
				ExpiresAt: res.Details.ExpiresAt,
				AnonToken: anonToken,
				AnonUID:   anonUID,
			}
		}
	}
	return nil
}

func (c *Client) doRequest(ctx context.Context, method, endpoint string, session *Session, payload any, extraHeaders ...map[string]string) ([]byte, error) {
	url := c.baseURL + endpoint
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("json marshal failed: %w", err)
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	req.Header.Set("User-Agent", SpoofedUserAgent)
	req.Header.Set("x-pm-appversion", SpoofedAppVersionHeader)
	req.Header.Set("x-pm-apiversion", "4")
	req.Header.Set("Accept", "application/vnd.protonmail.v1+json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for _, eh := range extraHeaders {
		for k, v := range eh {
			req.Header.Set(k, v)
		}
	}

	if session != nil && session.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+session.AccessToken)
		if session.UID != "" {
			req.Header.Set("x-pm-uid", session.UID)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body failed: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("HTTP 401 Unauthorized: Proton session expired")
	}
	if resp.StatusCode >= 400 {
		return respBytes, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	return respBytes, nil
}

// LoginGuest performs the standard 2-phase guest login.
func (c *Client) LoginGuest(ctx context.Context) (*Session, error) {
	sess, challenge, err := c.LoginGuestWithCaptcha(ctx, "", "", "")
	if err != nil {
		return nil, err
	}
	if challenge != nil {
		return nil, fmt.Errorf("Proton 要求人机验证 (Code %d): %s (WebUrl: %s)", challenge.Code, challenge.Error, challenge.WebURL)
	}
	return sess, nil
}

// LoginGuestWithCaptcha performs or resumes the 2-phase guest login with optional captcha token:
// Phase 0: Request anonymous session (/auth/v4/sessions)
// Phase 1: Upgrade to credential-less guest session (/auth/v4/credentialless)
func (c *Client) LoginGuestWithCaptcha(ctx context.Context, anonToken, anonUID, captchaToken string) (*Session, *CaptchaChallenge, error) {
	deviceHash := GetDeviceHash()
	challenge := BuildChallengePayload(deviceHash)

	// Phase 0: Request anonymous session if not yet obtained
	if anonToken == "" || anonUID == "" {
		body0, err := c.doRequest(ctx, http.MethodPost, "/auth/v4/sessions", nil, challenge)
		if err != nil {
			if challengeObj := parseCaptchaChallenge(body0, "", ""); challengeObj != nil {
				return nil, challengeObj, nil
			}
			return nil, nil, fmt.Errorf("phase 0 request failed: %w", err)
		}

		var res0 struct {
			Code        int    `json:"Code"`
			Error       string `json:"Error"`
			AccessToken string `json:"AccessToken"`
			UID         string `json:"UID"`
		}
		if err := json.Unmarshal(body0, &res0); err != nil {
			return nil, nil, fmt.Errorf("parse phase 0 response failed: %w", err)
		}
		if res0.Code != 1000 {
			if challengeObj := parseCaptchaChallenge(body0, "", ""); challengeObj != nil {
				return nil, challengeObj, nil
			}
			return nil, nil, fmt.Errorf("phase 0 failed (Code %d): %s", res0.Code, res0.Error)
		}
		if res0.AccessToken == "" || res0.UID == "" {
			return nil, nil, fmt.Errorf("missing AccessToken or UID in phase 0 response")
		}

		anonToken = res0.AccessToken
		anonUID = res0.UID
	}

	// Phase 1: Upgrade to guest session
	tempSession := &Session{AccessToken: anonToken, UID: anonUID}
	extraHeaders := make(map[string]string)
	if captchaToken != "" {
		extraHeaders["x-pm-human-verification-token"] = captchaToken
		extraHeaders["x-pm-human-verification-token-type"] = "captcha"
	}

	body1, err := c.doRequest(ctx, http.MethodPost, "/auth/v4/credentialless", tempSession, challenge, extraHeaders)
	if err != nil {
		if challengeObj := parseCaptchaChallenge(body1, anonToken, anonUID); challengeObj != nil {
			return nil, challengeObj, nil
		}
		return nil, nil, fmt.Errorf("phase 1 guest upgrade failed: %w", err)
	}

	var res1 struct {
		Code         int    `json:"Code"`
		Error        string `json:"Error"`
		AccessToken  string `json:"AccessToken"`
		UID          string `json:"UID"`
		RefreshToken string `json:"RefreshToken"`
		UserID       string `json:"UserID"`
	}
	if err := json.Unmarshal(body1, &res1); err != nil {
		return nil, nil, fmt.Errorf("parse phase 1 response failed: %w", err)
	}
	if res1.Code != 1000 {
		if challengeObj := parseCaptchaChallenge(body1, anonToken, anonUID); challengeObj != nil {
			return nil, challengeObj, nil
		}
		return nil, nil, fmt.Errorf("phase 1 failed (Code %d): %s", res1.Code, res1.Error)
	}

	finalToken := res1.AccessToken
	if finalToken == "" {
		finalToken = anonToken
	}
	finalUID := res1.UID
	if finalUID == "" {
		finalUID = anonUID
	}

	now := time.Now().Unix()
	session := &Session{
		AccessToken:  finalToken,
		RefreshToken: res1.RefreshToken,
		UID:          finalUID,
		UserID:       res1.UserID,
		MaxTier:      0,
		AuthMode:     "guest",
		UpdatedAt:    now,
	}

	return session, nil, nil
}

// RegisterCertificate generates a new WireGuard keypair and requests a 1-day signed certificate.
func (c *Client) RegisterCertificate(ctx context.Context, session *Session) error {
	wgPrivKeyB64, pemPub, err := GenerateVPNKeys()
	if err != nil {
		return fmt.Errorf("generate vpn keys failed: %w", err)
	}

	deviceHash := GetDeviceHash()
	deviceName := fmt.Sprintf("%s %s (%d)", SpoofedManufacturer, SpoofedModel, deviceHash)

	certPayload := map[string]any{
		"ClientPublicKey": pemPub,
		"Mode":            "session",
		"Duration":        "1440 min",
		"DeviceName":      deviceName,
	}

	respBytes, err := c.doRequest(ctx, http.MethodPost, "/vpn/v1/certificate", session, certPayload)
	if err != nil {
		return fmt.Errorf("certificate request failed: %w", err)
	}

	var resCert struct {
		Code           int    `json:"Code"`
		Error          string `json:"Error"`
		Certificate    string `json:"Certificate"`
		ExpirationTime int64  `json:"ExpirationTime"`
	}
	if err := json.Unmarshal(respBytes, &resCert); err != nil {
		return fmt.Errorf("parse certificate response failed: %w", err)
	}
	if resCert.Code != 1000 {
		return fmt.Errorf("certificate issue failed (Code %d): %s", resCert.Code, resCert.Error)
	}

	exp := resCert.ExpirationTime
	if exp <= 0 {
		exp = time.Now().Add(24 * time.Hour).Unix()
	}

	session.WGPrivateKey = wgPrivKeyB64
	session.WGCertificate = resCert.Certificate
	session.CertExpiresAt = exp
	session.UpdatedAt = time.Now().Unix()

	return nil
}

// FetchServers fetches logical servers and their loads from Proton VPN.
func (c *Client) FetchServers(ctx context.Context, session *Session) ([]Server, error) {
	// 1. Fetch servers
	respBytes, err := c.doRequest(ctx, http.MethodGet, "/vpn/v2/logicals?WithEntriesForProtocols=wireguard&WithState=true", session, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch logical servers failed: %w", err)
	}

	var resLogicals struct {
		Code           int                `json:"Code"`
		Error          string             `json:"Error"`
		LogicalServers []rawLogicalServer `json:"LogicalServers"`
	}
	if err := json.Unmarshal(respBytes, &resLogicals); err != nil {
		return nil, fmt.Errorf("parse logical servers failed: %w", err)
	}
	if resLogicals.Code != 1000 && resLogicals.Code != 0 {
		return nil, fmt.Errorf("fetch logicals failed (Code %d): %s", resLogicals.Code, resLogicals.Error)
	}

	// 2. Fetch server loads
	loadsMap := make(map[string]int)
	if loadBytes, err := c.doRequest(ctx, http.MethodGet, "/vpn/v1/loads", session, nil); err == nil {
		var resLoads struct {
			Code           int `json:"Code"`
			LogicalServers []struct {
				ID   string `json:"ID"`
				Load int    `json:"Load"`
			} `json:"LogicalServers"`
		}
		if json.Unmarshal(loadBytes, &resLoads) == nil && (resLoads.Code == 1000 || resLoads.Code == 0) {
			for _, item := range resLoads.LogicalServers {
				loadsMap[item.ID] = item.Load
			}
		}
	}

	// 3. Map to Server structs
	var servers []Server
	for _, raw := range resLogicals.LogicalServers {
		if raw.ID == "" || len(raw.Servers) == 0 {
			continue
		}
		phys := raw.Servers[0]
		if phys.EntryIP == "" || phys.X25519PublicKey == "" {
			continue
		}

		port := 51820
		if len(phys.WGPorts.UDP) > 0 && phys.WGPorts.UDP[0] > 0 {
			port = phys.WGPorts.UDP[0]
		}

		load := raw.Load
		if l, ok := loadsMap[raw.ID]; ok {
			load = l
		}
		if load <= 0 {
			load = 50
		}

		country := strings.ToUpper(strings.TrimSpace(raw.ExitCountry))
		if country == "" {
			country = strings.ToUpper(strings.TrimSpace(raw.EntryCountry))
		}

		servers = append(servers, Server{
			ID:              raw.ID,
			Name:            raw.Name,
			Country:         country,
			City:            raw.City,
			Tier:            raw.Tier,
			Score:           raw.Score,
			Load:            load,
			EntryIP:         phys.EntryIP,
			X25519PublicKey: phys.X25519PublicKey,
			EndpointPort:    port,
		})
	}

	return servers, nil
}

type rawLogicalServer struct {
	ID           string              `json:"ID"`
	Name         string              `json:"Name"`
	EntryCountry string              `json:"EntryCountry"`
	ExitCountry  string              `json:"ExitCountry"`
	City         string              `json:"City"`
	Tier         int                 `json:"Tier"`
	Score        float64             `json:"Score"`
	Load         int                 `json:"Load"`
	Status       int                 `json:"Status"`
	Servers      []rawPhysicalServer `json:"Servers"`
}

type rawPhysicalServer struct {
	EntryIP         string `json:"EntryIP"`
	X25519PublicKey string `json:"X25519PublicKey"`
	WGPorts         struct {
		UDP []int `json:"UDP"`
	} `json:"WGPorts"`
}
