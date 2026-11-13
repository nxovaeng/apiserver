package proton

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

const (
	ConfigFileName  = "wireproxy.conf"
	SessionFileName = "session.json"
	ServersFileName = "servers.json"
	PIDFileName     = "wireproxy.pid"
)

// ManagerConfig holds configurations for proton manager.
type ManagerConfig struct {
	DataDir    string
	BinaryPath string
	SocksHost  string
	SocksPort  int
	RepoURL    string
}

// Manager coordinates Proton VPN guest credentials, server lists, and WireProxy runtime.
type Manager struct {
	cfg        ManagerConfig
	client     *Client
	mu         sync.RWMutex
	cmd        *exec.Cmd
	activeSrv  *Server
	activeCC   string
	cachedSrvs []Server
	lastFetch  time.Time
	cachedIP   string
	cachedIPAt time.Time

	watchdogCancel context.CancelFunc
	failCount      int
}

// NewManager creates a new Proton Manager.
func NewManager(cfg ManagerConfig, client *Client) *Manager {
	if cfg.DataDir == "" {
		cfg.DataDir = "/opt/xray-panel/proton"
	}
	if cfg.SocksHost == "" {
		cfg.SocksHost = "127.0.0.1"
	}
	if cfg.SocksPort <= 0 {
		cfg.SocksPort = 1080
	}
	if client == nil {
		client = NewClient("", 30*time.Second)
	}
	_ = os.MkdirAll(cfg.DataDir, 0755)

	m := &Manager{
		cfg:    cfg,
		client: client,
	}
	// Try loading cached servers and session
	m.loadCachedServers()
	return m
}

func (m *Manager) GetDataDir() string {
	return m.cfg.DataDir
}

func (m *Manager) GetSocksPort() int {
	return m.cfg.SocksPort
}

func (m *Manager) GetSocksHost() string {
	return m.cfg.SocksHost
}

func (m *Manager) GetSessionPath() string {
	return filepath.Join(m.cfg.DataDir, SessionFileName)
}

func (m *Manager) HasValidSession() bool {
	sess, err := m.LoadSession()
	return err == nil && sess != nil && sess.AccessToken != ""
}

// SetSocksPort dynamically updates the SOCKS5 listen port.
// If wireproxy is currently running, it re-renders the configuration and restarts wireproxy.
func (m *Manager) SetSocksPort(ctx context.Context, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port: %d (must be between 1 and 65535)", port)
	}

	m.mu.Lock()
	m.cfg.SocksPort = port
	activeSrv := m.activeSrv
	m.mu.Unlock()

	if m.IsRunning() && activeSrv != nil {
		return m.Start(ctx, activeSrv)
	}
	return nil
}

// LocateWireproxy finds the wireproxy executable.
func (m *Manager) LocateWireproxy() (string, error) {
	var candidates []string
	if m.cfg.BinaryPath != "" {
		candidates = append(candidates, m.cfg.BinaryPath)
	}
	candidates = append(candidates,
		filepath.Join(m.cfg.DataDir, "wireproxy"),
		"/usr/local/bin/wireproxy",
		"/usr/bin/wireproxy",
	)
	if p, err := exec.LookPath("wireproxy"); err == nil {
		candidates = append(candidates, p)
	}

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("wireproxy binary not found")
}

// EnsureWireproxy checks if wireproxy exists; if not, downloads and installs it.
func (m *Manager) EnsureWireproxy(ctx context.Context) (string, error) {
	if p, err := m.LocateWireproxy(); err == nil {
		return p, nil
	}

	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("unsupported architecture for wireproxy: %s", arch)
	}

	version := "v1.0.9"
	fileName := fmt.Sprintf("wireproxy_linux_%s.tar.gz", arch)
	url := fmt.Sprintf("https://github.com/pufferffish/wireproxy/releases/download/%s/%s", version, fileName)

	destPath := filepath.Join(m.cfg.DataDir, "wireproxy")
	targetBin := "/usr/local/bin/wireproxy"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create download request failed: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download wireproxy failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download wireproxy failed with HTTP %d", resp.StatusCode)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("open gzip stream failed: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var found bool
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar archive failed: %w", err)
		}
		if filepath.Base(header.Name) == "wireproxy" {
			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return "", fmt.Errorf("create wireproxy binary file failed: %w", err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return "", fmt.Errorf("extract wireproxy failed: %w", err)
			}
			outFile.Close()
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("wireproxy binary not found inside archive")
	}

	_ = os.Chmod(destPath, 0755)
	// Try copying to /usr/local/bin if writable
	if data, err := os.ReadFile(destPath); err == nil {
		if err := os.WriteFile(targetBin, data, 0755); err == nil {
			return targetBin, nil
		}
	}

	return destPath, nil
}

// LoadSession reads session.json from DataDir.
func (m *Manager) LoadSession() (*Session, error) {
	path := filepath.Join(m.cfg.DataDir, SessionFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("corrupted session file removed: %w", err)
	}
	if sess.AccessToken == "" {
		_ = os.Remove(path)
		return nil, fmt.Errorf("empty access token in session")
	}
	return &sess, nil
}

// SaveSession writes session.json atomically.
func (m *Manager) SaveSession(sess *Session) error {
	path := filepath.Join(m.cfg.DataDir, SessionFileName)
	tmpPath := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// EnsureValidSession loads a valid session or performs guest login and issues a cert.
func (m *Manager) EnsureValidSession(ctx context.Context) (*Session, error) {
	sess, err := m.LoadSession()
	now := time.Now().Unix()

	if err != nil || sess == nil {
		// Perform fresh guest login
		newSess, err := m.client.LoginGuest(ctx)
		if err != nil {
			return nil, fmt.Errorf("guest login failed: %w", err)
		}
		if err := m.client.RegisterCertificate(ctx, newSess); err != nil {
			return nil, fmt.Errorf("register certificate failed: %w", err)
		}
		if err := m.SaveSession(newSess); err != nil {
			return nil, fmt.Errorf("save session failed: %w", err)
		}
		return newSess, nil
	}

	// Check if certificate is missing or expiring in < 2 hours (Proton v4 certs are 24 hours)
	needsRenew := sess.WGPrivateKey == "" || sess.CertExpiresAt == 0 || (sess.CertExpiresAt-now) < 7200
	if needsRenew {
		if err := m.client.RegisterCertificate(ctx, sess); err != nil {
			// Renewal failed, session might be invalid; retry full guest login
			newSess, loginErr := m.client.LoginGuest(ctx)
			if loginErr != nil {
				return nil, fmt.Errorf("certificate renew & re-login failed: %w (login: %v)", err, loginErr)
			}
			if err := m.client.RegisterCertificate(ctx, newSess); err != nil {
				return nil, fmt.Errorf("register certificate on fresh session failed: %w", err)
			}
			if err := m.SaveSession(newSess); err != nil {
				return nil, fmt.Errorf("save fresh session failed: %w", err)
			}
			return newSess, nil
		}
		_ = m.SaveSession(sess)
	}

	return sess, nil
}

// ForceLoginGuest performs an explicit fresh guest login and issues a new 24-hour certificate.
func (m *Manager) ForceLoginGuest(ctx context.Context) (*Session, error) {
	newSess, err := m.client.LoginGuest(ctx)
	if err != nil {
		return nil, fmt.Errorf("guest login failed: %w", err)
	}
	if err := m.client.RegisterCertificate(ctx, newSess); err != nil {
		return nil, fmt.Errorf("register certificate failed: %w", err)
	}
	if err := m.SaveSession(newSess); err != nil {
		return nil, fmt.Errorf("save session failed: %w", err)
	}

	// Refresh server list in background or synchronously
	_, _ = m.RefreshServers(ctx)

	// Hot-reload wireproxy if running
	if m.IsRunning() {
		m.mu.RLock()
		activeSrv := m.activeSrv
		m.mu.RUnlock()
		if activeSrv != nil {
			_ = m.Start(ctx, activeSrv)
		}
	}

	return newSess, nil
}

func (m *Manager) loadCachedServers() []Server {
	m.mu.RLock()
	if len(m.cachedSrvs) > 0 {
		srvs := m.cachedSrvs
		m.mu.RUnlock()
		return srvs
	}
	m.mu.RUnlock()

	path := filepath.Join(m.cfg.DataDir, ServersFileName)
	data, err := os.ReadFile(path)
	if err == nil {
		var srvs []Server
		if json.Unmarshal(data, &srvs) == nil && len(srvs) > 0 {
			m.mu.Lock()
			m.cachedSrvs = srvs
			m.mu.Unlock()
			return srvs
		}
	}
	return nil
}

func (m *Manager) saveCachedServers(srvs []Server) error {
	m.mu.Lock()
	m.cachedSrvs = srvs
	m.lastFetch = time.Now()
	m.mu.Unlock()

	path := filepath.Join(m.cfg.DataDir, ServersFileName)
	tmpPath := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	data, err := json.Marshal(srvs)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// RefreshServers updates the server cache via Proton API.
func (m *Manager) RefreshServers(ctx context.Context) ([]Server, error) {
	sess, err := m.EnsureValidSession(ctx)
	if err != nil {
		return nil, err
	}

	srvs, err := m.client.FetchServers(ctx, sess)
	if err != nil {
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "expired") {
			// Session expired, re-login once
			newSess, err2 := m.client.LoginGuest(ctx)
			if err2 == nil {
				_ = m.client.RegisterCertificate(ctx, newSess)
				_ = m.SaveSession(newSess)
				srvs, err = m.client.FetchServers(ctx, newSess)
			}
		}
	}
	if err != nil {
		return nil, err
	}

	_ = m.saveCachedServers(srvs)
	return srvs, nil
}

// SelectServer picks the best matching server for given country/name.
func (m *Manager) SelectServer(ctx context.Context, country, serverName string) (*Server, error) {
	srvs := m.loadCachedServers()
	if len(srvs) == 0 || time.Since(m.lastFetch) > 6*time.Hour {
		var err error
		srvs, err = m.RefreshServers(ctx)
		if err != nil && len(srvs) == 0 {
			return nil, fmt.Errorf("unable to load servers: %w", err)
		}
	}

	// 1. Direct server name match
	if serverName != "" {
		for _, s := range srvs {
			if strings.EqualFold(s.Name, serverName) || strings.EqualFold(s.ID, serverName) {
				return &s, nil
			}
		}
	}

	// 2. Filter by country and tier 0
	targetCC := strings.ToUpper(strings.TrimSpace(country))
	if targetCC == "" {
		targetCC = "US"
	}

	var candidates []Server
	for _, s := range srvs {
		if s.Tier == 0 && (targetCC == "" || strings.EqualFold(s.Country, targetCC)) {
			candidates = append(candidates, s)
		}
	}

	if len(candidates) == 0 {
		// Fallback: any Tier 0 server
		for _, s := range srvs {
			if s.Tier == 0 {
				candidates = append(candidates, s)
			}
		}
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no available Tier 0 Proton servers found")
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Load < candidates[j].Load
	})

	return &candidates[0], nil
}

// RenderWireproxyConf creates wireproxy INI configuration string.
func RenderWireproxyConf(privateKey string, server *Server, listenHost string, listenPort int) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = %s
Endpoint = %s:%d
PersistentKeepalive = 25

[Socks5]
BindAddress = %s:%d
`,
		strings.TrimSpace(privateKey),
		strings.TrimSpace(server.X25519PublicKey),
		strings.TrimSpace(server.EntryIP),
		server.EndpointPort,
		strings.TrimSpace(listenHost),
		listenPort,
	)
}

// IsRunning checks whether the wireproxy process is active.
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	cmd := m.cmd
	m.mu.RUnlock()

	if cmd != nil && cmd.Process != nil {
		if err := cmd.Process.Signal(syscall.Signal(0)); err == nil {
			return true
		}
	}

	// Fallback to checking PID file
	pidPath := filepath.Join(m.cfg.DataDir, PIDFileName)
	data, err := os.ReadFile(pidPath)
	if err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			if proc, err := os.FindProcess(pid); err == nil {
				if err := proc.Signal(syscall.Signal(0)); err == nil {
					return true
				}
			}
		}
	}

	return false
}

// Start launches wireproxy with the target server.
func (m *Manager) Start(ctx context.Context, server *Server) error {
	binPath, err := m.EnsureWireproxy(ctx)
	if err != nil {
		return fmt.Errorf("ensure wireproxy binary failed: %w", err)
	}

	sess, err := m.EnsureValidSession(ctx)
	if err != nil {
		return fmt.Errorf("ensure valid session failed: %w", err)
	}

	// Stop existing process if running
	_ = m.Stop()

	confContent := RenderWireproxyConf(sess.WGPrivateKey, server, m.cfg.SocksHost, m.cfg.SocksPort)
	confPath := filepath.Join(m.cfg.DataDir, ConfigFileName)
	if err := os.WriteFile(confPath, []byte(confContent), 0600); err != nil {
		return fmt.Errorf("write wireproxy.conf failed: %w", err)
	}

	cmd := exec.Command(binPath, "-c", confPath)
	cmd.Dir = m.cfg.DataDir
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn wireproxy failed: %w", err)
	}

	// Save PID
	pidPath := filepath.Join(m.cfg.DataDir, PIDFileName)
	_ = os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)

	m.mu.Lock()
	m.cmd = cmd
	m.activeSrv = server
	m.activeCC = server.Country
	m.cachedIP = ""
	m.cachedIPAt = time.Time{}
	m.failCount = 0
	m.mu.Unlock()

	// Give it a moment to bind
	time.Sleep(300 * time.Millisecond)

	// Ensure watchdog is active
	m.ensureWatchdog()

	return nil
}

// Stop stops the wireproxy process.
func (m *Manager) Stop() error {
	m.mu.Lock()
	cmd := m.cmd
	m.cmd = nil
	m.activeSrv = nil
	m.activeCC = ""
	m.cachedIP = ""
	m.cachedIPAt = time.Time{}
	m.mu.Unlock()

	pidPath := filepath.Join(m.cfg.DataDir, PIDFileName)
	var pids []int
	if cmd != nil && cmd.Process != nil {
		pids = append(pids, cmd.Process.Pid)
	}
	if data, err := os.ReadFile(pidPath); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	_ = os.Remove(pidPath)

	for _, pid := range pids {
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Signal(syscall.SIGTERM)
			// Wait briefly
			done := make(chan struct{})
			go func() {
				_, _ = proc.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(500 * time.Millisecond):
				_ = proc.Kill()
			}
		}
	}

	return nil
}

// Connect connects or reconnects to the requested country/server.
func (m *Manager) Connect(ctx context.Context, country, serverName string) (*Server, error) {
	server, err := m.SelectServer(ctx, country, serverName)
	if err != nil {
		return nil, fmt.Errorf("select server failed: %w", err)
	}

	if err := m.Start(ctx, server); err != nil {
		return nil, err
	}

	return server, nil
}

// Disconnect stops wireproxy.
func (m *Manager) Disconnect(ctx context.Context) error {
	return m.Stop()
}

// GetRealIP checks exit IP via the local SOCKS5 proxy.
func (m *Manager) GetRealIP(ctx context.Context) string {
	if !m.IsRunning() {
		return "N/A"
	}

	m.mu.RLock()
	if m.cachedIP != "" && time.Since(m.cachedIPAt) < 60*time.Second {
		ip := m.cachedIP
		m.mu.RUnlock()
		return ip
	}
	m.mu.RUnlock()

	socksAddr := fmt.Sprintf("%s:%d", m.cfg.SocksHost, m.cfg.SocksPort)
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return "Proxy Error"
	}

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		},
		Timeout: 4 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipinfo.io/json", nil)
	if err != nil {
		return "Unknown"
	}

	resp, err := hc.Do(req)
	if err != nil {
		return "Timeout / Unreachable"
	}
	defer resp.Body.Close()

	var res struct {
		IP string `json:"ip"`
	}
	if json.NewDecoder(resp.Body).Decode(&res) == nil && res.IP != "" {
		m.mu.Lock()
		m.cachedIP = res.IP
		m.cachedIPAt = time.Now()
		m.mu.Unlock()
		return res.IP
	}

	return "Unknown"
}

// Status returns current PVPN manager runtime status.
func (m *Manager) Status(ctx context.Context) (running bool, activeServer string, activeCountry string, exitIP string, certExpiresAt int64) {
	running = m.IsRunning()

	m.mu.RLock()
	if m.activeSrv != nil {
		activeServer = m.activeSrv.Name
	}
	activeCountry = m.activeCC
	m.mu.RUnlock()

	if running {
		exitIP = m.GetRealIP(ctx)
	} else {
		exitIP = "N/A"
	}

	if sess, err := m.LoadSession(); err == nil && sess != nil {
		certExpiresAt = sess.CertExpiresAt
	}

	return running, activeServer, activeCountry, exitIP, certExpiresAt
}

// GetCountries returns grouped country stats for all available Tier 0 servers.
func (m *Manager) GetCountries(ctx context.Context) ([]CountrySummary, error) {
	srvs := m.loadCachedServers()
	if len(srvs) == 0 {
		var err error
		srvs, err = m.RefreshServers(ctx)
		if err != nil && len(srvs) == 0 {
			return nil, err
		}
	}

	type stats struct {
		count int
		min   int
		total int
	}
	ccMap := make(map[string]*stats)

	for _, s := range srvs {
		if s.Tier != 0 {
			continue
		}
		st, ok := ccMap[s.Country]
		if !ok {
			st = &stats{count: 0, min: 100, total: 0}
			ccMap[s.Country] = st
		}
		st.count++
		st.total += s.Load
		if s.Load < st.min {
			st.min = s.Load
		}
	}

	var res []CountrySummary
	for cc, st := range ccMap {
		avg := 50
		if st.count > 0 {
			avg = st.total / st.count
		}
		res = append(res, CountrySummary{
			Code:       cc,
			Count:      st.count,
			LowestLoad: st.min,
			AvgLoad:    avg,
		})
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].Code < res[j].Code
	})
	return res, nil
}

// GetServers returns available servers for a country.
func (m *Manager) GetServers(ctx context.Context, country string) ([]Server, error) {
	srvs := m.loadCachedServers()
	if len(srvs) == 0 {
		var err error
		srvs, err = m.RefreshServers(ctx)
		if err != nil && len(srvs) == 0 {
			return nil, err
		}
	}

	targetCC := strings.ToUpper(strings.TrimSpace(country))
	var res []Server
	for _, s := range srvs {
		if s.Tier == 0 && (targetCC == "" || strings.EqualFold(s.Country, targetCC)) {
			res = append(res, s)
		}
	}

	sort.Slice(res, func(i, j int) bool {
		if res[i].Load != res[j].Load {
			return res[i].Load < res[j].Load
		}
		return res[i].Name < res[j].Name
	})

	return res, nil
}

func (m *Manager) ensureWatchdog() {
	m.mu.Lock()
	if m.watchdogCancel != nil {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.watchdogCancel = cancel
	m.mu.Unlock()

	go m.watchdogLoop(ctx)
}

func (m *Manager) watchdogLoop(ctx context.Context) {
	tickerHealth := time.NewTicker(30 * time.Second)
	tickerCert := time.NewTicker(5 * time.Minute)
	defer tickerHealth.Stop()
	defer tickerCert.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerHealth.C:
			if m.IsRunning() {
				m.checkHealthAndFailover(ctx)
			}
		case <-tickerCert.C:
			// Check if certificate needs renewal (< 2 hours remaining)
			oldSess, _ := m.LoadSession()
			var oldExp int64
			if oldSess != nil {
				oldExp = oldSess.CertExpiresAt
			}

			now := time.Now().Unix()
			if oldExp == 0 || (oldExp-now) < 7200 {
				newSess, err := m.EnsureValidSession(ctx)
				if err == nil && newSess != nil && newSess.CertExpiresAt != oldExp {
					// Certificate was renewed! Hot reload wireproxy if currently running
					if m.IsRunning() {
						m.mu.RLock()
						activeSrv := m.activeSrv
						m.mu.RUnlock()
						if activeSrv != nil {
							_ = m.Start(ctx, activeSrv)
						}
					}
				}
			}
		}
	}
}

func (m *Manager) checkHealthAndFailover(ctx context.Context) {
	socksAddr := fmt.Sprintf("%s:%d", m.cfg.SocksHost, m.cfg.SocksPort)
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return
	}

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		},
		Timeout: 3 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://connectivitycheck.gstatic.com/generate_204", nil)
	if err != nil {
		return
	}

	resp, err := hc.Do(req)
	if err == nil && resp.StatusCode == http.StatusNoContent {
		resp.Body.Close()
		m.mu.Lock()
		m.failCount = 0
		m.mu.Unlock()
		return
	}

	if resp != nil {
		resp.Body.Close()
	}

	m.mu.Lock()
	m.failCount++
	fails := m.failCount
	cc := m.activeCC
	curSrv := m.activeSrv
	m.mu.Unlock()

	// If failed 3 times, auto-failover
	if fails >= 3 && cc != "" {
		m.mu.Lock()
		m.failCount = 0
		m.mu.Unlock()

		// Pick alternative server in the same country
		srvs, _ := m.GetServers(ctx, cc)
		var nextSrv *Server
		for _, s := range srvs {
			if curSrv == nil || s.ID != curSrv.ID {
				sc := s
				nextSrv = &sc
				break
			}
		}

		if nextSrv != nil {
			_ = m.Start(ctx, nextSrv)
		}
	}
}
