package xray

import (
	"os/exec"
	"regexp"
	"strconv"
)

// APIClient interacts with Xray Stats API via `xray api`.
type APIClient struct {
	xrayBinary string
	apiPort    int
}

// NewAPIClientWithBinary creates an Xray API client with custom binary path.
func NewAPIClientWithBinary(port int, binaryPath string) *APIClient {
	if binaryPath == "" {
		binaryPath = "/usr/local/bin/xray"
	}
	if port <= 0 {
		port = 10085
	}
	return &APIClient{
		xrayBinary: binaryPath,
		apiPort:    port,
	}
}

// GetStats queries statistics for a user or inbound using `xray api stats`.
func (c *APIClient) GetStats(name string, reset bool) (int64, error) {
	args := []string{
		"api", "stats",
		"--server=127.0.0.1:" + strconv.Itoa(c.apiPort),
		"-name", name,
	}
	if reset {
		args = append(args, "-reset")
	}

	cmd := exec.Command(c.xrayBinary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, nil
	}

	re := regexp.MustCompile(`(?i)"?value"?:\s*"?(\d+)"?`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		if value, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			return value, nil
		}
	}
	return 0, nil
}

// IsHealthy reports whether Xray API is responding.
func (c *APIClient) IsHealthy() bool {
	cmd := exec.Command(c.xrayBinary, "api", "statsquery", "--server=127.0.0.1:"+strconv.Itoa(c.apiPort))
	return cmd.Run() == nil
}
