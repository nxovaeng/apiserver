package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func buildTestAcmeArchive(t *testing.T, installerScript string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	addDir := func(name string) {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeDir,
			Mode:     0755,
		}); err != nil {
			t.Fatal(err)
		}
	}
	addFile := func(name, content string, mode int64) {
		data := []byte(content)
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Mode:     mode,
			Size:     int64(len(data)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}

	addDir("acme.sh-master/")
	addDir("acme.sh-master/dnsapi/")
	addFile("acme.sh-master/acme.sh", installerScript, 0755)
	addFile("acme.sh-master/dnsapi/dns_cf.sh", "#!/bin/sh\necho dns_cf\n", 0755)

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExecAcmeRunnerAutoInstallFromArchiveAndHomeEnv(t *testing.T) {
	// Simulate mock acme.sh that supports "--install --home <dir>" on initial run
	// and echoes HOME / args / dnsapi presence on subsequent runs.
	mockScript := `#!/usr/bin/env bash
set -euo pipefail
for a in "$@"; do
  if [[ "$a" == "--version" ]]; then
    echo "https://github.com/acmesh-official/acme.sh"
    echo "v3.1.6"
    exit 0
  fi
done
if [[ "${1:-}" == "--install" ]]; then
  target_home=""
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --home)
        target_home="${2:-}"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done
  mkdir -p "${target_home}/dnsapi"
  cp "$0" "${target_home}/acme.sh"
  cp "$(dirname "$0")/dnsapi/dns_cf.sh" "${target_home}/dnsapi/dns_cf.sh"
  chmod +x "${target_home}/acme.sh"
  echo "installed:${target_home}"
  exit 0
fi
echo "HOME=${HOME:-}|LE_WORKING_DIR=${LE_WORKING_DIR:-}|ARGS=$*"
`
	archiveBytes := buildTestAcmeArchive(t, mockScript)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(archiveBytes)
	}))
	defer srv.Close()

	// Empty HOME simulates systemd Environment without HOME set
	t.Setenv("HOME", "")

	certDir := filepath.Join(t.TempDir(), "acme-home")
	sum := sha256.Sum256(archiveBytes)
	runner := &execAcmeRunner{
		certDirFn:        func() string { return certDir },
		archiveURL:       srv.URL + "/acme.tar.gz",
		archiveSHA256:    hex.EncodeToString(sum[:]),
		httpClient:       srv.Client(),
		skipSystemLookup: true,
	}

	out1, code1, err1 := runner.Run(context.Background(), []string{"--issue", "--dns", "dns_cf", "-d", "example.com"}, []string{"CF_Token=tok123"})
	if err1 != nil || code1 != 0 {
		t.Fatalf("first Run failed: code=%d err=%v out=%s", code1, err1, out1)
	}
	if !strings.Contains(out1, "--home "+certDir) || strings.Contains(out1, "--cert-home") {
		t.Fatalf("unexpected args on first Run: %s", out1)
	}
	if strings.Contains(out1, "HOME=|") {
		t.Fatalf("expected non-empty HOME fallback env, got: %s", out1)
	}
	if !strings.Contains(out1, "LE_WORKING_DIR="+certDir) {
		t.Fatalf("expected LE_WORKING_DIR pinned to acme home, got: %s", out1)
	}

	// Installed acme home must be root-private: account.conf holds DNS
	// API credentials (CF_Token etc.).
	if st, err := os.Stat(certDir); err != nil {
		t.Fatalf("stat acme home: %v", err)
	} else if st.Mode().Perm() != 0700 {
		t.Fatalf("acme home perms = %o, want 0700", st.Mode().Perm())
	}

	// Second call must reuse installed binary without re-downloading
	out2, code2, err2 := runner.Run(context.Background(), []string{"--version"}, nil)
	if err2 != nil || code2 != 0 {
		t.Fatalf("second Run failed: code=%d err=%v out=%s", code2, err2, out2)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected exactly 1 download hit, got %d", hits.Load())
	}
}

func TestExecAcmeRunnerCertHomeAndDownloadErrorDiagnostics(t *testing.T) {
	// 1. When pre-installed in an alternate dir (with dnsapi/), --cert-home points to configured certDir
	tmpDir := t.TempDir()
	preHome := filepath.Join(tmpDir, "pre-acme")
	customCertDir := filepath.Join(tmpDir, "custom-certs")
	if err := os.MkdirAll(filepath.Join(preHome, "dnsapi"), 0755); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(preHome, "acme.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env bash\necho \"ARGS=$*\"\n"), 0755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", tmpDir)
	homeAcme := filepath.Join(tmpDir, ".acme.sh")
	if err := os.MkdirAll(filepath.Join(homeAcme, "dnsapi"), 0755); err != nil {
		t.Fatal(err)
	}
	homeScript := filepath.Join(homeAcme, "acme.sh")
	if err := os.WriteFile(homeScript, []byte("#!/usr/bin/env bash\necho \"ARGS=$*\"\n"), 0755); err != nil {
		t.Fatal(err)
	}

	runner := &execAcmeRunner{
		certDirFn: func() string { return customCertDir },
	}
	out, code, err := runner.Run(context.Background(), []string{"--issue"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("Run via HOME/.acme.sh failed: code=%d err=%v out=%s", code, err, out)
	}
	if !strings.Contains(out, "--home "+homeAcme) || !strings.Contains(out, "--cert-home "+customCertDir) {
		t.Fatalf("expected resolved --home %s and --cert-home %s, got: %s", homeAcme, customCertDir, out)
	}

	// Verify symlink resolution in resolveAcmeHomeDir finds dnsapi directory next to target
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(binDir, "acme.sh")
	if err := os.Symlink(scriptPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if resolvedHome := resolveAcmeHomeDir(symlinkPath); resolvedHome != preHome {
		t.Fatalf("expected resolveAcmeHomeDir(%s) = %s, got %s", symlinkPath, preHome, resolvedHome)
	}

	// 2. HTTP failure returns explicit HTTP status rather than silent generic error
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream bad gateway"))
	}))
	defer failSrv.Close()

	absentRunner := &execAcmeRunner{
		certDirFn:  func() string { return filepath.Join(tmpDir, "missing-dir") },
		archiveURL: failSrv.URL,
		// Hash must be present for the download to be attempted at all;
		// the 502 aborts the download before verification runs.
		archiveSHA256:    strings.Repeat("a", 64),
		httpClient:       failSrv.Client(),
		skipSystemLookup: true,
	}
	outErr, codeErr, err := absentRunner.Run(context.Background(), []string{"--issue"}, nil)
	if err == nil || codeErr != -1 || !strings.Contains(outErr, "HTTP 502") {
		t.Fatalf("expected HTTP 502 error message, got code=%d err=%v out=%s", codeErr, err, outErr)
	}

	// 3. Zip-slip archive path rejected cleanly
	var badBuf bytes.Buffer
	gz := gzip.NewWriter(&badBuf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "../evil", Typeflag: tar.TypeReg, Mode: 0644, Size: 1})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	_ = gz.Close()
	if err := extractTarGz(&badBuf, t.TempDir()); err == nil || !strings.Contains(err.Error(), "非法") {
		t.Fatalf("expected traversal guard error, got %v", err)
	}
}

func TestExecAcmeRunnerArchiveSHA256Verification(t *testing.T) {
	mockScript := "#!/usr/bin/env bash\necho installed\n"
	archiveBytes := buildTestAcmeArchive(t, mockScript)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(archiveBytes)
	}))
	defer srv.Close()

	// 1. Wrong hash: download happens, verification refuses, nothing installed.
	wrongHash := strings.Repeat("0", 64)
	badRunner := &execAcmeRunner{
		certDirFn:        func() string { return filepath.Join(t.TempDir(), "bad-home") },
		archiveURL:       srv.URL + "/acme.tar.gz",
		archiveSHA256:    wrongHash,
		httpClient:       srv.Client(),
		skipSystemLookup: true,
	}
	_, code, err := badRunner.Run(context.Background(), []string{"--version"}, nil)
	if err == nil || code != -1 || !strings.Contains(err.Error(), "SHA-256 校验失败") {
		t.Fatalf("expected SHA-256 mismatch error, got code=%d err=%v", code, err)
	}

	// 2. Custom URL with no hash at all: refused before downloading.
	noHashRunner := &execAcmeRunner{
		certDirFn:        func() string { return filepath.Join(t.TempDir(), "nohash-home") },
		archiveURL:       srv.URL + "/acme.tar.gz",
		httpClient:       srv.Client(),
		skipSystemLookup: true,
	}
	_, code, err = noHashRunner.Run(context.Background(), []string{"--version"}, nil)
	if err == nil || code != -1 || !strings.Contains(err.Error(), "archive_sha256") {
		t.Fatalf("expected missing-hash refusal, got code=%d err=%v", code, err)
	}
}

func TestExecAcmeRunnerAutoInstallDisabled(t *testing.T) {
	runner := &execAcmeRunner{
		certDirFn:           func() string { return filepath.Join(t.TempDir(), "disabled-home") },
		skipSystemLookup:    true,
		autoInstallDisabled: true,
	}
	_, code, err := runner.Run(context.Background(), []string{"--version"}, nil)
	if err == nil || code != -1 || !strings.Contains(err.Error(), "自动安装") {
		t.Fatalf("expected auto-install-disabled error, got code=%d err=%v", code, err)
	}
}

func TestResolveHomeEnv(t *testing.T) {
	t.Setenv("HOME", "/should/not/be/used")
	// Standard layout <home>/.acme.sh resolves HOME to the parent.
	if got := resolveHomeEnv("/root/.acme.sh"); got != "/root" {
		t.Fatalf("resolveHomeEnv(/root/.acme.sh) = %q, want /root", got)
	}
	if got := resolveHomeEnv("/opt/panel/certs"); got == "/tmp" {
		t.Fatalf("HOME must never fall back to /tmp, got %q", got)
	}
}
