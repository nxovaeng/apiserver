#!/usr/bin/env bash

#
# Xray Panel Server 一键安装 / 升级 / 卸载 / 运维脚本
# 适用系统: Ubuntu / Debian / CentOS / Rocky Linux / AlmaLinux / Alpine
#
# 用法:
#   ./install.sh install [--bin /path/to/xray-panel-server] [--listen 127.0.0.1:8082]
#   ./install.sh update [--bin /path/to/xray-panel-server]
#   ./install.sh uninstall [--purge]
#   ./install.sh update-geo
#   ./install.sh status
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/xray-panel"
DATA_DIR="${INSTALL_DIR}/data"
LOGS_DIR="${INSTALL_DIR}/logs"
CONFIG_FILE="${INSTALL_DIR}/config.yaml"
BINARY_PATH="/usr/local/bin/xray-panel-server"
SERVICE_NAME="xray-panel-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

XRAY_BIN="/usr/local/bin/xray"
XRAY_CONF_DIR="/usr/local/etc/xray"
XRAY_ASSETS_DIR="/usr/local/share/xray"
NGINX_CONF_DIR="/etc/nginx/conf.d"
NGINX_STREAM_DIR="/etc/nginx/stream.d"

REPO="${XRAY_PANEL_SERVER_REPO:-nxovaeng/apiserver}"
DEFAULT_LISTEN="127.0.0.1:8082"
LOCAL_BIN=""

info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERR]${NC} $1"; }

check_root() {
    if [[ ${EUID} -ne 0 ]]; then
        error "请使用 root 权限运行此脚本 (sudo $0 ...)"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS="${ID:-unknown}"
    else
        error "无法识别操作系统类型"
        exit 1
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)
            ARCH="amd64"
            XRAY_ARCH="64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            XRAY_ARCH="arm64-v8a"
            ;;
        *)
            error "不支持的 CPU 架构: $(uname -m)"
            exit 1
            ;;
    esac
}

install_dependencies() {
    info "安装基础依赖 (curl / unzip / nginx / sqlite3 / cron / socat)..."
    case "${OS}" in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq curl wget unzip tar nginx sqlite3 ca-certificates openssl cron socat
            ;;
        centos|rhel|rocky|almalinux|fedora)
            if command -v dnf &>/dev/null; then
                dnf install -y -q curl wget unzip tar nginx sqlite ca-certificates openssl crontabs socat
            else
                yum install -y -q curl wget unzip tar nginx sqlite ca-certificates openssl crontabs socat
            fi
            ;;
        alpine)
            apk add --no-cache curl wget unzip tar nginx sqlite ca-certificates openssl bash socat
            ;;
        *)
            warn "未自动识别的包管理器 (${OS})，请确保已安装 curl, unzip, nginx, sqlite3, cron, socat"
            ;;
    esac
    success "基础依赖检查完成"
}

install_acme() {
    local acme_home="/root/.acme.sh"
    if [[ -x "${acme_home}/acme.sh" ]] || command -v acme.sh &>/dev/null; then
        info "检测到已安装 acme.sh"
        return 0
    fi

    info "安装 acme.sh 至 ${acme_home} (用于面板内置 DNS-01 证书签发)..."
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    local archive_url="https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz"
    if ! curl -fsSL --retry 3 -o "${tmp_dir}/acme.tar.gz" "${archive_url}"; then
        rm -rf "${tmp_dir}"
        warn "下载 acme.sh 失败，将在首次申请证书时再次尝试自动安装"
        return 0
    fi

    if ! tar -xzf "${tmp_dir}/acme.tar.gz" -C "${tmp_dir}"; then
        rm -rf "${tmp_dir}"
        warn "解压 acme.sh 失败，将在首次申请证书时再次尝试自动安装"
        return 0
    fi

    local installer
    installer="$(find "${tmp_dir}" -maxdepth 2 -type f -name 'acme.sh' | head -n1)"
    if [[ -z "${installer}" ]]; then
        rm -rf "${tmp_dir}"
        warn "压缩包中未找到 acme.sh 脚本"
        return 0
    fi

    chmod +x "${installer}"
    local extra_args=()
    if ! command -v crontab &>/dev/null; then
        extra_args+=(--nocron --force)
    fi

    if (cd "$(dirname "${installer}")" && HOME=/root "${installer}" --install --home "${acme_home}" ${extra_args[@]+"${extra_args[@]}"}); then
        success "acme.sh 安装完成 (${acme_home}/acme.sh)"
    else
        warn "acme.sh 预安装失败，面板将在首次申请证书时重试安装"
    fi
    rm -rf "${tmp_dir}"
}

install_xray() {
    if [[ -x "${XRAY_BIN}" ]]; then
        info "检测到已安装的 Xray: $(${XRAY_BIN} version 2>/dev/null | head -n1 || echo 'unknown')"
    else
        info "正在下载并安装最新 Xray-core (${XRAY_ARCH})..."
        local tmp_dir
        tmp_dir="$(mktemp -d)"
        local ver
        ver="$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name"' | head -n1 | cut -d '"' -f4 || echo '')"
        local url
        if [[ -n "${ver}" ]]; then
            url="https://github.com/XTLS/Xray-core/releases/download/${ver}/Xray-linux-${XRAY_ARCH}.zip"
        else
            url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${XRAY_ARCH}.zip"
        fi
        curl -fL --retry 3 -o "${tmp_dir}/xray.zip" "${url}"
        unzip -qo "${tmp_dir}/xray.zip" -d "${tmp_dir}"
        install -m 755 "${tmp_dir}/xray" "${XRAY_BIN}"
        mkdir -p "${XRAY_ASSETS_DIR}" "${XRAY_CONF_DIR}"
        [[ -f "${tmp_dir}/geoip.dat" ]] && install -m 644 "${tmp_dir}/geoip.dat" "${XRAY_ASSETS_DIR}/geoip.dat"
        [[ -f "${tmp_dir}/geosite.dat" ]] && install -m 644 "${tmp_dir}/geosite.dat" "${XRAY_ASSETS_DIR}/geosite.dat"
        rm -rf "${tmp_dir}"
        success "Xray-core 安装完成"
    fi

    mkdir -p "${XRAY_CONF_DIR}" "${XRAY_ASSETS_DIR}"
    if [[ ! -f "${XRAY_CONF_DIR}/config.json" ]]; then
        cat > "${XRAY_CONF_DIR}/config.json" <<'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
EOF
    fi

    if [[ ! -f /etc/systemd/system/xray.service ]]; then
        cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${XRAY_BIN} run -config ${XRAY_CONF_DIR}/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable xray >/dev/null 2>&1 || true
    fi
}

update_geo() {
    info "正在更新 GeoIP / GeoSite 数据文件到 ${XRAY_ASSETS_DIR}..."
    mkdir -p "${XRAY_ASSETS_DIR}"
    curl -fL --retry 3 -o "${XRAY_ASSETS_DIR}/geoip.dat.tmp" \
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    curl -fL --retry 3 -o "${XRAY_ASSETS_DIR}/geosite.dat.tmp" \
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    mv "${XRAY_ASSETS_DIR}/geoip.dat.tmp" "${XRAY_ASSETS_DIR}/geoip.dat"
    mv "${XRAY_ASSETS_DIR}/geosite.dat.tmp" "${XRAY_ASSETS_DIR}/geosite.dat"
    success "GeoData 更新完成"
}

prepare_nginx() {
    mkdir -p "${NGINX_CONF_DIR}"
    if [[ -f /etc/nginx/nginx.conf ]] && ! grep -q "${NGINX_CONF_DIR}" /etc/nginx/nginx.conf; then
        warn "/etc/nginx/nginx.conf 中未检测到 include ${NGINX_CONF_DIR}/*.conf，请确认 Nginx http 块会加载受控站点配置"
    fi
    systemctl enable nginx >/dev/null 2>&1 || true
    if nginx -t >/dev/null 2>&1; then
        systemctl start nginx >/dev/null 2>&1 || true
    else
        warn "nginx -t 检查未通过，已跳过自动启动 Nginx，请手动排查 /etc/nginx 配置"
    fi
}

check_ssh_tunnel_prereqs() {
    local sshd_bin=""
    if command -v sshd &>/dev/null; then
        sshd_bin="$(command -v sshd)"
    elif [[ -x /usr/sbin/sshd ]]; then
        sshd_bin="/usr/sbin/sshd"
    else
        warn "未检测到 OpenSSH 服务端 (sshd)，桌面端将无法通过 SSH 隧道接入"
        return
    fi

    local sshd_dump=""
    sshd_dump="$("${sshd_bin}" -T 2>/dev/null || true)"
    if [[ -n "${sshd_dump}" ]]; then
        local fwd
        fwd="$(echo "${sshd_dump}" | awk '$1=="allowtcpforwarding" {print $2; exit}')"
        local dfwd
        dfwd="$(echo "${sshd_dump}" | awk '$1=="disableforwarding" {print $2; exit}')"
        if [[ "${fwd}" == "no" || "${dfwd}" == "yes" ]]; then
            warn "检测到 sshd 禁用了端口转发 (AllowTcpForwarding=${fwd:-unknown}, DisableForwarding=${dfwd:-no})"
            warn "xray-panel-desktop SSH 隧道依赖 direct-tcpip 端口转发；请在 /etc/ssh/sshd_config 设置："
            warn "  AllowTcpForwarding yes"
            warn "并执行 systemctl reload sshd (Debian/Ubuntu 为 systemctl reload ssh)"
        else
            success "OpenSSH 端口转发检查通过 (AllowTcpForwarding=${fwd:-yes})"
        fi
    else
        info "未能通过 sshd -T 读取运行时配置，请确认 /etc/ssh/sshd_config 未禁用 AllowTcpForwarding"
    fi
}

install_server_binary() {
    local script_src="${BASH_SOURCE[0]:-}"
    local repo_dir="."
    if [[ -n "${script_src}" && -f "${script_src}" ]]; then
        local script_dir
        script_dir="$(cd "$(dirname "${script_src}")" && pwd)"
        repo_dir="$(cd "${script_dir}/.." && pwd)"
    fi

    if [[ -n "${LOCAL_BIN}" ]]; then
        if [[ ! -f "${LOCAL_BIN}" ]]; then
            error "指定的二进制不存在: ${LOCAL_BIN}"
            exit 1
        fi
        install -m 755 "${LOCAL_BIN}" "${BINARY_PATH}"
        success "已从 ${LOCAL_BIN} 安装 ${BINARY_PATH}"
        return
    fi

    if [[ -f "${repo_dir}/bin/xray-panel-server-linux-${ARCH}" ]]; then
        install -m 755 "${repo_dir}/bin/xray-panel-server-linux-${ARCH}" "${BINARY_PATH}"
        success "已从构建产物安装 ${BINARY_PATH}"
        return
    fi

    if [[ -f "${repo_dir}/bin/xray-panel-server" ]]; then
        install -m 755 "${repo_dir}/bin/xray-panel-server" "${BINARY_PATH}"
        success "已从 ./bin/xray-panel-server 安装 ${BINARY_PATH}"
        return
    fi

    if [[ -f "${repo_dir}/go.mod" ]] && command -v go &>/dev/null; then
        info "检测到本地 Go 源码与编译器，正在编译 xray-panel-server..."
        (cd "${repo_dir}" && CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" go build -ldflags "-s -w" -o "${BINARY_PATH}" ./cmd/server)
        chmod 755 "${BINARY_PATH}"
        success "源码编译并安装完成: ${BINARY_PATH}"
        return
    fi

    if [[ -n "${REPO}" ]]; then
        info "正在从 GitHub Release (${REPO}) 下载 xray-panel-server-linux-${ARCH}..."
        local url="https://github.com/${REPO}/releases/latest/download/xray-panel-server-linux-${ARCH}"
        if ! curl -fL --retry 3 -o "${BINARY_PATH}.tmp" "${url}"; then
            rm -f "${BINARY_PATH}.tmp"
            error "从 GitHub Release 下载失败: ${url}"
            error "请确认仓库已推送 tag 并发布对应 Release，或先本地构建/打包后通过 --bin 指定本地二进制。"
            exit 1
        fi
        install -m 755 "${BINARY_PATH}.tmp" "${BINARY_PATH}"
        rm -f "${BINARY_PATH}.tmp"
        success "已下载并安装 ${BINARY_PATH}"
        return
    fi

    error "未找到本地构建产物、Go 编译环境或 XRAY_PANEL_SERVER_REPO 下载源。"
    error "请先使用 'make release' 编译二进制，并通过 '--bin /path/to/xray-panel-server-linux-${ARCH}' 指定路径。"
    exit 1
}

write_config() {
    mkdir -p "${INSTALL_DIR}" "${DATA_DIR}" "${LOGS_DIR}"
    if [[ -f "${CONFIG_FILE}" ]]; then
        info "保留现有配置文件: ${CONFIG_FILE}"
        return
    fi

    info "生成默认服务端配置: ${CONFIG_FILE} (监听 ${DEFAULT_LISTEN})"
    cat > "${CONFIG_FILE}" <<EOF
# Xray Panel Server 配置文件 (headless API server)
server:
  listen: "${DEFAULT_LISTEN}"   # 默认仅监听回环地址，推荐桌面端通过 SSH 隧道接入
  debug: false

auth:
  bootstrap_tokens: []          # 可选静态引导 Token，格式 "xrp_..."
  fail_limit: 15                # 滑窗内允许的最大失败认证次数
  fail_window_minutes: 5        # 滑窗限流窗口 (分钟)

log:
  level: "info"
  file: "${LOGS_DIR}/panel.log"
  max_size: 100
  max_backups: 7
  max_age: 30
  compress: true

database:
  path: "${DATA_DIR}/panel.db"

xray:
  binary_path: "${XRAY_BIN}"
  config_path: "${XRAY_CONF_DIR}/config.json"
  assets_path: "${XRAY_ASSETS_DIR}"
  api_port: 10085
  socket_dir: "/dev/shm"

nginx:
  config_dir: "${NGINX_CONF_DIR}"
  stream_dir: "${NGINX_STREAM_DIR}"
  reload_cmd: "systemctl reload nginx"
  cert_dir: "/root/.acme.sh"
EOF
    chmod 600 "${CONFIG_FILE}"
    success "配置文件已创建: ${CONFIG_FILE}"
}

write_systemd_service() {
    info "安装 systemd 服务 ${SERVICE_FILE}..."
    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Xray Panel Server (Headless API)
After=network.target xray.service
Wants=network.target

[Service]
Type=simple
User=root
Environment=HOME=/root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BINARY_PATH} server --config ${CONFIG_FILE}
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
    success "systemd 服务注册完成"
}

ensure_initial_token() {
    local count
    count="$("${BINARY_PATH}" token list --config "${CONFIG_FILE}" 2>/dev/null | awk 'NR>1 && NF>0 {c++} END {print c+0}')"
    if [[ "${count}" -eq 0 ]]; then
        info "正在生成初始静态 API Token (用于 xray-panel-desktop 接入)..."
        echo ""
        "${BINARY_PATH}" token create --name "initial-admin" --config "${CONFIG_FILE}"
        echo ""
    else
        info "数据库中已存在 ${count} 个 API Token；如需新建请运行："
        echo "  ${BINARY_PATH} token create --name <设备名> --config ${CONFIG_FILE}"
    fi
}

cmd_install() {
    check_root
    detect_os
    detect_arch
    install_dependencies
    install_xray
    prepare_nginx
    install_acme
    install_server_binary
    write_config
    ensure_initial_token
    write_systemd_service
    check_ssh_tunnel_prereqs

    systemctl restart "${SERVICE_NAME}"
    sleep 1
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        success "xray-panel-server 安装并启动成功！"
        echo -e "${CYAN}提示：${NC}"
        echo "  - API 监听地址: ${DEFAULT_LISTEN}"
        echo "  - 配置文件路径: ${CONFIG_FILE}"
        echo "  - 桌面端连接方式: 使用 SSH 隧道 (连接本机 sshd 后经 direct-tcpip 转发至 ${DEFAULT_LISTEN}) + 上方 xrp_... API Token"
        echo "  - 若无法连接，请确认已配置 SSH 公钥/密码登录且 sshd 开启 AllowTcpForwarding yes"
        echo "  - 常用命令: ${BINARY_PATH} token list | create | revoke"
    else
        error "服务启动失败，请检查日志: journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
        exit 1
    fi
}

cmd_update() {
    check_root
    detect_arch
    install_server_binary
    systemctl restart "${SERVICE_NAME}"
    sleep 1
    systemctl status "${SERVICE_NAME}" --no-pager -l || true
    success "xray-panel-server 升级完成"
}

cmd_uninstall() {
    check_root
    local purge="${1:-}"

    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload || true
    rm -f "${BINARY_PATH}"

    if [[ "${purge}" == "--purge" ]]; then
        rm -rf "${INSTALL_DIR}"
        warn "已连同 ${INSTALL_DIR} 数据目录彻底清理"
    else
        info "已卸载二进制与服务；数据与配置保留在 ${INSTALL_DIR}（传入 --purge 可彻底清理）"
    fi
    success "卸载完成"
}

cmd_status() {
    echo "=== xray-panel-server ==="
    systemctl status "${SERVICE_NAME}" --no-pager -l 2>/dev/null || echo "未安装或未运行"
    echo ""
    echo "=== xray ==="
    systemctl status xray --no-pager -l 2>/dev/null || echo "未安装或未运行"
    echo ""
    echo "=== nginx ==="
    systemctl status nginx --no-pager -l 2>/dev/null || echo "未安装或未运行"
}

print_usage() {
    cat <<'EOF'
Xray Panel Server 一键安装 / 升级 / 卸载 / 运维脚本
适用系统: Ubuntu / Debian / CentOS / Rocky Linux / AlmaLinux / Alpine

用法:
  install.sh install [--bin /path/to/xray-panel-server] [--listen 127.0.0.1:8082]
  install.sh update [--bin /path/to/xray-panel-server]
  install.sh uninstall [--purge]
  install.sh update-geo
  install.sh status
EOF
}

ACTION="${1:-install}"
if [[ "${ACTION}" == "-h" || "${ACTION}" == "--help" ]]; then
    print_usage
    exit 0
fi
if [[ $# -gt 0 ]]; then
    shift
fi

PURGE_FLAG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin)
            LOCAL_BIN="$2"
            shift 2
            ;;
        --listen)
            DEFAULT_LISTEN="$2"
            shift 2
            ;;
        --purge)
            PURGE_FLAG="--purge"
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            error "未知参数: $1"
            exit 1
            ;;
    esac
done

case "${ACTION}" in
    install)
        cmd_install
        ;;
    update)
        cmd_update
        ;;
    uninstall)
        cmd_uninstall "${PURGE_FLAG}"
        ;;
    update-geo)
        check_root
        update_geo
        ;;
    status)
        cmd_status
        ;;
    *)
        error "未知子命令: ${ACTION} (支持 install / update / uninstall / update-geo / status)"
        exit 1
        ;;
esac
