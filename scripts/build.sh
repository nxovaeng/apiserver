#!/usr/bin/env bash

#
# Xray Panel Server 本地 / CI 自动构建与打包脚本
# 用法:
#   ./scripts/build.sh [--arch both|amd64|arm64] [--version v0.1.0] [--out dist] [--package]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ARCH_MODE="both"
VERSION=""
OUT_DIR="dist"
DO_PACKAGE="false"
BINARY_NAME="xray-panel-server"
PKG_PREFIX="apiserver"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            ARCH_MODE="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --out)
            OUT_DIR="$2"
            shift 2
            ;;
        --package)
            DO_PACKAGE="true"
            shift
            ;;
        -h|--help)
            sed -n '4,7p' "$0"
            exit 0
            ;;
        *)
            echo "未知参数: $1" >&2
            exit 1
            ;;
    esac
done

cd "${REPO_DIR}"

if [[ -z "${VERSION}" ]]; then
    VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo 'v0.1.0')"
fi
BUILD_TIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

case "${ARCH_MODE}" in
    both|all)
        ARCHS=("amd64" "arm64")
        ;;
    amd64|amd64-only)
        ARCHS=("amd64")
        ;;
    arm64|arm64-only)
        ARCHS=("arm64")
        ;;
    *)
        echo "不支持的架构选项: ${ARCH_MODE} (允许: both, amd64, arm64)" >&2
        exit 1
        ;;
esac

mkdir -p "${OUT_DIR}"

for ARCH in "${ARCHS[@]}"; do
    BIN_FILE="${OUT_DIR}/${BINARY_NAME}-linux-${ARCH}"
    echo "==> 构建 ${BIN_FILE} (version=${VERSION}, build=${BUILD_TIME})"
    CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" go build -trimpath \
        -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
        -o "${BIN_FILE}" \
        ./cmd/server

    (cd "${OUT_DIR}" && sha256sum "${BINARY_NAME}-linux-${ARCH}" > "${BINARY_NAME}-linux-${ARCH}.sha256")
    echo "    产物大小: $(du -sh "${BIN_FILE}" | cut -f1)"

    if [[ "${DO_PACKAGE}" == "true" ]]; then
        PKG_NAME="${PKG_PREFIX}-${VERSION}-linux-${ARCH}"
        PKG_DIR="${OUT_DIR}/${PKG_NAME}"
        rm -rf "${PKG_DIR}"
        mkdir -p "${PKG_DIR}/bin" "${PKG_DIR}/conf" "${PKG_DIR}/scripts" "${PKG_DIR}/api"

        cp "${BIN_FILE}" "${PKG_DIR}/bin/${BINARY_NAME}-linux-${ARCH}"
        chmod +x "${PKG_DIR}/bin/${BINARY_NAME}-linux-${ARCH}"
        cp conf/config.yaml.example "${PKG_DIR}/conf/"
        cp scripts/install.sh "${PKG_DIR}/scripts/"
        chmod +x "${PKG_DIR}/scripts/install.sh"
        cp api/openapi.yaml "${PKG_DIR}/api/"
        [[ -f README.md ]] && cp README.md "${PKG_DIR}/"

        (
            cd "${OUT_DIR}"
            tar czf "${PKG_NAME}.tar.gz" "${PKG_NAME}"
            sha256sum "${PKG_NAME}.tar.gz" > "${PKG_NAME}.tar.gz.sha256"
            rm -rf "${PKG_NAME}"
        )
        echo "    归档完成: ${OUT_DIR}/${PKG_NAME}.tar.gz"
    fi
done

echo "==> 构建完成，输出目录: ${OUT_DIR}"
ls -lh "${OUT_DIR}"
