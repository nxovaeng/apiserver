# xray-panel-server

无头（Headless）纯 Server 模式 Xray / Nginx / WireGuard 控制面 API 服务与 CLI 工具，专为与桌面控制端 `xray-panel-desktop` 通过 SSH 隧道或加密通道对接而设计。

## 核心特性

- **无前端零公网后台暴露**：默认仅监听 `127.0.0.1:8082`，无需向公网开放后台登录页，推荐由 `xray-panel-desktop` 通过 SSH `direct-tcpip` 隧道安全访问。
- **纯 Server 模式**：移除 legacy 客户端模式及直连代理分支，专注于 VLESS / Trojan / WireGuard 中转入站、多出站落地（Direct / SOCKS5 / WireGuard / Trojan / VLESS / VMess）、路由与订阅下发。
- **静态 SHA-256 Bearer API Token 认证**：
  - 使用 `xrp_<48 chars>` Token，数据库仅保存 SHA-256 哈希，明文仅在签发时展示一次。
  - 仅接受 `Authorization: Bearer <token>`（显式拒绝 URL Query 参数中的 Token 凭证）。
  - 滑动窗口 IP 失败限流（429 `RATE_LIMITED`）防暴力枚举。
  - 支持配置文件静态 `auth.bootstrap_tokens` 与 CLI/API 动态签发、吊销和删除。
- **OpenAPI 3.0 契约**：完整 REST API 定义位于 [`api/openapi.yaml`](api/openapi.yaml)，所有接口统一返回 `{ success, data, error }` JSON 包裹结构。
- **动态订阅路由与配置校验**：支持管理后台热修改 `sub_path` 即时生效；应用 Xray 配置前先执行 `xray -test -c` 校验，再同步受控 Nginx 配置（含泛域名通配符证书匹配）。

## 快速构建

需要 Go `1.22+`：

```bash
# 本地构建
make build

# 交叉编译 Linux release 二进制产物 (bin/xray-panel-server-linux-amd64 & arm64)
make release

# 本地一键构建并打包 tar.gz + sha256（输出到 dist/）
make package
# 或按需指定架构与版本：
./scripts/build.sh --arch both --version v0.1.0 --out dist --package

# 运行单元测试与接口测试
make test
```

## GitHub Actions 自动构建（`nxovaeng/apiserver`）

仓库已内置 3 套 GitHub Actions 工作流（位于 `.github/workflows/`）：

- [`ci.yml`](.github/workflows/ci.yml)：向 `main` 分支推送或提交 PR 时自动运行 `gofmt` 检查、`go vet ./...`、`go test -race -count=1 ./...`，以及 `linux/amd64` + `linux/arm64` 交叉编译校验。
- [`release.yml`](.github/workflows/release.yml)：推送 `v*` 标签（如 `git tag v0.1.0 && git push origin v0.1.0`）或在 Actions 页面手动触发时自动运行测试、交叉打包，并发布 GitHub Release（同时附带单文件二进制、`apiserver-<version>-linux-<arch>.tar.gz` 与 `.sha256` 校验文件）。
- [`build-flexible.yml`](.github/workflows/build-flexible.yml)：手动按需选择构建架构（`both` / `amd64-only` / `arm64-only`）、是否跑测试、是否创建 Pre-release。

## 服务器安装与运维

使用一键脚本 [`scripts/install.sh`](scripts/install.sh) 部署为系统服务 `xray-panel-server.service`（未指定 `--bin` 时默认从 `nxovaeng/apiserver` 最新 Release 下载）：

```bash
# 在线一键安装（需先在 GitHub Releases 发布过至少一个版本；请使用管道传给 sudo bash）
curl -fsSL https://raw.githubusercontent.com/nxovaeng/apiserver/main/scripts/install.sh | sudo bash -s -- install

# 使用本地编译二进制安装（自动安装 Xray-core、Nginx、生成 config.yaml、创建初始 Token 并注册 systemd）
sudo bash scripts/install.sh install --bin ./bin/xray-panel-server-linux-amd64

# 升级二进制
sudo bash scripts/install.sh update --bin ./bin/xray-panel-server-linux-amd64

# 更新 GeoIP / GeoSite 数据库
sudo bash scripts/install.sh update-geo

# 查看服务状态 / 卸载（传入 --purge 会同时删除 /opt/xray-panel）
sudo bash scripts/install.sh status
sudo bash scripts/install.sh uninstall
```

## CLI 命令参考

```bash
# 启动无头 API 服务
xray-panel-server server --config /opt/xray-panel/config.yaml

# Token 管理（纯 stdout 输出，可安全脚本化）
xray-panel-server token create --name "macbook" --days 365 --config /opt/xray-panel/config.yaml
xray-panel-server token list --config /opt/xray-panel/config.yaml
xray-panel-server token revoke --id <token-id> --config /opt/xray-panel/config.yaml
xray-panel-server token revoke --id <token-id> --purge --config /opt/xray-panel/config.yaml

# Nginx 同步 / 重载 / 为面板生成 HTTPS 反代配置
xray-panel-server nginx sync --config /opt/xray-panel/config.yaml
xray-panel-server nginx reload --config /opt/xray-panel/config.yaml
xray-panel-server nginx panel -d panel.example.com -cert /path/fullchain.cer -key /path/key.key

# 版本信息
xray-panel-server version
```

## 配置文件说明

参考 [`conf/config.yaml.example`](conf/config.yaml.example)：

- `server.listen`: 默认 `"127.0.0.1:8082"`，SSH 隧道模式下保持回环地址即可。
- `auth.bootstrap_tokens`: 可选静态引导 Token 列表（格式 `xrp_...`）。
- `auth.fail_limit` / `auth.fail_window_minutes`: IP 认证失败限流阈值与滑窗分钟数。
- `xray.socket_dir`: 默认 `"/dev/shm"`，用于高性能 UDS 入站监听。
- `nginx.config_dir` / `nginx.cert_dir`: Nginx HTTP 站点配置（`/etc/nginx/conf.d`）及 ACME 证书扫描目录（`nginx.stream_dir` 为预留配置项，当前版本不生成 `stream` 配置）。

## SSH 隧道接入（服务端要求与排查）

`xray-panel-desktop` 使用标准 SSH `direct-tcpip` 通道（等效于进程内免端口的 `ssh -L`）经由服务器自带 **OpenSSH (`sshd`)** 转发访问远端 `127.0.0.1:8082`，因此：

1. **无需在服务端额外安装或运行隧道程序**，也无需对公网放行 `8082` 端口（只需 `22` 端口的 SSH 正常可连）。
2. **检查 `/etc/ssh/sshd_config`**：部分安全加固系统或云厂商镜像会关闭转发，请确保：
   ```text
   AllowTcpForwarding yes
   # 不要设置 DisableForwarding yes
   # 如配置过 PermitOpen，需允许 127.0.0.1:8082（默认不限制）
   ```
   修改后重载 SSH 服务：`systemctl reload sshd`（Ubuntu/Debian 为 `systemctl reload ssh`）。
3. **准备 SSH 登录凭据与 API Token**：
   - 将桌面端私钥对应的公钥写入服务端对应用户的 `~/.ssh/authorized_keys`（或确认开启 `PasswordAuthentication yes`）。
   - 确保桌面端 Profile 中的 **远端监听地址:端口** 与服务端 `config.yaml` 的 `server.listen`（默认 `127.0.0.1:8082`）一致，并填入 `install.sh` 或 `xray-panel-server token create` 生成的 `xrp_...` Token。

## Nginx 与共用 443 端口说明

1. **当前生成机制**：[`internal/nginx`](internal/nginx/templates.go) **仅在 Nginx `http` 块（`/etc/nginx/conf.d/<domain>.conf`）生成 `server { listen 443 ssl; http2 on; ... }`**，通过 TLS SNI + HTTP `location`（XHTTP / WebSocket / gRPC）反代到 Xray 的 UDS 或 `127.0.0.1` 端口，**不会写入 `stream.d` 配置**。
2. **与现有站点共用 443**：
   - **不同子域名（推荐）**：只要服务器原有网站与节点域名不同（如 `www.example.com` 与 `node.example.com`），Nginx `http` 块原生支持多个 `server { listen 443 ssl; }` 共用 443 端口。
   - **同域名且已有手写配置文件**：出于安全考虑，本程序不会覆盖首行没有 `# Managed by Xray Panel` 标记的既有配置文件；此时请勿在入站中绑定该域名，改为在入站设置 **自定义 SNI**，并在你现有的 `nginx` `server` 块中手动添加对应 `location` 反代。
   - **关于 Nginx `stream` 443 分流**：在同一台机器上，Nginx 的 `stream { listen 443; }` 与 `http { listen 443 ssl; }` **无法同时监听 443**（端口占用冲突）。如果确实需要 `stream` 做 L4 SNI 分流，必须把**所有** HTTP `server` 块改为监听内网端口（如 `127.0.0.1:444`），再由自定义 `stream` 接管 443；本程序暂不自动接管 `stream` 配置。

## 目录结构

```text
xray-panel-server/
├── api/openapi.yaml           # OpenAPI 3.0 接口契约
├── cmd/server/main.go         # CLI 与服务端入口
├── conf/config.yaml.example   # 配置模板
├── internal/
│   ├── api/                   # Gin 路由、Bearer/限流中间件、v1 handler、SSE 与 workers
│   ├── config/                # YAML 配置加载
│   ├── database/              # SQLite 初始化、迁移与种子数据
│   ├── dto/                   # 请求/响应数据传输对象
│   ├── geodata/               # geosite.dat / geoip.dat 解析
│   ├── logger/                # 日志封装
│   ├── models/                # GORM 数据模型与默认设置/路由预设
│   ├── nginx/                 # Nginx HTTP 反代配置生成器（conf.d）
│   ├── service/               # 业务逻辑（Token/User/Inbound/Outbound/Routing/Domain/WG/System/Subscription）
│   ├── system/                # 主机指标采集与 systemd 日志读取
│   ├── utils/                 # 证书解析、随机值、分享链接解析
│   ├── wireguard/             # 内核 WireGuard 管理、环境检测与运行时统计
│   └── xray/                  # 纯 Server 模式 Xray config.json 生成与 gRPC 流量统计
├── scripts/install.sh         # 安装 / 升级 / 卸载 / GeoData 更新脚本
├── Makefile
└── go.mod
```
