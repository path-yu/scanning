# Scanning

本地 HTTP/HTTPS 抓包与流量分析工具。后端 Go，前端 React + TypeScript + MUI，采用前后端分离但单可执行文件分发。

功能覆盖 M0–M4，并已实现 M5a（桌面应用启动器）、M5b（进程归属）与 M5c（Windows 进程注入，实验）。

## 功能

- **双引擎采集**：MITM 代理（HTTP/HTTPS 解密）+ 网卡/PCAP 报文采集，共享统一 Flow 模型、过滤语法与存储。
- **上游代理链式转发**：可把 Scanning 接在本地 VPN/公司代理前面，支持 HTTP/HTTPS 上游代理与 Basic 认证。
- **桌面应用抓包**：选择可执行文件后以子进程启动并注入代理环境变量，不修改系统代理；流量可归因到进程名、PID 与可执行文件路径。
- **进程注入抓包（Windows 实验）**：向不读取代理设置的桌面进程注入 Hook DLL，通过 IAT Hook 接管 `connect` / `WSAConnect` / `ConnectEx`，把 80/443 直连流量送入本机 MITM 代理。不依赖 WinDivert 或内核驱动。
- **网易云 EAPI 解码**：自动识别 `*.music.163.com` 的 `/eapi/` 请求与响应，使用 AES-128-ECB 解密并以 JSON 展示；下载按钮默认导出 `.json`，同时保留原始密文 `.bin` 下载。
- **关键字全文搜索**：在过滤框直接输入关键字（例如 `Taylor Swift`），服务端会同时检索 URL、请求/响应头与完整正文（含 EAPI 解密后的 JSON），实时过滤 Flow 列表。
- **JSON 全屏查看**：响应 JSON 支持全屏弹窗与可折叠树形展示；字符串中的 http(s) 链接可直接点击在新标签页打开。
- **系统代理一键接管**：Windows 下可一键把系统代理切到 8899，自动备份原设置并支持还原；退出程序时会安全恢复。
- **流量工作台**：实时列表、过滤表达式、域名统计、请求/响应详情、正文查看（gzip/deflate 解码）、HAR 导出。
- **规则引擎**：按优先级执行，支持 host/path/method/status/mime/header/body 匹配，以及 Mock、阻断、延迟、远端映射、请求/响应改写、断点。
- **断点**：请求/响应阶段暂停、编辑后放行或中止，默认 60 秒超时自动放行。
- **重放与对比**：修改方法/URL/请求头/正文后重放，并与原响应做 Diff。
- **会话存档**：SQLite 持久化，保存、加载、删除会话快照。
- **报文视图**：纯 Go PCAP 读写，以太网/链路层、IPv4/IPv6、TCP/UDP、DNS、TLS ClientHello 解码，TCP 重组还原明文 HTTP。
- **采集渠道**：PCAP 导入/导出/清空、代理镜像合成 TCP 报文、Npcap 实时网卡（Windows）。
- **首次引导与自检**：一键启动代理、安装 CA、运行 DNS/TCP/TLS/HTTP 全链路自检。

## 环境要求

- Go 1.24+
- Node.js 20+（仅构建前端时需要）
- Windows 进程注入模式需要 x64 目标进程与相同权限；Hook DLL 使用 [Zig](https://ziglang.org/download/) 交叉编译（也可把 `HOOK_CC` 指向任意支持 `x86_64-windows-gnu` 的编译器）
- Windows 实时网卡抓包额外需要 [Npcap](https://npcap.com/#download)（安装时勾选 WinPcap 兼容模式）与管理员权限

## 构建

生产构建会先把前端产物嵌入 Go 二进制。Windows PowerShell：

```powershell
cd web
npm install
npm run build
cd ..
go build -ldflags "-s -w -X scanning/internal/version.Version=0.1.0" -o bin/scanning.exe ./cmd/scanning
```

Windows 实时网卡版本（纯 Go + syscall，无 cgo 依赖）：

```powershell
go build -tags wpcap -ldflags "-s -w" -o bin/scanning.exe ./cmd/scanning
```

构建进程注入 Hook DLL（Windows x64）：

```powershell
# 安装 Zig 后确保 zig 在 PATH，或显式指定：
# make hook HOOK_CC=C:/tools/zig/zig.exe
make hook
# 等价命令：
zig cc -target x86_64-windows-gnu -shared -O2 `
  -o bin/hook/scanning_hook_x64.dll `
  internal/hook/native/scanning_hook.c -lws2_32
```

生成的 DLL 固定放在 `bin/hook/scanning_hook_x64.dll`，程序会优先从可执行文件旁的 `hook/` 目录查找。

macOS / Linux 或已安装 GNU Make 的环境：

```bash
make build        # 普通构建
make build-wpcap  # Windows Npcap 构建
make test         # go test + 前端类型检查
```

开发模式（Vite 热更新）：

```bash
# 终端 1
cd web && npm run dev
# 终端 2
go run -tags dev ./cmd/scanning --dev
```

开发模式下跳过 API 鉴权，Vite 将 `/api` 代理到 `127.0.0.1:8898`；该模式默认启用演示数据，生产运行默认不生成模拟流量。

## 运行

```powershell
bin/scanning.exe
```

- 控制台：`http://127.0.0.1:8898`（默认自动打开浏览器）
- 代理：`127.0.0.1:8899`（默认随程序启动）
- 数据目录：Windows `%APPDATA%\Scanning`，macOS `~/Library/Application Support/Scanning`，Linux `~/.local/share/scanning`
- 访问令牌写入数据目录下的 `runtime.json`；浏览器首次打开控制台时会自动获得会话 Cookie

常用参数：

| 参数 | 说明 |
| --- | --- |
| `--addr 127.0.0.1:8898` | 控制台/API 监听地址 |
| `--config path.yaml` | 指定配置文件，默认读取数据目录 `config.yaml` |
| `--data-dir path` | 覆盖数据目录 |
| `--no-open` | 启动后不自动打开浏览器 |
| `--no-proxy` | 不自动启动代理 |
| `--headless` | 不提供 Web UI |
| `--dev` | 开发模式（跳过鉴权，允许 Vite 来源） |
| `--version` | 输出版本 |

## 三步开始抓包

1. **启动代理**：顶栏状态胶囊或「快速开始」中启动，默认监听 `127.0.0.1:8899`。
2. **安装并信任 CA**：在「代理与 HTTPS 证书」或「快速开始」中安装到当前用户；Firefox 需单独导入。
3. **把流量指向代理**：系统代理或环境变量：

   ```bash
   export HTTPS_PROXY=http://127.0.0.1:8899
   export HTTP_PROXY=http://127.0.0.1:8899
   ```

最后点击「运行自检」，会通过代理发起真实 HTTPS 请求，依次检查 DNS、代理端口、TLS 解密与 HTTP 往返。自检需要外网；离线环境可使用 PCAP 导入。

不想修改系统代理时，可在「代理与 HTTPS 证书」或「快速开始」中点击「抓包浏览器」：它会用独立配置目录启动 Edge/Chrome/Chromium，仅该窗口走 `127.0.0.1:8899`，其他应用不受影响。

## 系统代理一键接管

打开「代理与 HTTPS 证书」→「系统代理」：

- 点击「接管系统代理」，会把 Windows 当前用户（HKCU）Internet Settings 的代理写入 `127.0.0.1:8899`；
- 接管前会自动备份 `ProxyEnable`、`ProxyServer`、`ProxyOverride`、`AutoConfigURL`，保存在数据目录 `proxy-backup.json`；
- 点击「还原系统代理」可恢复接管前的完整设置；
- 正常退出 Scanning 时，如果系统代理仍指向本工具，会自动还原；若已被其他程序修改则不覆盖。

注意：

- 当前仅 Windows 支持一键接管；macOS/Linux 会提示手动设置系统代理。
- 只修改 WinINET（浏览器、多数桌面应用），不会修改 WinHTTP 机器级代理。
- 接管期间所有应用的流量都会经过 Scanning；Scanning 已配置上游代理时仍可正常上网。

## 桌面应用抓包

点击顶栏「桌面应用抓包」图标：

1. 选择或填写可执行文件路径（Windows 仅支持 `.exe`/`.com`）；
2. 可选填写启动参数（每行一个）与工作目录；
3. 点击「启动并抓包」，应用会以子进程启动，并注入：

   ```text
   HTTP_PROXY=http://127.0.0.1:8899
   HTTPS_PROXY=http://127.0.0.1:8899
   NO_PROXY=127.0.0.1,localhost,::1
   ```

4. 最近启动的应用会保存在数据目录 `recent-apps.json`，可一键再次启动。

启动后约 6 秒会自动检测该应用是否真正走了代理：若捕获到经 8899 的请求，显示「已走代理」；若目标进程没有任何代理连接，则显示「未走代理」并列出检测到的直连目标地址。

注意：

- 只有读取环境变量代理的应用才能被这种方式捕获；不读取的应用可改用下方的进程注入模式，或使用网卡抓包。
- Chromium/Electron 应用可勾选「追加 --proxy-server 参数」，其他应用可能因未知参数退出。
- 启动器以当前用户权限运行目标程序，不会自动提权或结束进程；启动与文件选择接口仅允许本机访问。
- 进程归属在 Windows 与 Linux 上生效（Windows 使用 TCP 表 + PID，Linux 读取 `/proc`）；macOS 暂显示未知。
- 流量列表新增「进程」列，左侧栏可按进程筛选，HAR 导出包含进程与来源扩展字段。

## 进程注入抓包（Windows 实验）

对于不读取环境变量或系统代理的桌面应用（例如网易云音乐桌面端），可在「桌面应用抓包」对话框底部展开「进程注入（实验）」：

1. 启动代理并安装 CA；
2. 输入进程名（如 `cloudmusic.exe`）并点击「扫描进程」；
3. 选择单个 PID 注入，或勾选「注入全部同名进程」批量注入；
4. 注入后目标进程的 80/443 TCP 直连会改送到 `127.0.0.1:8899`，HTTPS 由 MITM 解密，HTTP 通过 Host 头还原域名；
5. 可在同一面板查看注入状态与 Hook 日志。

实现原理：

- Go 后端通过 `OpenProcess` + `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread(LoadLibraryW)` 注入 `scanning_hook_x64.dll`；
- DLL 扫描目标进程所有模块的 IAT，把 `ws2_32` 的 `connect`、`WSAConnect`、`WSAIoctl`（用于获取 `ConnectEx`）替换为 detour，并定期重扫新加载模块；
- detour 在目标 socket 上连接本机代理并完成 HTTP CONNECT 握手，代理按 TLS SNI / HTTP Host 还原域名后复用现有 Flow、规则、断点、重放与会话能力；
- 不使用 WinDivert、WFP 或内核驱动；只要与目标进程权限/完整性级别相同即可，通常无需管理员。
- 对网易云 `*.music.163.com` 的 `/eapi/` 流量，后端自动用 AES-128-ECB 解密 `params` 与响应体；请求/响应以 JSON 预览和格式化展示。点击「下载 JSON」导出 `.json`，锁形图标可下载原始密文 `.bin`。

实测（2026-10-23，网易云音乐 3.1.40 x64）：注入主进程后成功捕获并解密 `interfacepc.music.163.com`、`clientlog3.music.163.com` 等 HTTPS 请求，Flow 正确归因为 `cloudmusic.exe`（PID 27876）。

限制：

- 仅 Windows x64；32 位进程需要另行构建 x86 DLL。
- 目标进程与 Scanning 的权限/完整性级别需匹配；杀软、反作弊或进程保护可能拦截注入。
- 证书固定（Pinning）的客户端可能拒绝 MITM 解密。
- 仅接管 `hook.ports`（默认 80/443）的 TCP；UDP/QUIC 不会接管。
- 注入后不支持安全卸载，需重启目标进程恢复原始网络行为。
- EAPI 解密依赖客户端当前使用的固定密钥；客户端升级更换密钥后将自动回退为二进制占位。HAR 导出仍保留原始密文，解密 JSON 仅用于界面展示与下载。

## 关键字搜索与 JSON 全屏查看

- 过滤框直接输入关键字（支持空格，如 `Taylor Swift`）时，会匹配 URL、请求/响应头与完整正文；正文搜索由服务端完成，EAPI 密文会先解密再匹配。
- 字段过滤语法保持不变，例如 `method:POST and host:*.music.163.com`；纯关键字输入会自动触发正文搜索（约 280ms 防抖）。
- 响应详情正文工具栏的「全屏」按钮会打开全屏 JSON 视图，使用可折叠树形结构展示；值中的 http(s) 链接可直接点击在新标签页打开。

## 报文采集

进入顶栏「报文」视图，点击采集状态胶囊：

- **实时网卡**：选择网卡与 BPF 过滤，需要 Npcap 和管理员权限。
- **代理镜像**：把经过代理的 Flow 合成为 TCP 报文，无需驱动即可在报文视图查看。
- **导入 PCAP**：支持标准 PCAP，导入后生成报文、DNS 映射与可还原的明文 HTTP Flow。
- **导出 PCAP**：导出当前报文环形缓存。
- **DNS 面板**：查看域名到 IP 的映射与 TTL。

## 规则 / 断点 / 重放 / 会话

- 顶栏「规则」：新建或编辑规则，规则持久化到数据目录 `rules.json`。
- 断点：规则动作选择 `pause`；暂停中的 Flow 会出现在顶部提示与断点队列，可改包后放行。
- 重放：在 Flow 详情中选择重放，支持方法与正文覆盖，完成后查看 Diff。
- 会话：顶栏「会话存档」保存当前内存流量到 SQLite，或加载历史会话。

## 配置

默认配置即开即用，可在数据目录创建 `config.yaml` 覆盖。常用项：

```yaml
server:
  api_addr: 127.0.0.1:8898
  allow_remote: false
proxy:
  enabled: true
  addr: 127.0.0.1:8899
  mitm: true
  upstream_proxy: ""         # 例如 http://127.0.0.1:7890；留空表示直连上游
  max_body_bytes: 10485760
  breakpoint_timeout_seconds: 60
capture:
  enabled: false
  bpf: "tcp or udp or icmp or icmp6"
  buffer_packets: 20000
store:
  memory_flows: 50000
demo:
  enabled: false   # 默认关闭；需要演示数据时改为 true
```

完整字段与校验规则见 `internal/config/config.go`。

`upstream_proxy` 可省略 `http://` 前缀，用户名密码可写成 `http://user:pass@host:port`；不支持 SOCKS5。修改后需重启程序，代理对话框会显示当前生效的上游地址。

## API 摘要

所有接口位于 `/api/v1`，返回 `{ data, meta }` 或 `{ error: { code, message } }`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/system/info` | 运行信息、能力与代理/采集状态 |
| POST | `/system/selftest` | 全链路连通性自检 |
| GET | `/flows` | 流量列表（过滤、游标、排序） |
| GET | `/flows/search?q=` | 关键字全文搜索（URL/请求与响应头/正文），返回命中 Flow ID |
| GET | `/flows/{id}` | Flow 详情 |
| GET | `/flows/{id}/body` | 请求/响应正文 |
| POST | `/flows/{id}/replay` | 重放 |
| POST | `/flows/{id}/resume` | 断点放行/中止/改写 |
| GET/POST/PUT/DELETE | `/rules` | 规则管理 |
| GET/POST | `/sessions` | 会话存档 |
| GET | `/packets`、`/dns` | 报文与 DNS |
| POST | `/capture/start`、`/stop`、`/import`、`/mirror` | 采集控制 |
| POST | `/browser/launch` | 启动走本代理的独立浏览器窗口 |
| GET | `/apps`、`/apps/recent` | 已启动应用与最近应用 |
| POST | `/apps/launch` | 注入代理环境变量并启动桌面应用 |
| GET | `/hook/status` | 进程注入状态、DLL/代理/端口与已注入进程 |
| GET | `/hook/processes` | 按进程名扫描可注入进程 |
| POST | `/hook/inject` | 按 PID 或进程名注入 Hook DLL |
| GET | `/hook/log` | 读取 Hook DLL 进程内日志尾部 |
| POST | `/system/pick-file` | 在服务端桌面打开文件选择框 |
| GET | `/system/proxy-config` | 读取系统代理与备份状态 |
| POST | `/system/proxy-config/apply` | 一键接管系统代理并备份 |
| POST | `/system/proxy-config/restore` | 还原系统代理 |
| GET | `/export/pcap`、`/export/har` | 导出 |
| GET | `/proxy/status`、`/cert/status` | 代理与证书状态 |
| WS | `/events` | 实时事件（flow/stats/proxy/capture） |

未启用 `--dev` 时需要 Bearer Token 或会话 Cookie。

## 目录结构

```
cmd/scanning        程序入口
internal/api        HTTP API、鉴权、SPA 静态资源
internal/app        应用装配与生命周期
internal/blob       正文内容寻址存储
internal/capture    报文模型、PCAP、解码、TCP 重组、采集引擎
internal/export     HAR 导出
internal/flow       Flow 模型、过滤、演示数据
internal/hook       进程注入管理、Hook 配置与持久化
internal/hook/native Windows Hook DLL（C 源码）
internal/mitm       根 CA 与叶证书签发、安装
internal/persist    SQLite 会话存档
internal/proxy      MITM/转发、断点、重放
internal/rules      规则引擎
internal/store      Flow 环形缓存
web                 前端（Vite + React + MUI）
docs                技术设计文档
```

## 测试与发布

```bash
go vet ./...
go test ./...
cd web && npm run typecheck && npm run build
```

交叉编译（需要 GNU Make）：

```bash
make release
```

产物位于 `bin/`：

- `scanning-windows-amd64.exe`（含 Npcap 实时抓包）
- `scanning-linux-amd64`、`scanning-linux-arm64`
- `scanning-darwin-amd64`、`scanning-darwin-arm64`

未安装 Make 时，可直接执行 `GOOS`/`GOARCH`/`CGO_ENABLED=0` 的 `go build` 命令。项目暂不生成安装器。

## 已知限制

- 系统代理一键接管目前仅 Windows；macOS/Linux 需手动设置。只覆盖 WinINET，不覆盖 WinHTTP 或应用自有网络栈。
- 桌面应用启动器只能覆盖读取 `HTTP(S)_PROXY` 的应用；直连型应用可使用 Windows 进程注入模式（实验），但仅限 x64 且受权限/杀软限制。
- 进程注入不接管 UDP/QUIC，不适用于 32 位进程，注入后需重启目标进程才能完全恢复。
- 进程归属为尽力而为：Windows/Linux 有实现，macOS 暂未实现；权限不足时只显示 PID 或未知。
- 上游代理仅支持 HTTP/HTTPS（可带 Basic 认证），不支持 SOCKS5；修改配置后需要重启。
- 实时网卡抓包仅 Windows 构建支持，且需要 Npcap 与管理权限；无驱动时使用 PCAP 导入或代理镜像。
- WebSocket 升级请求经代理仍返回 `501`；SSE 响应不应用响应阶段规则。
- 规则正文匹配上限 512 KB；请求/响应正文默认最多保存 10 MB。
- QUIC/HTTP3、证书固定（Pinning）的客户端可能绕过代理或拒绝解密。
- 自检依赖外网目标（默认 `example.com`）；纯离线环境无法完成完整自检。
- 仅提供可执行文件，不含安装器、自动更新与代码签名；未进行 24 小时持续稳定性验证。
- 默认只监听回环地址；远程访问需显式开启 `server.allow_remote` 并自行配置访问控制。

## 安全与合规

- 仅抓取你拥有或已获授权的流量。
- 根 CA 私钥位于数据目录 `certs/ca.key`，仅本机用户可读；重新生成后旧证书立即失效。
- 非开发模式下 API 需要令牌；跨源写请求需携带 `X-Scanning-Request: 1`。
- 请勿将代理或控制台暴露到公网。

更详细的架构、存储与协议设计见 [docs/technical-design.md](docs/technical-design.md)。
