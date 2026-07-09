# AScan 🔑

扫描 API 工具、IDE、CLI、AI 平台的缓存和配置文件，检测泄露的密钥和敏感信息。

支持 **Windows / macOS / Linux** 三平台，覆盖 **216 款工具**，内置 **165 条检测规则**。

## 功能特性

- **多工具全覆盖** — 扫描 216 款 API 工具、IDE、AI 平台、云服务商的缓存与配置文件
- **多平台支持** — Windows、macOS、Linux 全平台支持，自动识别当前操作系统路径
- **智能检测** — 165 条正则规则，覆盖 API Key、Token、Secret、Private Key 等敏感信息
- **假阳性过滤** — 内置占位符检测、已知公共值过滤，减少误报
- **分级报告** — Critical / High / Medium / Low 四级严重程度，支持按级别过滤
- **多种输出格式** — JSON / CSV / TXT / 摘要，CSV 带 UTF-8 BOM 兼容 Excel
- **高效扫描** — 快速关键词预过滤 + 二进制文件跳过 + 并发扫描（工具级 4 并发、文件级 8 并发）
- **值脱敏** — 发现的值默认仅显示前 6 后 4 字符，保护隐私

## 支持的工具分类

| 分类 | 数量 | 示例 |
|------|------|------|
| 🖥️ **API GUI 工具** | 24 | Postman, Insomnia, Bruno, Apifox, Hoppscotch, Altair GraphQL, MQTTX... |
| 📝 **IDE 工具** | 11 | VS Code, IntelliJ, Thunder Client, REST Client, httpYac... |
| 🔧 **CLI 工具** | 35 | cURL, HTTPie, Hurl, vegeta, wrk, Apache Bench, OWASP ZAP, Burp Suite... |
| ⚙️ **系统配置** | 44 | SSH, Git, AWS CLI, GCloud, Azure, Docker, Kubernetes, Terraform, Env Files... |
| 🏗️ **基础设施** | 26 | nginx, Apache, Redis, MySQL, MongoDB, Kafka, Prometheus, Grafana... |
| 🤖 **AI 平台** | 76 | OpenAI, Anthropic, Claude, Hugging Face, Replicate, Ollama, LangChain, Cursor, Windsurf, Copilot, Devin... |

**总计: 216 款工具**

## 快速开始

### 下载预编译二进制

从 [Releases](https://github.com/your-username/AScan/releases) 下载对应平台的二进制文件：

| 平台 | 文件 |
|------|------|
| Windows amd64 | `ascan-windows-amd64.exe` |
| Windows arm64 | `ascan-windows-arm64.exe` |
| Linux amd64 | `ascan-linux-amd64` |
| macOS amd64 | `ascan-darwin-amd64` |
| macOS arm64 | `ascan-darwin-arm64` |

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/your-username/AScan.git
cd AScan

# 编译当前平台
go build -o ascan .

# 全平台编译
# Windows
build.bat
# macOS / Linux
chmod +x build.sh && ./build.sh
```

## 使用方法

```bash
# 扫描所有工具
ascan

# 详细输出模式
ascan -v

# 只扫描指定工具（名称包含匹配，不区分大小写）
ascan -t postman
ascan -t insomnia

# 只输出指定严重程度的发现
ascan -s Critical
ascan -t aws -s High

# 输出到指定目录
ascan -o ./results

# 列出所有支持的工具及其缓存路径
ascan --list

# 静默模式（仅保存报告，不打印终端输出）
ascan --silent
```

### 命令行选项

| 选项 | 说明 |
|------|------|
| `-o, --output <dir>` | 输出统计目录（默认: `./api-key-stats/`） |
| `-t, --tool <name>` | 只扫描指定工具（名称包含匹配，不区分大小写） |
| `-s, --severity <level>` | 只输出指定严重程度的发现（Critical/High/Medium/Low） |
| `-v, --verbose` | 详细输出，打印每个扫描的文件 |
| `--list` | 列出所有支持的工具及其缓存路径 |
| `--silent` | 静默模式，不打印控制台输出 |

## 输出格式

扫描完成后在输出目录生成以下文件：

### JSON 格式
完整的扫描结果，包含所有元数据、工具统计和发现详情。

### CSV 格式
带 UTF-8 BOM 的 CSV 文件，可直接用 Excel 打开。包含字段：Tool, File, Line, Type, Value (Masked), Severity, Context。

### TXT 格式
人类可读的详细报告，包含按工具统计、按严重程度统计、按密钥类型统计和详细发现列表。

### 摘要格式
简洁的单行摘要，适合快速查看或 CI 集成。

## 示例输出

```
========================================
  AScan - 扫描结果
========================================
  时间: 2026-07-09 10:39:55
  系统: Windows/amd64 | 主机: DESKTOP-ABC123
  扫描文件: 42 | 发现: 3
----------------------------------------
  Critical: 1 | High: 1 | Medium: 1 | Low: 0
----------------------------------------
  按工具分布:
    Shell_History                 : 1
    gitconfig                     : 1
    Browser_Cookies               : 1
========================================
```

## 跨平台注意事项

### Windows
- 自动识别 `%USERPROFILE%`、`%APPDATA%`、`%LOCALAPPDATA%`、`%PROGRAMFILES%` 等环境变量
- PowerShell 历史记录路径自动适配
- 支持 `\` 和 `/` 路径分隔符

### macOS
- 自动识别 `~/Library/Application Support`、`~/Library/Caches` 等路径
- 支持 Keychain 相关工具路径

### Linux
- 自动识别 `~/.config`、`~/.cache` 等 XDG 标准路径
- 支持 Snap、Flatpak 等包管理器的路径

## 安全说明

- **只读扫描**：工具不会修改任何文件，仅读取和检测
- **值脱敏**：发现的密钥默认仅显示前 6 后 4 字符（如 `sk-proj...f4Ab`）
- **本地运行**：所有扫描在本地执行，数据不会上传到任何外部服务
- **隐私保护**：报告文件保存在本地指定目录，请妥善保管

## 技术架构

```
AScan/
├── main.go                 # 入口、CLI 参数解析
├── go.mod                  # Go 模块定义
├── build.bat               # Windows 构建脚本
├── build.sh                # Unix 构建脚本
├── .gitignore
├── README.md
└── scanner/
    ├── scanner.go          # 核心扫描逻辑、并发控制、文件遍历
    ├── detector.go         # 检测引擎、165 条正则规则、值脱敏
    ├── reporter.go         # 报告生成（JSON/CSV/TXT/Summary）
    ├── tools.go            # Tool 结构体、路径解析、聚合入口
    ├── tools_gui.go        # GUI 工具定义（24 款）
    ├── tools_ide.go        # IDE 工具定义（11 款）
    ├── tools_cli.go        # CLI 工具定义（35 款）
    ├── tools_config.go     # 配置工具定义（44 款）
    ├── tools_infra.go      # 基础设施工具定义（26 款）
    └── tools_ai.go         # AI 平台工具定义（76 款）
```

## 许可证

MIT License