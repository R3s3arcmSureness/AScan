package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// 包级常量：严重程度权重映射，避免每次调用重新创建
var severityOrder = map[string]int{
	"Critical": 4,
	"High":     3,
	"Medium":   2,
	"Low":      1,
}

// 包级变量：预编译的二进制扩展名集合，避免每次调用重新创建 map
var binaryExts = map[string]bool{
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".bin": true, ".obj": true, ".o": true, ".a": true, ".lib": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true,
	".ico": true, ".webp": true, ".tiff": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true, ".wav": true,
	".zip": true, ".tar": true, ".gz": true, ".bz2": true, ".7z": true,
	".rar": true, ".xz": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true,
	".sqlite": true, ".db": true, ".sst": true,
	".class": true, ".pyc": true, ".pyo": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".jar": true, ".war": true, ".ear": true,
}

// Package 级变量：预编译的浏览器路径片段列表，避免每次扫描重复创建
var browserPathSegments = []string{
	"google-chrome", "chromium", "microsoft-edge", "microsoft edge",
	"mozilla", "firefox", "brave", "opera", "vivaldi", "user data",
}

// 包级变量：预编译的假阳性关键词列表，避免每次调用重新创建
var falsePositivePlaceholders = []string{
	"your_api_key", "your_api_token", "your_key_here",
	"placeholder", "xxxxxxxx", "changeme", "replace_me",
	"your-key", "your-token", "your-secret",
	"<api_key>", "<token>", "{{api_key}}", "{{token}}",
	"example", "sample", "test_", "dummy",
}

var falsePositiveKnownPublic = []string{
	"localhost", "127.0.0.1", "0.0.0.0",
	"undefined", "null", "none", "nil",
}

// ScanResult 是一次完整扫描的结果
type ScanResult struct {
	ScanTime    time.Time    `json:"scan_time"`
	OS          string       `json:"os"`
	Hostname    string       `json:"hostname"`
	TotalFiles  int          `json:"total_files_scanned"`
	TotalFound  int          `json:"total_findings"`
	Errors      []string     `json:"errors,omitempty"`
	ToolResults []ToolResult `json:"tool_results"`
	Findings    []Finding    `json:"findings"`
}

// ToolResult 单个工具的扫描统计
type ToolResult struct {
	Tool        string `json:"tool"`
	Path        string `json:"path"`
	FilesScanned int   `json:"files_scanned"`
	Findings    int    `json:"findings"`
	Error       string `json:"error,omitempty"`
	Exists      bool   `json:"path_exists"`
}

// Scanner 负责扫描工具缓存文件
type Scanner struct {
	Tools    []Tool
	Patterns []Pattern
	Verbose  bool
}

// NewScanner 创建一个扫描器实例
func NewScanner(verbose bool) *Scanner {
	return &Scanner{
		Tools:    AllTools(),
		Patterns: GetPatterns(),
		Verbose:  verbose,
	}
}

// ScanAll 扫描所有工具
func (s *Scanner) ScanAll() *ScanResult {
	hostname, _ := os.Hostname()

	osName := runtime.GOOS
	if len(osName) > 0 {
		osName = strings.ToUpper(osName[:1]) + osName[1:]
	}

	result := &ScanResult{
		ScanTime: time.Now(),
		OS:       fmt.Sprintf("%s/%s", osName, runtime.GOARCH),
		Hostname: hostname,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 4) // 限制并发数为4

	for i := range s.Tools {
		wg.Add(1)
		go func(tool Tool) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tr, findings := s.scanTool(tool)

			mu.Lock()
			result.ToolResults = append(result.ToolResults, tr)
			result.Findings = append(result.Findings, findings...)
			result.TotalFiles += tr.FilesScanned
			result.TotalFound += len(findings)
			mu.Unlock()
		}(s.Tools[i])
	}

	wg.Wait()
	return result
}

// scanTool 扫描单个工具
func (s *Scanner) scanTool(tool Tool) (ToolResult, []Finding) {
	tr := ToolResult{Tool: tool.Name}
	var findings []Finding

	paths := tool.GetPaths()
	if len(paths) == 0 {
		return tr, findings
	}

	for _, rootPath := range paths {
		// 展开通配符（支持任意位置的 *）
		resolvedPaths := s.resolvePaths(rootPath)
		if len(resolvedPaths) == 0 {
			continue
		}

		for _, rp := range resolvedPaths {
			if s.Verbose {
				fmt.Printf("  [扫描] %s: %s\n", tool.Name, rp)
			}

			info, err := os.Stat(rp)
			if err != nil {
				if s.Verbose && !os.IsNotExist(err) {
					fmt.Printf("  [跳过] %s: %v\n", rp, err)
				}
				continue
			}

			tr.Exists = true

			if info.IsDir() {
				filesScanned, f := s.scanDir(rp, tool, &tr)
				tr.FilesScanned += filesScanned
				findings = append(findings, f...)
			} else {
				f := s.scanFile(rp, tool, &tr)
				tr.FilesScanned++
				findings = append(findings, f...)
			}

			if tr.Path == "" {
				tr.Path = rp
			}
		}
	}

	tr.Findings = len(findings)
	return tr, findings
}

// scanDir 递归扫描目录
func (s *Scanner) scanDir(dirPath string, tool Tool, tr *ToolResult) (int, []Finding) {
	var filesScanned int
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	maxSize := tool.MaxFileSize
	if maxSize == 0 {
		maxSize = 1024 * 1024 // 默认 1MB
	}

	filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 跳过无法访问的文件
		}
		if d.IsDir() {
			base := strings.ToLower(d.Name())
			// 跳过明显的非缓存目录（通用噪声目录）
			if base == "node_modules" || base == ".git" || base == "__pycache__" ||
				base == "vendor" || (base == "cache" && strings.Contains(path, "node_modules")) {
				return filepath.SkipDir
			}
			// 跳过已知的纯二进制缓存目录（不包含 leveldb/indexeddb，浏览器工具需要扫描它们）
			if base == "code cache" || base == "gpucache" || base == "shader cache" ||
				base == "service worker" || base == "webgpu" || base == "webrtc" {
				return filepath.SkipDir
			}
			// 通用 cache 目录：仅当不是浏览器工具路径时跳过
			if base == "cache" || base == "caches" {
				lower := strings.ToLower(path)
				isBrowser := false
				for _, bp := range browserPathSegments {
					if strings.Contains(lower, bp) {
						isBrowser = true
						break
					}
				}
				if !isBrowser {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// 检查扩展名过滤
		if len(tool.Extensions) > 0 {
			ext := strings.ToLower(filepath.Ext(path))
			found := false
			for _, e := range tool.Extensions {
				if ext == e {
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		}

		// 检查文件大小
		info, err := d.Info()
		if err != nil || info.Size() > maxSize {
			return nil
		}

		// 先获取信号量再创建 goroutine，避免文件描述符耗尽
		sem <- struct{}{}
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			defer func() { <-sem }()

			f := s.scanFile(filePath, tool, tr)

			mu.Lock()
			filesScanned++
			findings = append(findings, f...)
			mu.Unlock()
		}(path)

		return nil
	})

	wg.Wait()
	return filesScanned, findings
}

// scanFile 扫描单个文件
func (s *Scanner) scanFile(filePath string, tool Tool, tr *ToolResult) []Finding {
	var findings []Finding

	// 二进制文件检测：跳过非文本文件
	if isBinaryFile(filePath) {
		return findings
	}

	// 文件大小安全限制：单文件超过 1MB 跳过，防止内存撑爆
	// info 由调用方传入，若为 nil 则自行 Stat
	info, err := os.Stat(filePath)
	if err != nil {
		return findings
	}
	maxSize := tool.MaxFileSize
	if maxSize == 0 {
		maxSize = 1024 * 1024 // 默认 1MB
	}
	if info.Size() > maxSize {
		return findings
	}
	// 空文件直接跳过
	if info.Size() == 0 {
		return findings
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return findings
	}

	// 快速关键词过滤：文件不含任何可疑关键词时直接跳过整个文件
	// 避免对无密钥文件进行逐行正则匹配，大幅提升扫描速度
	if !fileHasPotentialSecrets(content) {
		return findings
	}

	// 再次检查内容是否为二进制（仅在关键词过滤通过后执行）
	// 顺序：先二进制扩展名 → 快速关键词 → 内容二进制检测 → 逐行正则
	// 关键词过滤通常能过滤掉 90%+ 的无密钥文件，再执行内容二进制检测成本更低
	if isBinaryContent(content) {
		return findings
	}

	contentStr := string(content)

	// 统一行尾：将 \r\n 和 \r 都统一为 \n，避免跨平台换行符问题
	normalized := strings.ReplaceAll(contentStr, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")

	lines := strings.Split(normalized, "\n")
	for lineNum, line := range lines {
		// 跳过空行
		if strings.TrimSpace(line) == "" {
			continue
		}

		for _, pattern := range s.Patterns {
			matches := pattern.Regex.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				value := match[0]
				// 如果有捕获组，使用捕获组的值
				if len(match) > 1 && match[1] != "" {
					value = match[1]
				}

				// 排除明显的假阳性
				if isFalsePositive(value) {
					continue
				}

				findings = append(findings, Finding{
					Tool:     tool.Name,
					FilePath: filePath,
					Line:     lineNum + 1,
					Type:     pattern.Name,
					Value:    maskValue(value),
					Severity: pattern.Severity,
					Context:  truncate(strings.TrimSpace(line), 200),
				})
			}
		}
	}

	return findings
}

// resolvePaths 展开通配符路径，支持任意位置的 *
func (s *Scanner) resolvePaths(pattern string) []string {
	if !strings.Contains(pattern, "*") {
		return []string{pattern}
	}

	// 使用 filepath.Glob 展开
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}

	// 对于目录通配（如 JetBrains/*/scratches），取最新的匹配
	if len(matches) > 1 {
		// 按修改时间排序，取最新
		var best string
		var bestTime time.Time
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil {
				continue
			}
			if best == "" || info.ModTime().After(bestTime) {
				best = m
				bestTime = info.ModTime()
			}
		}
		if best != "" {
			return []string{best}
		}
	}

	return matches
}

// isBinaryFile 通过扩展名判断是否为二进制文件
func isBinaryFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return binaryExts[ext]
}

// isBinaryContent 检测文件内容是否包含大量空字节（二进制特征）
func isBinaryContent(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	// 检查前 8KB
	checkLen := 8192
	if len(data) < checkLen {
		checkLen = len(data)
	}
	nullCount := 0
	for i := 0; i < checkLen; i++ {
		if data[i] == 0 {
			nullCount++
		}
	}
	// 超过 10% 空字节视为二进制
	return nullCount > checkLen/10
}

// isFalsePositive 排除常见假阳性
func isFalsePositive(value string) bool {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `'"`)

	lower := strings.ToLower(value)

	for _, p := range falsePositivePlaceholders {
		if strings.Contains(lower, p) {
			return true
		}
	}

	for _, k := range falsePositiveKnownPublic {
		if lower == k {
			return true
		}
	}

	return false
}

// 快速关键词过滤集合（小写），用于文件级跳过
// 覆盖所有 126 个模式的关键字前缀，确保不漏检
var quickCheckKeywords = []string{
	// AI/LLM 服务
	"sk-", "sk-ant-", "sk-proj-",
	"hf_", "r8_", "gsk_", "pplx-", "xai-",
	"mist_", "aiza",
	"deepseek", "together", "fireworks", "replicate",
	"huggingface", "hugging_face", "hugging",
	"elevenlabs", "assemblyai", "deepgram",
	"wandb", "neptune", "comet", "mlflow",
	"prefect", "modal", "bentoml",
	"stability", "runway",
	"ai21", "synthesia", "heygen", "playht", "d-id", "d_id",
	"scale", "labelbox",
	"llamaindex", "litellm", "langchain",
	"codeium", "tabnine", "supermaven",
	"cody", "copilot",
	"cursor", "windsurf", "ollama",
	"perplexity", "groq", "mistral",
	// AI IDE / AI 工具（补充）
	"leonardo", "ideogram", "mintlify",
	"replit", "devin", "openhands", "sweep",
	"codex", "vercel", "bolt", "lovable",
	"factory", "codesandbox", "gitpod",
	"midjourney", "askcodi", "codegpt", "blackbox",
	"augment", "bitointernal", "bito",
	// 云服务商
	"akia", "asia", "a3t", "a3b", "a3s", "wjalrxu",
	// GitHub
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat",
	// Slack
	"xoxp-", "xoxb-", "xapp-", "xoxa-", "xoxr-",
	// Stripe
	"sk_live_", "sk_test_", "rk_live_", "rk_test_",
	"pk_live_", "pk_test_", "whsec_",
	// SendGrid
	"sg.",
	// Shopify
	"shpat_", "shpca_", "shppa_", "shpss_",
	// npm
	"npm_",
	// 通用密钥关键字
	"api_key", "apikey", "api-key",
	"token", "secret", "password",
	"-----begin", "private.key", "private_key",
	"public_key", "public.key",
	"eyj", "ya29",
	"bearer", "authorization",
	"ssh-rsa", "ssh-ed25519", "ssh-dss", "ssh-",
	// 数据库连接
	"jdbc:", "mongodb://", "mysql://", "postgresql://", "redis://",
	"s3://",
	"database_url", "connection_string",
	"postgres_password", "mysql_password", "redis_password",
	// 环境变量/配置
	"access_key", "secret_key", "client_secret", "client_id",
	"app_secret", "signing_key", "session_token", "refresh_token",
	"account_sid", "auth_token",
	"heroku_api_key",
	"slack_bot", "slack_app",
	"telegram_bot", "discord_token",
	// 云厂商
	"cf_", "cfemail", "cloudflare",
	"azure_", "azure.",
	"gcp_", "google_",
	"digitalocean", "do_",
	"linode", "vultr",
	// 基础设施
	"kubeconfig", "kube_",
	"terraform", "ansible", "vault",
	"prometheus", "grafana",
	"pagerduty", "datadog", "new.relic",
	// 其他
	"mapbox", "sendgrid", "mailgun", "twilio",
	"doppler", "consul",
	"oauth", "jwt",
	"pgp", "gpg",
	"login", "credential",
	"proxy", "socks5",
	"connector", "conn_string",
	"host=", "port=", "username=", "password=",
	"publishable", "pat=", "perm:",
}

// fileHasPotentialSecrets 快速检查文件内容是否包含任何可疑关键词
// 接受 []byte 参数，避免调用方额外的 string() 转换
// 这是最重要的性能优化：无密钥文件直接跳过，避免逐行正则匹配
func fileHasPotentialSecrets(data []byte) bool {
	// 先检查前 512 字节（大多数文件头部包含关键词）
	checkLen := 512
	if len(data) < checkLen {
		checkLen = len(data)
	}
	// 使用 bytes.Index 的等价操作：将小块转换为小写字符串
	head := strings.ToLower(string(data[:checkLen]))
	for _, kw := range quickCheckKeywords {
		if strings.Contains(head, kw) {
			return true
		}
	}
	// 头部未命中但文件较大时，检查全文
	if len(data) > checkLen {
		full := strings.ToLower(string(data))
		for _, kw := range quickCheckKeywords {
			if strings.Contains(full, kw) {
				return true
			}
		}
	}
	return false
}

// FilterBySeverity 按严重程度过滤发现
func (sr *ScanResult) FilterBySeverity(minSeverity string) []Finding {
	minOrder, ok := severityOrder[minSeverity]
	if !ok {
		return sr.Findings
	}

	var filtered []Finding
	for _, f := range sr.Findings {
		if order, ok := severityOrder[f.Severity]; ok && order >= minOrder {
			filtered = append(filtered, f)
		}
	}
	return filtered
}
