package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Tool 定义了一个 API 工具的缓存位置和文件匹配规则
type Tool struct {
	Name        string
	WinPaths    []string
	MacPaths    []string
	LinuxPaths  []string
	Extensions  []string
	GlobPattern string
	MaxFileSize int64 // 0 = 默认 1MB
}

// GetPaths 返回当前操作系统的路径列表
func (t *Tool) GetPaths() []string {
	switch runtime.GOOS {
	case "windows":
		return t.expandPaths(t.WinPaths)
	case "darwin":
		return t.expandPaths(t.MacPaths)
	default:
		return t.expandPaths(t.LinuxPaths)
	}
}

func (t *Tool) expandPaths(paths []string) []string {
	homeDir, _ := os.UserHomeDir()
	localAppData, _ := os.UserCacheDir()
	configDir, _ := os.UserConfigDir()

	// Windows 特有环境变量
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		userProfile = homeDir
	}
	programFiles := os.Getenv("PROGRAMFILES")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	programFilesX86 := os.Getenv("PROGRAMFILES(X86)")
	if programFilesX86 == "" {
		programFilesX86 = `C:\Program Files (x86)`
	}

	var result []string
	for _, p := range paths {
		expanded := os.Expand(p, func(key string) string {
			switch key {
			case "HOME":
				return homeDir
			case "LOCALAPPDATA":
				return localAppData
			case "APPDATA":
				return configDir
			case "CONFIG":
				return configDir
			case "USERPROFILE":
				return userProfile
			case "PROGRAMFILES":
				return programFiles
			case "PROGRAMFILES(x86)":
				return programFilesX86
			default:
				return os.Getenv(key)
			}
		})

		// 处理 ~ 展开（支持 ~/ 和 ~\ 以及单独的 ~）
		if expanded == "~" {
			expanded = homeDir
		} else if strings.HasPrefix(expanded, "~/") {
			expanded = filepath.Join(homeDir, expanded[2:])
		} else if strings.HasPrefix(expanded, "~\\") {
			expanded = filepath.Join(homeDir, expanded[2:])
		}

		// 清理路径（规范化分隔符）
		expanded = filepath.Clean(expanded)

		result = append(result, expanded)
	}
	return result
}

// MB 辅助函数
func mb(n int64) int64 { return n * 1024 * 1024 }

// AllTools 返回所有已配置的 API 工具定义（全覆盖 216 款工具，按类别聚合）
func AllTools() []Tool {
	var tools []Tool
	tools = append(tools, toolsCatGUI()...)
	tools = append(tools, toolsCatIDE()...)
	tools = append(tools, toolsCatCLI()...)
	tools = append(tools, toolsCatConfig()...)
	tools = append(tools, toolsCatInfra()...)
	tools = append(tools, toolsCatAI()...)
	return tools
}