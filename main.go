package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"AScan/scanner"
)

var (
	outputDir     string
	verbose       bool
	listTools     bool
	filterTool    string
	filterSev     string
	silent        bool
	version       = "1.0.0"
)

func init() {
	flag.StringVar(&outputDir, "o", "", "输出统计目录（默认: ./api-key-stats/）")
	flag.StringVar(&outputDir, "output", "", "同 -o")
	flag.BoolVar(&verbose, "v", false, "详细输出模式")
	flag.BoolVar(&verbose, "verbose", false, "同 -v")
	flag.BoolVar(&listTools, "list", false, "列出所有支持的工具及其路径")
	flag.StringVar(&filterTool, "t", "", "只扫描指定工具（名称包含匹配）")
	flag.StringVar(&filterTool, "tool", "", "同 -t")
	flag.StringVar(&filterSev, "s", "", "只输出指定严重程度的发现 (Critical/High/Medium/Low)")
	flag.StringVar(&filterSev, "severity", "", "同 -s")
	flag.BoolVar(&silent, "silent", false, "静默模式，不打印控制台输出")
}

func main() {
	flag.Usage = usage
	flag.Parse()

	// 列出工具
	if listTools {
		printTools()
		return
	}

	// 创建扫描器
	s := scanner.NewScanner(verbose)

	// 过滤工具
	if filterTool != "" {
		var filtered []scanner.Tool
		for _, t := range s.Tools {
			if strings.Contains(strings.ToLower(t.Name), strings.ToLower(filterTool)) {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) == 0 {
			fmt.Fprintf(os.Stderr, "错误: 未找到匹配的工具: %s\n", filterTool)
			fmt.Fprintf(os.Stderr, "使用 --list 查看所有支持的工具\n")
			os.Exit(1)
		}
		s.Tools = filtered
	}

	// 设置输出目录
	if outputDir == "" {
		outputDir = filepath.Join(".", "api-key-stats")
	}

	if !silent {
		fmt.Println("==============================================")
		fmt.Println("  AScan v" + version)
		fmt.Println("  扫描 API 工具缓存文件中的密钥信息")
		fmt.Println("==============================================")
		fmt.Printf("  输出目录: %s\n", outputDir)
		fmt.Printf("  扫描工具数: %d\n", len(s.Tools))
		fmt.Println()
	}

	// 执行扫描
	result := s.ScanAll()

	// 过滤严重程度
	if filterSev != "" {
		result.Findings = result.FilterBySeverity(filterSev)
		result.TotalFound = len(result.Findings)
	}

	// 输出到终端
	if !silent {
		scanner.PrintSummary(result)
	}

	// 保存报告
	reporter := scanner.NewReporter(outputDir)
	files, err := reporter.SaveAll(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 保存报告失败: %v\n", err)
		os.Exit(1)
	}

	if !silent {
		fmt.Println("\n报告已保存:")
		for format, path := range files {
			fmt.Printf("  [%s] %s\n", strings.ToUpper(format), path)
		}
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `AScan v%s - 扫描 API 工具缓存，发现泄露的密钥信息

用法: AScan [选项]

选项:
  -o, --output <目录>    输出统计目录 (默认: ./api-key-stats/)
  -t, --tool <名称>      只扫描指定工具 (名称包含匹配，不区分大小写)
  -s, --severity <级别>  只输出指定严重程度的发现 (Critical/High/Medium/Low)
  -v, --verbose          详细输出，打印每个扫描的文件
  --list                 列出所有支持的工具及其缓存路径
  --silent               静默模式，不打印控制台输出

示例:
  AScan                              # 扫描所有工具
  AScan -v                           # 详细模式
  AScan -t postman                   # 只扫描 Postman
  AScan -t insomnia -s Critical      # 只扫描 Insomnia 的 Critical 级别
  AScan -o ./results                 # 输出到指定目录
  AScan --list                       # 查看支持的工具

输出格式: JSON, CSV, TXT, 摘要
`, version)
}

func printTools() {
	s := scanner.NewScanner(false)
	fmt.Println("==============================================")
	fmt.Println("  支持的工具列表")
	fmt.Println("==============================================")
	fmt.Println()

	for _, tool := range s.Tools {
		fmt.Printf("  📦 %s\n", tool.Name)
		paths := tool.GetPaths()
		if len(paths) == 0 {
			fmt.Println("      (当前平台不支持)")
			continue
		}
		for _, p := range paths {
			_, err := os.Stat(p)
			status := "✗"
			if err == nil {
				status = "✓"
			}
			fmt.Printf("      %s %s\n", status, p)
		}
		fmt.Println()
	}
}
