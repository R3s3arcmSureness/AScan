package scanner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Reporter 负责将扫描结果输出到统计目录
type Reporter struct {
	OutputDir string
}

// NewReporter 创建报告生成器
func NewReporter(outputDir string) *Reporter {
	return &Reporter{OutputDir: outputDir}
}

// SaveAll 保存所有格式的报告
func (r *Reporter) SaveAll(result *ScanResult) (map[string]string, error) {
	if err := os.MkdirAll(r.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("创建输出目录失败: %w", err)
	}

	files := make(map[string]string)

	// 预排序：按严重程度降序（Critical 优先），同级别按工具名排序
	sortedFindings := sortFindings(result.Findings)

	// JSON 完整报告
	jsonPath, err := r.SaveJSON(result)
	if err != nil {
		return nil, err
	}
	files["json"] = jsonPath

	// CSV 明细报告
	csvPath, err := r.SaveCSV(sortedFindings, result.ScanTime)
	if err != nil {
		return nil, err
	}
	files["csv"] = csvPath

	// TXT 可读报告
	txtPath, err := r.SaveText(result, sortedFindings)
	if err != nil {
		return nil, err
	}
	files["txt"] = txtPath

	// 摘要
	summaryPath, err := r.SaveSummary(result)
	if err != nil {
		return nil, err
	}
	files["summary"] = summaryPath

	return files, nil
}

// sortFindings 按严重程度降序 + 工具名升序排序，复用避免重复排序
func sortFindings(findings []Finding) []Finding {
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		oi := severityOrder[sorted[i].Severity]
		oj := severityOrder[sorted[j].Severity]
		if oi != oj {
			return oi > oj
		}
		return sorted[i].Tool < sorted[j].Tool
	})
	return sorted
}

// SaveJSON 保存 JSON 格式的完整报告
func (r *Reporter) SaveJSON(result *ScanResult) (string, error) {
	timestamp := result.ScanTime.Format("20060102_150405")
	filename := fmt.Sprintf("scan_%s.json", timestamp)
	filePath := filepath.Join(r.OutputDir, filename)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return "", fmt.Errorf("写入JSON文件失败: %w", err)
	}

	return filePath, nil
}

// SaveCSV 保存 CSV 格式的明细报告
func (r *Reporter) SaveCSV(sortedFindings []Finding, scanTime time.Time) (string, error) {
	timestamp := scanTime.Format("20060102_150405")
	filename := fmt.Sprintf("scan_%s.csv", timestamp)
	filePath := filepath.Join(r.OutputDir, filename)

	f, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("创建CSV文件失败: %w", err)
	}
	defer f.Close()

	// UTF-8 BOM 让 Excel 正确识别
	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return "", fmt.Errorf("写入CSV BOM失败: %w", err)
	}

	writer := csv.NewWriter(f)

	// 表头
	if err := writer.Write([]string{
		"Tool", "File", "Line", "Type", "Value (Masked)", "Severity", "Context",
	}); err != nil {
		return "", fmt.Errorf("写入CSV表头失败: %w", err)
	}

	for _, finding := range sortedFindings {
		if err := writer.Write([]string{
			finding.Tool,
			finding.FilePath,
			fmt.Sprintf("%d", finding.Line),
			finding.Type,
			finding.Value,
			finding.Severity,
			finding.Context,
		}); err != nil {
			return "", fmt.Errorf("写入CSV记录失败: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", fmt.Errorf("CSV写入最终刷新失败: %w", err)
	}

	return filePath, nil
}

// SaveText 保存可读的文本报告
func (r *Reporter) SaveText(result *ScanResult, sortedFindings []Finding) (string, error) {
	timestamp := result.ScanTime.Format("20060102_150405")
	filename := fmt.Sprintf("scan_%s.txt", timestamp)
	filePath := filepath.Join(r.OutputDir, filename)

	var sb strings.Builder

	sb.WriteString("============================================================\n")
	sb.WriteString("  AScan - 扫描报告\n")
	sb.WriteString("============================================================\n\n")

	sb.WriteString(fmt.Sprintf("扫描时间: %s\n", result.ScanTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("操作系统: %s\n", result.OS))
	sb.WriteString(fmt.Sprintf("主机名:   %s\n", result.Hostname))
	sb.WriteString(fmt.Sprintf("扫描文件: %d\n", result.TotalFiles))
	sb.WriteString(fmt.Sprintf("发现敏感信息: %d\n\n", result.TotalFound))

	// 按工具统计
	sb.WriteString("--- 按工具统计 ---\n")
	for _, tr := range result.ToolResults {
		status := "✓"
		if !tr.Exists {
			status = "✗ (未找到)"
		}
		sb.WriteString(fmt.Sprintf("  %-25s %s  扫描: %d 文件, 发现: %d\n",
			tr.Tool, status, tr.FilesScanned, tr.Findings))
	}

	// 按严重程度统计
	sb.WriteString("\n--- 按严重程度统计 ---\n")
	severityCount := make(map[string]int)
	for _, f := range result.Findings {
		severityCount[f.Severity]++
	}
	severityOrder := []string{"Critical", "High", "Medium", "Low"}
	for _, sev := range severityOrder {
		if count, ok := severityCount[sev]; ok {
			sb.WriteString(fmt.Sprintf("  %-10s: %d\n", sev, count))
		}
	}

	// 按类型统计
	sb.WriteString("\n--- 按密钥类型统计 ---\n")
	typeCount := make(map[string]int)
	for _, f := range result.Findings {
		typeCount[f.Type]++
	}
	type sortEntry struct {
		key   string
		count int
	}
	var typeList []sortEntry
	for k, v := range typeCount {
		typeList = append(typeList, sortEntry{k, v})
	}
	sort.Slice(typeList, func(i, j int) bool {
		return typeList[i].count > typeList[j].count
	})
	for _, entry := range typeList {
		sb.WriteString(fmt.Sprintf("  %-35s: %d\n", entry.key, entry.count))
	}

	// 详细信息
	sb.WriteString("\n--- 详细发现 ---\n")
	for i, f := range sortedFindings {
		sb.WriteString(fmt.Sprintf("\n[%d] %s | %s\n", i+1, f.Severity, f.Type))
		sb.WriteString(fmt.Sprintf("    工具: %s\n", f.Tool))
		sb.WriteString(fmt.Sprintf("    文件: %s:%d\n", f.FilePath, f.Line))
		sb.WriteString(fmt.Sprintf("    值:   %s\n", f.Value))
		sb.WriteString(fmt.Sprintf("    上下文: %s\n", f.Context))
	}

	sb.WriteString("\n============================================================\n")
	sb.WriteString("  扫描完成\n")
	sb.WriteString("============================================================\n")

	if err := os.WriteFile(filePath, []byte(sb.String()), 0644); err != nil {
		return "", fmt.Errorf("写入TXT文件失败: %w", err)
	}

	return filePath, nil
}

// SaveSummary 保存简洁摘要
func (r *Reporter) SaveSummary(result *ScanResult) (string, error) {
	timestamp := result.ScanTime.Format("20060102_150405")
	filename := fmt.Sprintf("scan_%s_summary.txt", timestamp)
	filePath := filepath.Join(r.OutputDir, filename)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== AScan Summary ===\n"))
	sb.WriteString(fmt.Sprintf("Time: %s | OS: %s | Host: %s\n",
		result.ScanTime.Format("2006-01-02 15:04:05"), result.OS, result.Hostname))
	sb.WriteString(fmt.Sprintf("Files: %d | Findings: %d\n",
		result.TotalFiles, result.TotalFound))

	severityCount := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
	for _, f := range result.Findings {
		severityCount[f.Severity]++
	}
	sb.WriteString(fmt.Sprintf("Critical:%d High:%d Medium:%d Low:%d\n",
		severityCount["Critical"], severityCount["High"],
		severityCount["Medium"], severityCount["Low"]))

	if err := os.WriteFile(filePath, []byte(sb.String()), 0644); err != nil {
		return "", fmt.Errorf("写入摘要文件失败: %w", err)
	}

	return filePath, nil
}

// PrintSummary 在终端打印扫描摘要
func PrintSummary(result *ScanResult) {
	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  AScan - 扫描结果")
	fmt.Println("========================================")
	fmt.Printf("  时间: %s\n", result.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("  系统: %s | 主机: %s\n", result.OS, result.Hostname)
	fmt.Printf("  扫描文件: %d | 发现: %d\n", result.TotalFiles, result.TotalFound)
	fmt.Println("----------------------------------------")

	sevCount := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
	toolCount := map[string]int{}
	for _, f := range result.Findings {
		sevCount[f.Severity]++
		toolCount[f.Tool]++
	}

	fmt.Printf("  Critical: %d | High: %d | Medium: %d | Low: %d\n",
		sevCount["Critical"], sevCount["High"], sevCount["Medium"], sevCount["Low"])

	if len(toolCount) > 0 {
		fmt.Println("----------------------------------------")
		fmt.Println("  按工具分布:")
		type toolKv struct {
			k string
			v int
		}
		var list []toolKv
		for k, v := range toolCount {
			list = append(list, toolKv{k, v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
		for _, item := range list {
			fmt.Printf("    %-25s: %d\n", item.k, item.v)
		}
	}
	fmt.Println("========================================")
}
