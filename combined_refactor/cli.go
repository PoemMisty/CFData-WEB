package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type cliConfig struct {
	enabled        bool
	mode           string
	ipType         int
	threads        int
	port           int
	delay          int
	dc             string
	file           string
	outFile        string
	speedTest      int
	speedLimit     int
	speedMin       float64
	enableTLS      bool
	showProgress   bool
	noColor        bool
	compactIPv4    bool
}

type cliFlagInfo struct {
	name         string
	description  string
	defaultValue string
}

var (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiRed     = "\033[31m"
	ansiCyan    = "\033[36m"
	ansiMagenta = "\033[35m"

			cliCommonFlags = []cliFlagInfo{
		{name: "cli", description: "是否启用命令行模式，不带时默认启动 Web（请用 -cli 或 -cli=true，不要写成 -cli true）", defaultValue: "false"},
		{name: "mode", description: "运行模式：official 或 nsb", defaultValue: "official"},
		{name: "threads", description: "扫描并发数", defaultValue: "100"},
		{name: "out", description: "输出文件名", defaultValue: "ip.csv"},
		{name: "speedtest", description: "测速线程数，官方和非标共用", defaultValue: "5"},
		{name: "progress", description: "是否输出进度日志", defaultValue: "true"},
		{name: "nocolor", description: "禁用颜色输出（cmd 等不支持 ANSI 的终端可开启避免乱码）", defaultValue: "false"},
		{name: "url", description: "测速下载地址", defaultValue: "speed.cloudflare.com/__down?bytes=99999999"},
		{name: "debug", description: "是否开启调试输出", defaultValue: "false"},
		{name: "compactipv4", description: "精简本地 IPv4 地址库：按 /24 子网测 TCP:80 连通性并覆盖 ips-v4.txt", defaultValue: "false"},
	}
	cliOfficialFlags = []cliFlagInfo{
		{name: "iptype", description: "官方模式 IP 类型：4 或 6", defaultValue: "4"},
		{name: "testport", description: "官方模式详细测试与测速端口", defaultValue: "443"},
		{name: "delay", description: "官方模式延迟阈值（毫秒）", defaultValue: "500"},
		{name: "dc", description: "指定数据中心；不填时自动选择最低延迟数据中心", defaultValue: ""},
		{name: "speedlimit", description: "官方模式测速达标结果上限；0 表示关闭官方测速", defaultValue: "0"},
		{name: "speedmin", description: "官方模式测速达标下限，单位 MB/s", defaultValue: "0.1"},
	}
	cliNSBFlags = []cliFlagInfo{
		{name: "file", description: "非标模式输入文件路径", defaultValue: ""},
		{name: "tls", description: "非标模式是否启用 TLS", defaultValue: "true"},
	}
)

func registerCLIFlags() *cliConfig {
	cfg := &cliConfig{}
	flag.Usage = printCLIUsage
	flag.BoolVar(&cfg.enabled, "cli", false, "启用命令行模式（默认启动 Web）")
	flag.StringVar(&cfg.mode, "mode", "official", "CLI 模式：official 或 nsb")
	flag.IntVar(&cfg.ipType, "iptype", 4, "官方模式 IP 类型：4 或 6")
	flag.IntVar(&cfg.threads, "threads", 100, "扫描并发数")
	flag.IntVar(&cfg.port, "testport", 443, "目标测试端口")
	flag.IntVar(&cfg.delay, "delay", 500, "延迟阈值（毫秒）")
	flag.StringVar(&cfg.dc, "dc", "", "官方模式指定数据中心，不填则自动选择最低延迟数据中心")
	flag.StringVar(&cfg.file, "file", "", "非标模式输入文件路径")
	flag.StringVar(&cfg.outFile, "out", "ip.csv", "CLI 输出文件名")
	flag.IntVar(&cfg.speedLimit, "speedlimit", 0, "官方模式测速达标结果上限；0 表示关闭官方测速")
	flag.Float64Var(&cfg.speedMin, "speedmin", 0.1, "官方模式测速达标下限，单位 MB/s")
	flag.BoolVar(&cfg.enableTLS, "tls", true, "非标模式是否启用 TLS")
	flag.BoolVar(&cfg.showProgress, "progress", true, "CLI 模式输出进度日志")
	flag.BoolVar(&cfg.noColor, "nocolor", false, "禁用 ANSI 颜色输出（cmd 等不支持的终端建议开启）")
	flag.BoolVar(&cfg.compactIPv4, "compactipv4", false, "精简本地 IPv4 地址库，按 /24 子网探测 TCP:80 连通性后覆盖 ips-v4.txt")
	return cfg
}

func runCLI(cfg *cliConfig) error {
	cfg.speedTest = speedTestWorkers
	if cfg.noColor {
		disableANSIColors()
	}
	printCLIConfig(cfg)

	if cfg.compactIPv4 {
		return runCompactIPv4CLI(cfg)
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.mode))
	switch mode {
	case "official":
		return runOfficialCLI(cfg)
	case "nsb":
		return runNSBCLI(cfg)
	default:
		return fmt.Errorf("不支持的 -mode: %s（仅支持 official 或 nsb）", cfg.mode)
	}
}

func runCompactIPv4CLI(cfg *cliConfig) error {
	session := newCLISession(cfg)
	if err := session.runTaskSync(func(ctx context.Context, session *appSession) {
		runCompactIPv4Task(ctx, session)
	}); err != nil {
		return cliTaskError(err)
	}
	return nil
}

func newCLISession(cfg *cliConfig) *appSession {
	session := &appSession{progressState: map[string][2]int{}}
	session.emit = func(msgType string, data interface{}) {
		handleCLIMessage(cfg, session, msgType, data)
	}
	return session
}

func handleCLIMessage(cfg *cliConfig, session *appSession, msgType string, data interface{}) {
	debugWrongType := func(expected string) {
		if debugMode {
			fmt.Fprintf(os.Stderr, "%s[cli-debug]%s 消息 %s 类型断言失败，期望 %s，实际 %T\n", ansiYellow, ansiReset, msgType, expected, data)
		}
	}
	switch msgType {
	case "log":
		fmt.Println(data)
	case "error":
		fmt.Fprintln(os.Stderr, colorize(fmt.Sprint(data), ansiRed))
	case "scan_progress":
		if cfg.showProgress {
			m, ok := data.(map[string]interface{})
			if !ok {
				debugWrongType("map[string]interface{}")
				break
			}
			current := asInt(m["current"])
			total := asInt(m["total"])
			setCLIProgress(session, "scan", current, total)
		}
	case "test_progress":
		if cfg.showProgress {
			m, ok := data.(map[string]interface{})
			if !ok {
				debugWrongType("map[string]interface{}")
				break
			}
			current := asInt(m["current"])
			total := asInt(m["total"])
			setCLIProgress(session, "test", current, total)
		}
	case "nsb_progress":
		if cfg.showProgress {
			m, ok := data.(map[string]interface{})
			if !ok {
				debugWrongType("map[string]interface{}")
				break
			}
			phase := fmt.Sprint(m["phase"])
			label := "scan"
			if phase == "speed" {
				label = "speed"
			}
			current := asInt(m["current"])
			total := asInt(m["total"])
			setCLIProgress(session, label, current, total)
		}
	case "scan_result":
		res, ok := data.(ScanResult)
		if !ok {
			debugWrongType("ScanResult")
			break
		}
		fmt.Printf("%s[scan-result]%s %s %s:%d %s %s %s\n", ansiMagenta, ansiReset, advanceCLIProgress(session, "scan"), res.IP, res.Port, res.DataCenter, res.City, colorizeLatencyString(res.LatencyStr))
	case "nsb_scan_result":
		m, ok := data.(nsbScanMessage)
		if !ok {
			debugWrongType("nsbScanMessage")
			break
		}
		if m.Speed != "" && m.Speed != "-" {
			progress := advanceCLIProgress(session, "speed")
			fmt.Printf("%s[speed]%s %s %s:%s %s\n", ansiMagenta, ansiReset, progress, m.IP, m.Port, colorizeSpeedString(m.Speed))
		} else {
			progress := advanceCLIProgress(session, "scan")
			fmt.Printf("%s[scan-result]%s %s %s:%s %s\n", ansiMagenta, ansiReset, progress, m.IP, m.Port, colorizeLatencyString(m.Latency))
		}
	case "test_result":
		res, ok := data.(TestResult)
		if !ok {
			debugWrongType("TestResult")
			break
		}
		fmt.Printf("%s[test-result]%s %s %s loss=%s avg=%s\n", ansiMagenta, ansiReset, advanceCLIProgress(session, "test"), res.IP, colorizeLossRate(res.LossRate), colorizeLatencyMS(int(res.AvgLatency/time.Millisecond)))
	case "test_complete":
		results, ok := data.([]TestResult)
		if !ok {
			debugWrongType("[]TestResult")
			break
		}
		session.testMutex.Lock()
		session.testResults = append([]TestResult(nil), results...)
		session.testMutex.Unlock()
		fmt.Printf("%s[test-complete]%s %d results\n", ansiCyan, ansiReset, len(results))
	case "nsb_csv_complete":
		payload, ok := data.(csvHeaderPayload)
		if !ok {
			debugWrongType("csvHeaderPayload")
			break
		}
		fmt.Printf("%s[nsb-output]%s %s (%d rows)\n", ansiGreen, ansiReset, payload.File, len(payload.Rows))
	case "speed_test_result":
		m, ok := data.(map[string]string)
		if !ok {
			debugWrongType("map[string]string")
			break
		}
		endpoint := m["endpoint"]
		if endpoint == "" {
			endpoint = m["ip"]
		}
		fmt.Printf("%s[speed]%s %s %s\n", ansiMagenta, ansiReset, endpoint, colorizeSpeedString(m["speed"]))
	case "compact_ipv4_progress":
		if cfg.showProgress {
			m, ok := data.(map[string]interface{})
			if !ok {
				debugWrongType("map[string]interface{}")
				break
			}
			current := asInt(m["current"])
			total := asInt(m["total"])
			setCLIProgress(session, "compact", current, total)
			maybePrintCLIProgress(session, "compact", current, total)
		}
	case "compact_ipv4_hit":
		if !debugMode {
			break
		}
		m, ok := data.(map[string]interface{})
		if !ok {
			debugWrongType("map[string]interface{}")
			break
		}
		fmt.Printf("%s[compact-hit]%s pass=%v %v\n", ansiMagenta, ansiReset, m["pass"], m["ip"])
	case "compact_ipv4_done":
		m, ok := data.(map[string]interface{})
		if !ok {
			debugWrongType("map[string]interface{}")
			break
		}
		fmt.Printf("%s[compact-done]%s 保留 %v 个子网 → %v\n", ansiGreen, ansiReset, m["count"], m["file"])
	}
}

func runOfficialCLI(cfg *cliConfig) error {
	if cfg.ipType != 4 && cfg.ipType != 6 {
		return errors.New("官方模式 -iptype 仅支持 4 或 6")
	}
	if cfg.threads <= 0 {
		cfg.threads = 100
	}
	if cfg.port <= 0 {
		cfg.port = 443
	}
	if cfg.delay < 0 {
		cfg.delay = 0
	}
	if cfg.speedLimit < 0 {
		cfg.speedLimit = 0
	}
	if cfg.speedMin <= 0 {
		cfg.speedMin = 0.1
	}

	session := newCLISession(cfg)
	if err := session.runTaskSync(func(ctx context.Context, session *appSession) {
		runOfficialTask(ctx, session, cfg.ipType, cfg.threads, cfg.port)
	}); err != nil {
		return cliTaskError(err)
	}

	session.scanMutex.Lock()
	scanResults := append([]ScanResult(nil), session.scanResults...)
	session.scanMutex.Unlock()
	if len(scanResults) == 0 {
		return errors.New("官方模式未发现有效 IP")
	}

	dc := strings.TrimSpace(cfg.dc)
	if dc == "" {
		dc = pickBestDataCenter(scanResults)
		if dc == "" {
			fmt.Printf("%s[official]%s 无法确定数据中心，仅输出扫描结果\n", ansiYellow, ansiReset)
			return writeOfficialScanCSV(cfg.outFile, scanResults)
		}
		fmt.Printf("%s[official]%s 自动选择数据中心: %s\n", ansiGreen, ansiReset, colorize(dc, ansiBold+ansiGreen))
	}

	session.testMutex.Lock()
	session.testResults = nil
	session.testMutex.Unlock()
	if err := session.runTaskSync(func(ctx context.Context, session *appSession) {
		runDetailedTest(ctx, session, dc, cfg.port, cfg.delay)
	}); err != nil {
		return cliTaskError(err)
	}

	session.testMutex.Lock()
	results := append([]TestResult(nil), session.testResults...)
	session.testMutex.Unlock()
	if cfg.speedLimit <= 0 {
		fmt.Printf("%s[official]%s 官方测速已关闭（-speedlimit 0）\n", ansiYellow, ansiReset)
	} else if cfg.speedTest <= 0 {
		fmt.Printf("%s[official]%s 官方测速已关闭（-speedtest 0）\n", ansiYellow, ansiReset)
	} else if len(results) == 0 {
		fmt.Printf("%s[official]%s 没有可用的详细测试结果，跳过测速\n", ansiYellow, ansiReset)
	} else {
		setCLIProgress(session, "speed", 0, len(results))
		fmt.Printf("%s[official]%s 开始串行测速，达标上限=%d，下限=%.2f MB/s\n", ansiGreen, ansiReset, cfg.speedLimit, cfg.speedMin)
		results = runOfficialSpeedTests(context.Background(), session, results, cfg.port, cfg.speedLimit, cfg.speedMin)
	}
	return writeOfficialCLIResults(cfg.outFile, scanResults, results)
}

func runNSBCLI(cfg *cliConfig) error {
	if strings.TrimSpace(cfg.file) == "" {
		return errors.New("非标模式需要通过 -file 指定输入文件")
	}
	if cfg.threads <= 0 {
		cfg.threads = 100
	}
	if cfg.speedTest < 0 {
		cfg.speedTest = 0
	}
	if cfg.delay < 0 {
		cfg.delay = 0
	}
	if strings.TrimSpace(cfg.outFile) == "" {
		cfg.outFile = "ip.csv"
	}
	content, err := getFileContent(cfg.file)
	if err != nil {
		return err
	}

	session := newCLISession(cfg)
	if err := session.runTaskSync(func(ctx context.Context, session *appSession) {
		runNSBTask(ctx, session, cfg.file, content, cfg.outFile, cfg.threads, cfg.speedTest, speedTestURL, cfg.enableTLS, cfg.delay)
	}); err != nil {
		return cliTaskError(err)
	}
	return nil
}

func cliTaskError(err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.New("已有任务正在运行，请等待完成后再试")
	}
	return err
}

func pickBestDataCenter(scanResults []ScanResult) string {
	dcLatency := map[string]time.Duration{}
	for _, res := range scanResults {
		current, ok := dcLatency[res.DataCenter]
		if !ok || res.TCPDuration < current {
			dcLatency[res.DataCenter] = res.TCPDuration
		}
	}
	type item struct {
		dc      string
		latency time.Duration
	}
	items := make([]item, 0, len(dcLatency))
	for dc, latency := range dcLatency {
		items = append(items, item{dc: dc, latency: latency})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].latency < items[j].latency })
	if len(items) == 0 {
		return ""
	}
	return items[0].dc
}

func runOfficialSpeedTests(ctx context.Context, session *appSession, results []TestResult, port int, limit int, speedMinMB float64) []TestResult {
	capacity := len(results)
	if limit > 0 && limit < capacity {
		capacity = limit
	}
	qualified := make([]TestResult, 0, capacity)
	interSpeedPause := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(1200 * time.Millisecond):
			return true
		}
	}
	for i := range results {
		select {
		case <-ctx.Done():
			return qualified
		default:
		}
		setCLIProgress(session, "speed", i+1, len(results))
		if limit > 0 && len(qualified) >= limit {
			break
		}
		speedMB, speedErr := runWindowedSpeedTest(ctx, results[i].IP, port, speedTestURL)
		if speedErr != "" {
			results[i].Speed = speedErr
			fmt.Printf("%s[speed]%s %s %s:%d %s\n", ansiMagenta, ansiReset, renderCLIProgress(session, "speed"), results[i].IP, port, colorizeSpeedString(speedErr))
			if !interSpeedPause() {
				return qualified
			}
			continue
		}
		results[i].Speed = fmt.Sprintf("%.2f MB/s", speedMB)
		fmt.Printf("%s[speed]%s %s %s:%d %s\n", ansiMagenta, ansiReset, renderCLIProgress(session, "speed"), results[i].IP, port, colorizeSpeedString(results[i].Speed))
		if speedMB >= speedMinMB {
			qualified = append(qualified, results[i])
			fmt.Printf("%s[official]%s 达标 %d/%d\n", ansiGreen, ansiReset, len(qualified), limit)
		}
		if !interSpeedPause() {
			return qualified
		}
	}
	return qualified
}

func printCLIConfig(cfg *cliConfig) {
	type item struct {
		name         string
		description  string
		value        string
		defaultValue string
	}
	printGroup := func(title string, rows []item) {
		fmt.Println(colorize("----------------------------------------", ansiCyan))
		fmt.Println(colorize(title, ansiBold+ansiCyan))
		for _, row := range rows {
			fmt.Printf("%s-%s%s %s\n", ansiBold, row.name, ansiReset, colorizeCLIParamValue(row.value, row.defaultValue))
			fmt.Printf("  %s %s\n", colorize("说明:", ansiYellow), row.description)
			fmt.Printf("  %s %s\n", colorize("默认:", ansiYellow), colorizeCLIDefaultValue(row.defaultValue))
		}
	}

	fmt.Println(colorize("[cli-config] 当前命令参数", ansiBold+ansiGreen))
	printGroup("通用参数", []item{
		{"cli", lookupCLIFlagDescription(cliCommonFlags, "cli"), strconv.FormatBool(cfg.enabled), "false"},
		{"mode", lookupCLIFlagDescription(cliCommonFlags, "mode"), cfg.mode, "official"},
		{"threads", lookupCLIFlagDescription(cliCommonFlags, "threads"), strconv.Itoa(cfg.threads), "100"},
		{"out", lookupCLIFlagDescription(cliCommonFlags, "out"), cfg.outFile, "ip.csv"},
		{"speedtest", lookupCLIFlagDescription(cliCommonFlags, "speedtest"), strconv.Itoa(cfg.speedTest), strconv.Itoa(speedTestWorkers)},
		{"progress", lookupCLIFlagDescription(cliCommonFlags, "progress"), strconv.FormatBool(cfg.showProgress), "true"},
		{"nocolor", lookupCLIFlagDescription(cliCommonFlags, "nocolor"), strconv.FormatBool(cfg.noColor), "false"},
		{"url", lookupCLIFlagDescription(cliCommonFlags, "url"), speedTestURL, "speed.cloudflare.com/__down?bytes=99999999"},
		{"debug", lookupCLIFlagDescription(cliCommonFlags, "debug"), strconv.FormatBool(debugMode), "false"},
		{"compactipv4", lookupCLIFlagDescription(cliCommonFlags, "compactipv4"), strconv.FormatBool(cfg.compactIPv4), "false"},
	})
	printGroup("官方模式参数", []item{
		{"iptype", lookupCLIFlagDescription(cliOfficialFlags, "iptype"), strconv.Itoa(cfg.ipType), "4"},
		{"testport", lookupCLIFlagDescription(cliOfficialFlags, "testport"), strconv.Itoa(cfg.port), "443"},
		{"delay", lookupCLIFlagDescription(cliOfficialFlags, "delay"), strconv.Itoa(cfg.delay), "500"},
		{"dc", lookupCLIFlagDescription(cliOfficialFlags, "dc"), cfg.dc, ""},
		{"speedlimit", lookupCLIFlagDescription(cliOfficialFlags, "speedlimit"), strconv.Itoa(cfg.speedLimit), "0"},
		{"speedmin", lookupCLIFlagDescription(cliOfficialFlags, "speedmin"), fmt.Sprintf("%.2f", cfg.speedMin), "0.1"},
	})
	printGroup("非标模式参数", []item{
		{"file", lookupCLIFlagDescription(cliNSBFlags, "file"), cfg.file, ""},
		{"tls", lookupCLIFlagDescription(cliNSBFlags, "tls"), strconv.FormatBool(cfg.enableTLS), "true"},
	})
	fmt.Println(colorize("----------------------------------------", ansiCyan))
}

func printCLIUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "%s\n", colorize("CFData 命令行帮助", ansiBold+ansiGreen))
	fmt.Fprintf(flag.CommandLine.Output(), "\n")
	fmt.Fprintf(flag.CommandLine.Output(), "默认行为: 不带 -cli 时启动 Web 服务；带 -cli 或 -cli=true 时进入 CLI 模式\n")
	fmt.Fprintf(flag.CommandLine.Output(), "注意: Go 的布尔参数必须写成 -cli 或 -cli=true，不能写成 -cli true（会导致后续参数被忽略）\n")
	fmt.Fprintf(flag.CommandLine.Output(), "CLI 用法: ./combined_refactor_debug -cli -mode=official ...\n")
	fmt.Fprintf(flag.CommandLine.Output(), "\n")
	printCLIUsageGroup("通用参数", cliCommonFlags)
	printCLIUsageGroup("官方模式参数", cliOfficialFlags)
	printCLIUsageGroup("非标模式参数", cliNSBFlags)
}

func printCLIUsageGroup(title string, rows []cliFlagInfo) {
	fmt.Fprintf(flag.CommandLine.Output(), "%s\n", colorize("----------------------------------------", ansiCyan))
	fmt.Fprintf(flag.CommandLine.Output(), "%s\n", colorize(title, ansiBold+ansiCyan))
	for _, row := range rows {
		fmt.Fprintf(flag.CommandLine.Output(), "%s-%s%s\n", ansiBold, row.name, ansiReset)
		fmt.Fprintf(flag.CommandLine.Output(), "  %s %s\n", colorize("说明:", ansiYellow), row.description)
		fmt.Fprintf(flag.CommandLine.Output(), "  %s %s\n", colorize("默认:", ansiYellow), colorizeCLIDefaultValue(row.defaultValue))
	}
}

func lookupCLIFlagDescription(rows []cliFlagInfo, name string) string {
	for _, row := range rows {
		if row.name == name {
			return row.description
		}
	}
	return ""
}

func colorize(text string, code string) string {
	if text == "" {
		return text
	}
	return code + text + ansiReset
}

func colorizeLatencyString(latency string) string {
	ms, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(latency), " ms"))
	if err != nil {
		return latency
	}
	return colorizeLatencyMS(ms)
}

func colorizeLatencyMS(ms int) string {
	text := fmt.Sprintf("%dms", ms)
	if ms < 100 {
		return colorize(text, ansiGreen)
	}
	if ms < 200 {
		return colorize(text, ansiYellow)
	}
	return colorize(text, ansiRed)
}

func colorizeLossRate(lossRate float64) string {
	text := fmt.Sprintf("%.0f%%", lossRate*100)
	if lossRate <= 0 {
		return colorize(text, ansiGreen)
	}
	if lossRate < 0.5 {
		return colorize(text, ansiYellow)
	}
	return colorize(text, ansiRed)
}

func colorizeSpeedString(speed string) string {
	if strings.Contains(speed, "MB/s") {
		value, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(speed, "MB/s")), 64)
		if err == nil {
			if value > 10 {
				return colorize(speed, ansiGreen)
			}
			return colorize(speed, ansiYellow)
		}
	}
	if strings.Contains(strings.ToLower(speed), "错误") || strings.Contains(speed, "失败") || strings.Contains(speed, "0 MB/s") {
		return colorize(speed, ansiRed)
	}
	return speed
}

func colorizeCLIParamValue(value string, defaultValue string) string {
	if value == defaultValue {
		if value == "" {
			return colorize("<空>", ansiGreen)
		}
		return colorize(value, ansiGreen)
	}
	if value == "" {
		return colorize("<空>", ansiYellow)
	}
	if value == "true" {
		return colorize(value, ansiGreen)
	}
	if value == "false" {
		return colorize(value, ansiRed)
	}
	return colorize(value, ansiMagenta)
}

func colorizeCLIDefaultValue(value string) string {
	if value == "" {
		return colorize("<空>", ansiYellow)
	}
	return colorize(value, ansiGreen)
}

func setCLIProgress(session *appSession, phase string, current int, total int) {
	session.progressMutex.Lock()
	defer session.progressMutex.Unlock()
	if session.progressState == nil {
		session.progressState = map[string][2]int{}
	}
	state := session.progressState[phase]
	if total <= 0 {
		total = state[1]
	}
	if current < state[0] {
		current = state[0]
	}
	session.progressState[phase] = [2]int{current, total}
}

func maybePrintCLIProgress(session *appSession, phase string, current, total int) {
	if total <= 0 {
		return
	}
	session.progressMutex.Lock()
	if session.progressPrintTime == nil {
		session.progressPrintTime = map[string]time.Time{}
	}
	if session.progressPrintPercent == nil {
		session.progressPrintPercent = map[string]float64{}
	}
	now := time.Now()
	percent := float64(current) / float64(total) * 100
	lastTime := session.progressPrintTime[phase]
	lastPercent := session.progressPrintPercent[phase]

	shouldPrint := false
	switch {
	case lastTime.IsZero():
		shouldPrint = true
	case current >= total:
		shouldPrint = true
	case percent-lastPercent >= 5.0:
		shouldPrint = true
	case now.Sub(lastTime) >= 3*time.Second:
		shouldPrint = true
	}

	if shouldPrint {
		session.progressPrintTime[phase] = now
		session.progressPrintPercent[phase] = percent
	}
	session.progressMutex.Unlock()

	if !shouldPrint {
		return
	}
	fmt.Printf("%s[%s-progress]%s %s\n", ansiCyan, phase, ansiReset, colorize(fmt.Sprintf("[%d/%d %.2f%%]", current, total, percent), ansiCyan))
}

func renderCLIProgress(session *appSession, phase string) string {
	session.progressMutex.Lock()
	defer session.progressMutex.Unlock()
	if session.progressState == nil {
		return colorize("[0/0]", ansiCyan)
	}
	state, ok := session.progressState[phase]
	if !ok {
		return colorize("[0/0]", ansiCyan)
	}
	if state[1] <= 0 {
		return colorize(fmt.Sprintf("[%d/0]", state[0]), ansiCyan)
	}
	percent := float64(state[0]) / float64(state[1]) * 100
	return colorize(fmt.Sprintf("[%d/%d %.2f%%]", state[0], state[1], percent), ansiCyan)
}

func advanceCLIProgress(session *appSession, phase string) string {
	session.progressMutex.Lock()
	defer session.progressMutex.Unlock()
	if session.progressState == nil {
		session.progressState = map[string][2]int{}
	}
	state := session.progressState[phase]
	if state[1] > 0 && state[0] < state[1] {
		state[0]++
		session.progressState[phase] = state
	}
	if state[1] <= 0 {
		return colorize(fmt.Sprintf("[%d/0]", state[0]), ansiCyan)
	}
	percent := float64(state[0]) / float64(state[1]) * 100
	return colorize(fmt.Sprintf("[%d/%d %.2f%%]", state[0], state[1], percent), ansiCyan)
}

func asInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		value, err := strconv.Atoi(n)
		if err == nil {
			return value
		}
	}
	return 0
}

func writeOfficialScanCSV(filename string, scanResults []ScanResult) error {
	filename = safeFilename(filename)
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := writeUTF8BOM(file); err != nil {
		os.Remove(filename)
		return err
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()
	if err := writer.Write([]string{"IP", "端口", "数据中心", "地区", "城市", "延迟"}); err != nil {
		return err
	}
	for _, res := range scanResults {
		if err := writer.Write([]string{res.IP, fmt.Sprintf("%d", res.Port), res.DataCenter, res.Region, res.City, res.LatencyStr}); err != nil {
			return err
		}
	}
	fmt.Printf("[official-output] %s (%d rows, scan only)\n", filename, len(scanResults))
	return nil
}

func writeOfficialCLIResults(filename string, scanResults []ScanResult, testResults []TestResult) error {
	filename = safeFilename(filename)
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := writeUTF8BOM(file); err != nil {
		os.Remove(filename)
		return err
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()
	if len(testResults) == 0 {
		if err := writer.Write([]string{"IP", "端口", "数据中心", "地区", "城市", "延迟"}); err != nil {
			return err
		}
		for _, res := range scanResults {
			if err := writer.Write([]string{res.IP, fmt.Sprintf("%d", res.Port), res.DataCenter, res.Region, res.City, res.LatencyStr}); err != nil {
				return err
			}
		}
		fmt.Printf("[official-output] %s (%d rows, scan only)\n", filename, len(scanResults))
		return nil
	}

	if err := writer.Write([]string{"IP", "端口", "数据中心", "地区", "城市", "丢包率", "最小延迟", "最大延迟", "平均延迟", "下载速度"}); err != nil {
		return err
	}
	scanByIP := make(map[string]ScanResult, len(scanResults))
	for _, res := range scanResults {
		scanByIP[res.IP] = res
	}
	for _, res := range testResults {
		scan := scanByIP[res.IP]
		if err := writer.Write([]string{res.IP, fmt.Sprintf("%d", scan.Port), scan.DataCenter, scan.Region, scan.City, fmt.Sprintf("%.0f%%", res.LossRate*100), fmt.Sprintf("%d ms", res.MinLatency/time.Millisecond), fmt.Sprintf("%d ms", res.MaxLatency/time.Millisecond), fmt.Sprintf("%d ms", res.AvgLatency/time.Millisecond), res.Speed}); err != nil {
			return err
		}
	}
	fmt.Printf("[official-output] %s (%d test rows)\n", filename, len(testResults))
	return nil
}
