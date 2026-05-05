package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type cliConfig struct {
	enabled        bool
	configResolved bool
	mode           string
	ipType         int
	threads        int
	port           int
	delay          int
	resultLimit    int
	dc             string
	file           string
	sourceURL      string
	outFile        string
	speedTest      int
	speedLimit     int
	speedMin       float64
	enableTLS      bool
	compactNSB     bool
	nsbIPType      string
	nsbQualified   bool
	nsbDC          string
	nsbSpeedMin    float64
	nsbSpeedLimit  int
	showProgress   bool
	noColor        bool
	compactIPv4    bool
	export         cliExportConfig
}

type cliExportConfig struct {
	ConfigFile  string `json:"-"`
	Format      string `json:"format"`
	Fields      string `json:"fields"`
	GitHub      bool   `json:"github"`
	GitHubSet   bool   `json:"-"`
	GHRepo      string `json:"ghrepo"`
	GHBranch    string `json:"ghbranch"`
	GHPath      string `json:"ghpath"`
	GHMessage   string `json:"ghmessage"`
	GHToken     string `json:"ghtoken"`
	GHTokenFile string `json:"ghtokenfile"`
	GHUpload    string `json:"ghupload"`
}

type cliFileConfig struct {
	CLI           bool    `json:"cli"`
	Mode          string  `json:"mode"`
	IPType        int     `json:"iptype"`
	Threads       int     `json:"threads"`
	Out           string  `json:"out"`
	SpeedTest     int     `json:"speedtest"`
	Progress      bool    `json:"progress"`
	NoColor       bool    `json:"nocolor"`
	URL           string  `json:"url"`
	DNS           string  `json:"dns"`
	Debug         bool    `json:"debug"`
	CompactIPv4   bool    `json:"compactipv4"`
	TestPort      int     `json:"testport"`
	Delay         int     `json:"delay"`
	DC            string  `json:"dc"`
	SpeedLimit    int     `json:"speedlimit"`
	SpeedMin      float64 `json:"speedmin"`
	File          string  `json:"file"`
	SourceURL     string  `json:"sourceurl"`
	NSBDC         string  `json:"nsbdc"`
	NSBIPType     string  `json:"nsbiptype"`
	NSBQualified  bool    `json:"nsbqualified"`
	TLS           bool    `json:"tls"`
	Compact       bool    `json:"compact"`
	ResultLimit   int     `json:"resultlimit"`
	NSBSpeedMin   float64 `json:"nsbspeedmin"`
	NSBSpeedLimit int     `json:"nsbspeedlimit"`
	Format        string  `json:"format"`
	Fields        string  `json:"fields"`
	GitHub        bool    `json:"github"`
	GHRepo        string  `json:"ghrepo"`
	GHBranch      string  `json:"ghbranch"`
	GHPath        string  `json:"ghpath"`
	GHMessage     string  `json:"ghmessage"`
	GHToken       string  `json:"ghtoken"`
	GHTokenFile   string  `json:"ghtokenfile"`
	GHUpload      string  `json:"ghupload"`
}

type cliResultRow map[string]string

type cliResultField struct {
	Key   string
	Label string
}

var cliResultFields = []cliResultField{
	{Key: "ipport", Label: "ip:port"},
	{Key: "ip", Label: "IP地址"},
	{Key: "port", Label: "端口号"},
	{Key: "tls", Label: "TLS"},
	{Key: "latency", Label: "网络延迟"},
	{Key: "speed", Label: "下载速度"},
	{Key: "outboundIP", Label: "出站IP"},
	{Key: "ipType", Label: "IP类型"},
	{Key: "dc", Label: "数据中心"},
	{Key: "loc", Label: "源IP位置"},
	{Key: "region", Label: "地区"},
	{Key: "city", Label: "城市"},
	{Key: "asnNumber", Label: "ASN号码"},
	{Key: "asnOrg", Label: "ASN组织"},
	{Key: "visitScheme", Label: "访问协议"},
	{Key: "tlsVersion", Label: "TLS版本"},
	{Key: "sni", Label: "SNI"},
	{Key: "httpVersion", Label: "HTTP版本"},
	{Key: "warp", Label: "WARP"},
	{Key: "gateway", Label: "Gateway"},
	{Key: "rbi", Label: "RBI"},
	{Key: "kex", Label: "密钥交换"},
	{Key: "timestamp", Label: "时间戳"},
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
		{name: "port", description: "Web 服务监听端口", defaultValue: "13335"},
		{name: "user", description: "Web 认证用户名（不设置则不启用认证）", defaultValue: ""},
		{name: "password", description: "Web 认证密码（需同时设置 -user）", defaultValue: ""},
		{name: "session", description: "Web 登录会话有效期（分钟）", defaultValue: "720"},
		{name: "mode", description: "运行模式：official 或 nsb", defaultValue: "official"},
		{name: "threads", description: "扫描并发数", defaultValue: "100"},
		{name: "out", description: "输出文件名", defaultValue: "ip.csv"},
		{name: "progress", description: "是否输出进度日志", defaultValue: "true"},
		{name: "nocolor", description: "禁用颜色输出（cmd 等不支持 ANSI 的终端可开启避免乱码）", defaultValue: "false"},
		{name: "url", description: "测速下载地址", defaultValue: "speed.cloudflare.com/__down?bytes=99999999"},
		{name: "dns", description: "自定义 DNS 服务器，例如 223.5.5.5、8.8.8.8:53 或逗号分隔多个；留空使用系统 DNS", defaultValue: defaultDNSServers},
		{name: "debug", description: "是否开启调试输出", defaultValue: "false"},
		{name: "compactipv4", description: "精简本地 IPv4 地址库：按 /24 子网测 TCP:80 连通性并覆盖 ips-v4.txt", defaultValue: "false"},
		{name: "config", description: "CLI 配置文件路径，不存在时在二进制目录自动生成模板", defaultValue: "二进制目录/cfdata-config.json"},
		{name: "format", description: "CLI 导出格式：csv 或 txt", defaultValue: "csv"},
		{name: "fields", description: "CLI 导出字段：compact、all、ipport 或逗号分隔自定义字段", defaultValue: "compact"},
		{name: "github", description: "CLI 导出后上传到 GitHub", defaultValue: "false"},
		{name: "ghrepo", description: "GitHub 仓库，格式 owner/repo", defaultValue: ""},
		{name: "ghbranch", description: "GitHub 分支", defaultValue: "main"},
		{name: "ghpath", description: "GitHub 目标路径；留空时按 -format 自动使用 results/ip.csv 或 results/ip.txt", defaultValue: "<自动>"},
		{name: "ghmessage", description: "GitHub 提交信息", defaultValue: "update cfdata results"},
		{name: "ghtoken", description: "GitHub token（不推荐直接写入配置；强烈建议使用仅限制指定仓库读写权限的 token，并确保仓库内无重要数据）", defaultValue: ""},
		{name: "ghtokenfile", description: "GitHub token 文件路径（强烈建议文件内 token 仅限制指定仓库读写权限，并确保仓库内无重要数据）", defaultValue: ""},
		{name: "ghupload", description: "快速上传指定文件到 GitHub，不执行测试；需配合 -github", defaultValue: ""},
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
		{name: "sourceurl", description: "非标模式网络输入 URL；与 -file 同时提供时优先使用 -file", defaultValue: ""},
		{name: "nsbiptype", description: "非标模式最终导出 IP 类型筛选：all、ipv4 或 ipv6；只影响导出和上传内容", defaultValue: "all"},
		{name: "nsbqualified", description: "非标模式只导出测速合格结果；未测速、测速失败或低于阈值的结果不会导出", defaultValue: "true"},
		{name: "speedtest", description: "非标测速线程数；表示同时测速的 IP 数量，0 表示不测速", defaultValue: "0"},
		{name: "nsbdc", description: "非标模式指定结果数据中心；留空不限制", defaultValue: ""},
		{name: "tls", description: "非标模式是否启用 TLS", defaultValue: "true"},
		{name: "compact", description: "非标模式导出精简表格列", defaultValue: "true"},
		{name: "resultlimit", description: "非标模式延迟测试结果上限；必须为非 0 正整数", defaultValue: "1000"},
		{name: "nsbspeedmin", description: "非标模式测速结果阈值，单位 MB/s", defaultValue: "0.1"},
		{name: "nsbspeedlimit", description: "非标模式测速结果上限；0 表示关闭测速", defaultValue: "20"},
	}
)

var errCLIConfigCreated = errors.New("CLI 配置文件已生成")

func registerCLIFlags() *cliConfig {
	cfg := &cliConfig{}
	flag.Usage = printCLIUsage
	flag.BoolVar(&cfg.enabled, "cli", false, "启用命令行模式（默认启动 Web）")
	flag.StringVar(&cfg.mode, "mode", "official", "CLI 模式：official 或 nsb")
	flag.IntVar(&cfg.ipType, "iptype", 4, "官方模式 IP 类型：4 或 6")
	flag.IntVar(&cfg.threads, "threads", 100, "扫描并发数")
	flag.IntVar(&cfg.speedTest, "speedtest", 0, "非标测速线程数；表示同时测速的 IP 数量，0 表示不测速")
	flag.IntVar(&cfg.port, "testport", 443, "目标测试端口")
	flag.IntVar(&cfg.delay, "delay", 500, "延迟阈值（毫秒）")
	flag.StringVar(&cfg.dc, "dc", "", "官方模式指定数据中心，不填则自动选择最低延迟数据中心")
	flag.StringVar(&cfg.file, "file", "", "非标模式输入文件路径")
	flag.StringVar(&cfg.sourceURL, "sourceurl", "", "非标模式网络输入 URL；与 -file 同时提供时优先使用 -file")
	flag.StringVar(&cfg.nsbIPType, "nsbiptype", "all", "非标模式最终导出 IP 类型筛选：all、ipv4 或 ipv6")
	flag.BoolVar(&cfg.nsbQualified, "nsbqualified", true, "非标模式只导出测速合格结果")
	flag.StringVar(&cfg.nsbDC, "nsbdc", "", "非标模式指定结果数据中心")
	flag.StringVar(&cfg.outFile, "out", "ip.csv", "CLI 输出文件名")
	flag.IntVar(&cfg.speedLimit, "speedlimit", 0, "官方模式测速达标结果上限；0 表示关闭官方测速")
	flag.Float64Var(&cfg.speedMin, "speedmin", 0.1, "官方模式测速达标下限，单位 MB/s")
	flag.BoolVar(&cfg.enableTLS, "tls", true, "非标模式是否启用 TLS")
	flag.BoolVar(&cfg.compactNSB, "compact", true, "非标模式导出精简表格列")
	flag.IntVar(&cfg.resultLimit, "resultlimit", 1000, "非标模式延迟测试结果上限；必须为非 0 正整数")
	flag.Float64Var(&cfg.nsbSpeedMin, "nsbspeedmin", 0.1, "非标模式测速结果阈值，单位 MB/s")
	flag.IntVar(&cfg.nsbSpeedLimit, "nsbspeedlimit", 20, "非标模式测速结果上限；0 表示关闭测速")
	flag.BoolVar(&cfg.showProgress, "progress", true, "CLI 模式输出进度日志")
	flag.BoolVar(&cfg.noColor, "nocolor", false, "禁用 ANSI 颜色输出（cmd 等不支持的终端建议开启）")
	flag.BoolVar(&cfg.compactIPv4, "compactipv4", false, "精简本地 IPv4 地址库，按 /24 子网探测 TCP:80 连通性后覆盖 ips-v4.txt")
	flag.StringVar(&cfg.export.ConfigFile, "config", "", "CLI 导出/GitHub 配置文件路径")
	flag.StringVar(&cfg.export.Format, "format", "", "CLI 导出格式：csv 或 txt")
	flag.StringVar(&cfg.export.Fields, "fields", "", "CLI 导出字段：compact、all、ipport 或逗号分隔自定义字段")
	flag.BoolVar(&cfg.export.GitHub, "github", false, "CLI 导出后上传到 GitHub")
	flag.StringVar(&cfg.export.GHRepo, "ghrepo", "", "GitHub 仓库 owner/repo")
	flag.StringVar(&cfg.export.GHBranch, "ghbranch", "", "GitHub 分支")
	flag.StringVar(&cfg.export.GHPath, "ghpath", "", "GitHub 目标路径")
	flag.StringVar(&cfg.export.GHMessage, "ghmessage", "", "GitHub 提交信息")
	flag.StringVar(&cfg.export.GHToken, "ghtoken", "", "GitHub token")
	flag.StringVar(&cfg.export.GHTokenFile, "ghtokenfile", "", "GitHub token 文件")
	flag.StringVar(&cfg.export.GHUpload, "ghupload", "", "快速上传指定文件到 GitHub，不执行测试")
	return cfg
}

func runCLI(cfg *cliConfig) error {
	if !cfg.configResolved {
		if err := prepareCLIConfig(cfg); err != nil {
			return err
		}
	}
	printCLIConfig(cfg)

	if cfg.compactIPv4 {
		return runCompactIPv4CLI(cfg)
	}
	if strings.TrimSpace(cfg.export.GHUpload) != "" {
		return runCLIQuickGitHubUpload(cfg)
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

func prepareCLIConfig(cfg *cliConfig) error {
	if err := resolveCLIExportConfig(cfg); err != nil {
		return err
	}
	if cfg.noColor {
		disableANSIColors()
	}
	cfg.configResolved = true
	return nil
}

func runCLIQuickGitHubUpload(cfg *cliConfig) error {
	if !cfg.export.GitHub {
		return fmt.Errorf("使用 -ghupload 快速上传时需要同时启用 -github")
	}
	path := expandHome(cfg.export.GHUpload)
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.export.GHPath) == "" || cfg.export.GHPath == "results/ip."+cfg.export.Format {
		cfg.export.GHPath = "results/" + filepath.Base(path)
	}
	return uploadCLIExportToGitHub(cfg, string(content))
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

func resolveCLIExportConfig(cfg *cliConfig) error {
	provided := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	configPath := cfg.export.ConfigFile
	if configPath == "" {
		configPath = os.Getenv("CFDATA_CONFIG")
	}
	if configPath == "" {
		configPath = defaultCLIConfigPath()
	}
	fileCfg, created, err := loadOrCreateCLIConfig(configPath)
	if err != nil {
		return err
	}
	if created {
		fmt.Printf("[config] 已生成配置文件: %s\n", configPath)
		fmt.Println("[config] 优先级: 命令行参数 > 配置文件 > 环境变量 > 默认值")
		fmt.Println("[config] 请退出后按需编辑配置文件，再重新开始测试。")
		return errCLIConfigCreated
	}
	envCfg := cliExportConfig{
		Format:      os.Getenv("CFDATA_FORMAT"),
		Fields:      os.Getenv("CFDATA_FIELDS"),
		GHRepo:      os.Getenv("CFDATA_GHREPO"),
		GHBranch:    os.Getenv("CFDATA_GHBRANCH"),
		GHPath:      os.Getenv("CFDATA_GHPATH"),
		GHMessage:   os.Getenv("CFDATA_GHMESSAGE"),
		GHToken:     firstNonEmpty(os.Getenv("CFDATA_GHTOKEN"), os.Getenv("GITHUB_TOKEN")),
		GHTokenFile: os.Getenv("CFDATA_GHTOKENFILE"),
		GHUpload:    os.Getenv("CFDATA_GHUPLOAD"),
	}
	if value := strings.TrimSpace(os.Getenv("CFDATA_GITHUB")); value != "" {
		envCfg.GitHub = parseBoolEnv(value)
		envCfg.GitHubSet = true
	}
	applyCLIEnvConfig(cfg, provided)
	merged := defaultCLIExportConfig()
	mergeCLIExportConfig(&merged, envCfg, false)
	applyCLIFileConfig(cfg, fileCfg, provided)
	mergeCLIExportConfig(&merged, fileCfg.Export(), false)
	mergeCLIExportConfig(&merged, cfg.export, true, provided)
	merged.ConfigFile = configPath
	merged.Format = strings.ToLower(strings.TrimSpace(merged.Format))
	if merged.Format == "" {
		merged.Format = "csv"
	}
	if merged.Format != "csv" && merged.Format != "txt" {
		return fmt.Errorf("不支持的 -format: %s", merged.Format)
	}
	if strings.TrimSpace(merged.Fields) == "" {
		merged.Fields = "compact"
	}
	if strings.TrimSpace(merged.GHBranch) == "" {
		merged.GHBranch = "main"
	}
	if strings.TrimSpace(merged.GHMessage) == "" {
		merged.GHMessage = "update cfdata results"
	}
	if strings.TrimSpace(merged.GHPath) == "" || (!provided["ghpath"] && fileCfg.GHPath == "" && envCfg.GHPath == "") {
		merged.GHPath = "results/ip." + merged.Format
	}
	if merged.GHToken == "" && strings.TrimSpace(merged.GHTokenFile) != "" {
		data, err := os.ReadFile(expandHome(merged.GHTokenFile))
		if err != nil {
			return fmt.Errorf("读取 token 文件失败: %w", err)
		}
		merged.GHToken = strings.TrimSpace(string(data))
	}
	cfg.export = merged
	return nil
}

func applyCLIEnvConfig(cfg *cliConfig, provided map[string]bool) {
	setString := func(flagName, envName string, target *string) {
		if !provided[flagName] && strings.TrimSpace(os.Getenv(envName)) != "" {
			*target = strings.TrimSpace(os.Getenv(envName))
		}
	}
	setInt := func(flagName, envName string, target *int) {
		if provided[flagName] || strings.TrimSpace(os.Getenv(envName)) == "" {
			return
		}
		if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(envName))); err == nil {
			*target = v
		}
	}
	setFloat := func(flagName, envName string, target *float64) {
		if provided[flagName] || strings.TrimSpace(os.Getenv(envName)) == "" {
			return
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(envName)), 64); err == nil {
			*target = v
		}
	}
	setBool := func(flagName, envName string, target *bool) {
		if !provided[flagName] && strings.TrimSpace(os.Getenv(envName)) != "" {
			*target = parseBoolEnv(os.Getenv(envName))
		}
	}
	setString("mode", "CFDATA_MODE", &cfg.mode)
	setInt("iptype", "CFDATA_IPTYPE", &cfg.ipType)
	setInt("threads", "CFDATA_THREADS", &cfg.threads)
	setString("out", "CFDATA_OUT", &cfg.outFile)
	setInt("speedtest", "CFDATA_SPEEDTEST", &cfg.speedTest)
	setBool("progress", "CFDATA_PROGRESS", &cfg.showProgress)
	setBool("nocolor", "CFDATA_NOCOLOR", &cfg.noColor)
	if !provided["url"] && strings.TrimSpace(os.Getenv("CFDATA_URL")) != "" {
		speedTestURL = strings.TrimSpace(os.Getenv("CFDATA_URL"))
	}
	if !provided["dns"] && strings.TrimSpace(os.Getenv("CFDATA_DNS")) != "" {
		customDNSServer = strings.TrimSpace(os.Getenv("CFDATA_DNS"))
	}
	setBool("debug", "CFDATA_DEBUG", &debugMode)
	setBool("compactipv4", "CFDATA_COMPACTIPV4", &cfg.compactIPv4)
	setInt("testport", "CFDATA_TESTPORT", &cfg.port)
	setInt("delay", "CFDATA_DELAY", &cfg.delay)
	setString("dc", "CFDATA_DC", &cfg.dc)
	setInt("speedlimit", "CFDATA_SPEEDLIMIT", &cfg.speedLimit)
	setFloat("speedmin", "CFDATA_SPEEDMIN", &cfg.speedMin)
	setString("file", "CFDATA_FILE", &cfg.file)
	setString("sourceurl", "CFDATA_SOURCEURL", &cfg.sourceURL)
	setString("nsbiptype", "CFDATA_NSBIPTYPE", &cfg.nsbIPType)
	setBool("nsbqualified", "CFDATA_NSBQUALIFIED", &cfg.nsbQualified)
	setString("nsbdc", "CFDATA_NSBDC", &cfg.nsbDC)
	setBool("tls", "CFDATA_TLS", &cfg.enableTLS)
	setBool("compact", "CFDATA_COMPACT", &cfg.compactNSB)
	setInt("resultlimit", "CFDATA_RESULTLIMIT", &cfg.resultLimit)
	setFloat("nsbspeedmin", "CFDATA_NSBSPEEDMIN", &cfg.nsbSpeedMin)
	setInt("nsbspeedlimit", "CFDATA_NSBSPEEDLIMIT", &cfg.nsbSpeedLimit)
}

func defaultCLIExportConfig() cliExportConfig {
	return cliExportConfig{Format: "csv", Fields: "compact", GitHub: false, GHBranch: "main", GHPath: "", GHMessage: "update cfdata results"}
}

func defaultCLIFileConfig() cliFileConfig {
	return cliFileConfig{CLI: true, Mode: "official", IPType: 4, Threads: 100, Out: "ip.csv", SpeedTest: 0, Progress: true, NoColor: false, URL: "speed.cloudflare.com/__down?bytes=99999999", DNS: defaultDNSServers, Debug: false, CompactIPv4: false, TestPort: 443, Delay: 500, DC: "", SpeedLimit: 0, SpeedMin: 0.1, File: "", SourceURL: "", NSBIPType: "all", NSBQualified: true, NSBDC: "", TLS: true, Compact: true, ResultLimit: 1000, NSBSpeedMin: 0.1, NSBSpeedLimit: 20, Format: "csv", Fields: "compact", GitHub: false, GHBranch: "main", GHPath: "", GHMessage: "update cfdata results"}
}

func (c cliFileConfig) Export() cliExportConfig {
	return cliExportConfig{Format: c.Format, Fields: c.Fields, GitHub: c.GitHub, GitHubSet: true, GHRepo: c.GHRepo, GHBranch: c.GHBranch, GHPath: c.GHPath, GHMessage: c.GHMessage, GHToken: c.GHToken, GHTokenFile: c.GHTokenFile, GHUpload: c.GHUpload}
}

type cliExportConfigTemplate struct {
	Config          cliFileConfig    `json:"config"`
	Description     string           `json:"_description"`
	Priority        string           `json:"_priority"`
	Usage           string           `json:"_usage"`
	ConfigHelp      []cliConfigHelp  `json:"_config_help"`
	FormatValues    []string         `json:"_format_values"`
	FieldsValues    []string         `json:"_fields_values"`
	ModeValues      []string         `json:"_mode_values"`
	AvailableFields []cliResultField `json:"_available_fields"`
}

type cliConfigHelp struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Default     string   `json:"default"`
	Options     []string `json:"options,omitempty"`
}

func mergeCLIExportConfig(dst *cliExportConfig, src cliExportConfig, onlyProvided bool, provided ...map[string]bool) {
	isSet := func(flagName string, value string) bool {
		if onlyProvided {
			return len(provided) > 0 && provided[0][flagName]
		}
		return strings.TrimSpace(value) != ""
	}
	if isSet("config", src.ConfigFile) {
		dst.ConfigFile = src.ConfigFile
	}
	if isSet("format", src.Format) {
		dst.Format = src.Format
	}
	if isSet("fields", src.Fields) {
		dst.Fields = src.Fields
	}
	if (!onlyProvided && src.GitHubSet) || (onlyProvided && len(provided) > 0 && provided[0]["github"]) {
		dst.GitHub = src.GitHub
		dst.GitHubSet = true
	}
	if isSet("ghrepo", src.GHRepo) {
		dst.GHRepo = src.GHRepo
	}
	if isSet("ghbranch", src.GHBranch) {
		dst.GHBranch = src.GHBranch
	}
	if isSet("ghpath", src.GHPath) {
		dst.GHPath = src.GHPath
	}
	if isSet("ghmessage", src.GHMessage) {
		dst.GHMessage = src.GHMessage
	}
	if isSet("ghtoken", src.GHToken) {
		dst.GHToken = src.GHToken
	}
	if isSet("ghtokenfile", src.GHTokenFile) {
		dst.GHTokenFile = src.GHTokenFile
	}
	if isSet("ghupload", src.GHUpload) {
		dst.GHUpload = src.GHUpload
	}
}

func loadOrCreateCLIConfig(path string) (cliFileConfig, bool, error) {
	path = expandHome(path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return cliFileConfig{}, false, err
		}
		template := cliExportConfigTemplate{
			Config:          defaultCLIFileConfig(),
			Description:     "CFData CLI 全量配置；真正配置项在 config 内。",
			Priority:        "命令行参数 > 配置文件 > 环境变量 > 默认值",
			Usage:           "首次生成后建议退出并编辑本文件，再重新运行测试。布尔值使用 true/false。",
			ConfigHelp:      buildCLIConfigHelp(),
			FormatValues:    []string{"csv", "txt"},
			FieldsValues:    []string{"compact", "all", "ipport", "ipport,dc,loc", "ipport,latency,dc,loc"},
			ModeValues:      []string{"official", "nsb"},
			AvailableFields: cliResultFields,
		}
		var buf strings.Builder
		encoder := json.NewEncoder(&buf)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(template); err != nil {
			return cliFileConfig{}, false, err
		}
		if err := os.WriteFile(path, []byte(buf.String()), 0600); err != nil {
			return cliFileConfig{}, false, err
		}
		return cliFileConfig{}, true, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cliFileConfig{}, false, err
	}
	cfg := defaultCLIFileConfig()
	if len(strings.TrimSpace(string(data))) == 0 {
		return cfg, false, nil
	}
	template := cliExportConfigTemplate{Config: defaultCLIFileConfig()}
	if err := json.Unmarshal(data, &template); err == nil && (template.Config.Mode != "" || template.Config.Format != "" || template.Description != "") {
		cfg = template.Config
	} else if err := json.Unmarshal(data, &cfg); err != nil {
		return cliFileConfig{}, false, fmt.Errorf("解析配置文件失败 %s: %w", path, err)
	}
	return cfg, false, nil
}

func buildCLIConfigHelp() []cliConfigHelp {
	return []cliConfigHelp{
		{Name: "cli", Description: "启用 CLI 模式", Default: "true", Options: []string{"true", "false"}},
		{Name: "mode", Description: "运行模式", Default: "official", Options: []string{"official", "nsb"}},
		{Name: "iptype", Description: "官方模式 IP 类型", Default: "4", Options: []string{"4", "6"}},
		{Name: "threads", Description: "扫描并发数", Default: "100"},
		{Name: "out", Description: "本地导出文件名", Default: "ip.csv"},
		{Name: "speedtest", Description: "非标测速线程数；表示同时测速的 IP 数量，0 表示不测速", Default: "0"},
		{Name: "progress", Description: "输出进度日志", Default: "true", Options: []string{"true", "false"}},
		{Name: "nocolor", Description: "禁用 ANSI 颜色输出", Default: "false", Options: []string{"true", "false"}},
		{Name: "url", Description: "测速下载地址，不含协议前缀", Default: "speed.cloudflare.com/__down?bytes=99999999"},
		{Name: "dns", Description: "自定义 DNS 服务器；留空使用系统 DNS。用于 IP 库、locations、ASN、GitHub、网络 URL 输入等需要 DNS 的外部请求", Default: ""},
		{Name: "debug", Description: "开启调试输出和失败明细", Default: "false", Options: []string{"true", "false"}},
		{Name: "compactipv4", Description: "精简本地 IPv4 地址库并覆盖 ips-v4.txt", Default: "false", Options: []string{"true", "false"}},
		{Name: "testport", Description: "官方模式详细测试与测速端口", Default: "443"},
		{Name: "delay", Description: "延迟阈值，单位毫秒", Default: "500"},
		{Name: "dc", Description: "官方模式指定数据中心；留空自动选择最低延迟数据中心", Default: ""},
		{Name: "speedlimit", Description: "官方模式测速达标结果上限；0 表示关闭官方测速", Default: "0"},
		{Name: "speedmin", Description: "官方模式测速达标下限，单位 MB/s", Default: "0.1"},
		{Name: "file", Description: "非标模式输入文件路径", Default: ""},
		{Name: "sourceurl", Description: "非标模式网络输入 URL；与 file 同时提供时优先使用 file", Default: ""},
		{Name: "nsbiptype", Description: "非标模式最终导出 IP 类型筛选；只影响导出和上传内容", Default: "all", Options: []string{"all", "ipv4", "ipv6"}},
		{Name: "nsbdc", Description: "非标模式指定结果数据中心；留空不限制", Default: ""},
		{Name: "tls", Description: "非标模式启用 TLS；缺省端口随 TLS 为 443/80", Default: "true", Options: []string{"true", "false"}},
		{Name: "compact", Description: "非标模式本地 CSV 是否默认精简字段", Default: "true", Options: []string{"true", "false"}},
		{Name: "resultlimit", Description: "非标模式延迟测试结果上限；必须为非 0 正整数，达到上限后停止继续扫描并等待已启动并发完成", Default: "1000"},
		{Name: "nsbspeedmin", Description: "非标模式测速结果阈值，单位 MB/s", Default: "0.1"},
		{Name: "nsbspeedlimit", Description: "非标模式测速结果上限；0 表示关闭测速", Default: "20"},
		{Name: "format", Description: "导出/上传内容格式", Default: "csv", Options: []string{"csv", "txt"}},
		{Name: "fields", Description: "导出字段；支持 compact、all、ipport 或逗号分隔字段 key", Default: "compact", Options: []string{"compact", "all", "ipport", "ipport,dc,loc", "ipport,latency,dc,loc"}},
		{Name: "github", Description: "导出后上传到 GitHub", Default: "false", Options: []string{"true", "false"}},
		{Name: "ghrepo", Description: "GitHub 仓库，格式 owner/repo", Default: ""},
		{Name: "ghbranch", Description: "GitHub 分支", Default: "main"},
		{Name: "ghpath", Description: "GitHub 目标路径；留空时按 format 自动使用 results/ip.csv 或 results/ip.txt；文件不存在会新建，存在会覆盖", Default: "自动按 format 生成"},
		{Name: "ghmessage", Description: "GitHub 提交信息", Default: "update cfdata results"},
		{Name: "ghtoken", Description: "GitHub token；不推荐直接写入配置。强烈建议使用仅限制指定仓库读写权限的 token，并确保仓库内无重要数据，避免 token 泄露造成不必要的意外", Default: ""},
		{Name: "ghtokenfile", Description: "GitHub token 文件路径。强烈建议文件内 token 仅限制指定仓库读写权限，并确保仓库内无重要数据", Default: ""},
		{Name: "ghupload", Description: "快速上传指定文件到 GitHub，不执行测试；需 github=true", Default: ""},
	}
}

func applyCLIFileConfig(cfg *cliConfig, fileCfg cliFileConfig, provided map[string]bool) {
	setString := func(name string, target *string, value string) {
		if !provided[name] && strings.TrimSpace(value) != "" {
			*target = value
		}
	}
	setInt := func(name string, target *int, value int) {
		if !provided[name] {
			*target = value
		}
	}
	setFloat := func(name string, target *float64, value float64) {
		if !provided[name] {
			*target = value
		}
	}
	setBool := func(name string, target *bool, value bool) {
		if !provided[name] {
			*target = value
		}
	}
	if !provided["cli"] && fileCfg.CLI {
		cfg.enabled = fileCfg.CLI
	}
	setString("mode", &cfg.mode, fileCfg.Mode)
	setInt("iptype", &cfg.ipType, fileCfg.IPType)
	setInt("threads", &cfg.threads, fileCfg.Threads)
	setString("out", &cfg.outFile, fileCfg.Out)
	setInt("speedtest", &cfg.speedTest, fileCfg.SpeedTest)
	if !provided["progress"] {
		cfg.showProgress = fileCfg.Progress
	}
	if !provided["nocolor"] {
		cfg.noColor = fileCfg.NoColor
	}
	if !provided["url"] && strings.TrimSpace(fileCfg.URL) != "" {
		speedTestURL = fileCfg.URL
	}
	if !provided["dns"] && strings.TrimSpace(fileCfg.DNS) != "" {
		customDNSServer = fileCfg.DNS
	}
	if !provided["debug"] {
		debugMode = fileCfg.Debug
	}
	if !provided["compactipv4"] {
		cfg.compactIPv4 = fileCfg.CompactIPv4
	}
	setInt("testport", &cfg.port, fileCfg.TestPort)
	setInt("delay", &cfg.delay, fileCfg.Delay)
	setString("dc", &cfg.dc, fileCfg.DC)
	setInt("speedlimit", &cfg.speedLimit, fileCfg.SpeedLimit)
	setFloat("speedmin", &cfg.speedMin, fileCfg.SpeedMin)
	setString("file", &cfg.file, fileCfg.File)
	setString("sourceurl", &cfg.sourceURL, fileCfg.SourceURL)
	setString("nsbiptype", &cfg.nsbIPType, fileCfg.NSBIPType)
	setBool("nsbqualified", &cfg.nsbQualified, fileCfg.NSBQualified)
	setString("nsbdc", &cfg.nsbDC, fileCfg.NSBDC)
	if !provided["tls"] {
		cfg.enableTLS = fileCfg.TLS
	}
	if !provided["compact"] {
		cfg.compactNSB = fileCfg.Compact
	}
	setInt("resultlimit", &cfg.resultLimit, fileCfg.ResultLimit)
	setFloat("nsbspeedmin", &cfg.nsbSpeedMin, fileCfg.NSBSpeedMin)
	setInt("nsbspeedlimit", &cfg.nsbSpeedLimit, fileCfg.NSBSpeedLimit)
}

func defaultCLIConfigPath() string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return "cfdata-config.json"
	}
	return filepath.Join(filepath.Dir(exe), "cfdata-config.json")
}

func expandHome(path string) string {
	path = strings.TrimSpace(path)
	if path == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func parseBoolEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
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
		payload, ok := data.(nsbCSVCompletePayload)
		if !ok {
			debugWrongType("nsbCSVCompletePayload")
			break
		}
		session.nsbMutex.Lock()
		session.nsbHeaders = append([]string(nil), payload.Headers...)
		session.nsbRows = append([][]string(nil), payload.Rows...)
		session.nsbMutex.Unlock()
		fmt.Printf("%s[nsb-output]%s %s (%d rows)\n", ansiGreen, ansiReset, payload.File, len(payload.Rows))
		if payload.Status == "failed" {
			fmt.Printf("%s[nsb]%s 任务失败: 测试%s\n", ansiRed, ansiReset, payload.Message)
		} else if payload.Status == "partial" {
			fmt.Printf("%s[nsb]%s 任务结束: %s\n", ansiYellow, ansiReset, payload.Message)
		}
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
			return writeCLIExportAndMaybeUpload(cfg, officialScanRows(scanResults), "official-scan")
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
	} else if len(results) == 0 {
		fmt.Printf("%s[official]%s 没有可用的详细测试结果，跳过测速\n", ansiYellow, ansiReset)
	} else {
		setCLIProgress(session, "speed", 0, len(results))
		fmt.Printf("%s[official]%s 开始串行测速，达标上限=%d，下限=%.2fMB/s\n", ansiGreen, ansiReset, cfg.speedLimit, cfg.speedMin)
		results = runOfficialSpeedTests(context.Background(), session, results, cfg.port, cfg.speedLimit, cfg.speedMin)
	}
	return writeCLIExportAndMaybeUpload(cfg, officialResultRows(scanResults, results), "official")
}

func runNSBCLI(cfg *cliConfig) error {
	if strings.TrimSpace(cfg.file) == "" && strings.TrimSpace(cfg.sourceURL) == "" {
		return errors.New("非标模式需要通过 -file 或 -sourceurl 指定输入来源")
	}
	if cfg.threads <= 0 {
		cfg.threads = 100
	}
	if cfg.speedTest < 0 {
		cfg.speedTest = 0
	}
	if cfg.resultLimit <= 0 {
		return fmt.Errorf("-resultlimit 必须是非 0 正整数")
	}
	if cfg.nsbSpeedLimit < 0 {
		cfg.nsbSpeedLimit = 0
	}
	if cfg.nsbSpeedMin < 0 {
		cfg.nsbSpeedMin = 0
	}
	cfg.nsbIPType = normalizeIPTypeFilter(cfg.nsbIPType)
	if cfg.nsbIPType == "" {
		return fmt.Errorf("-nsbiptype 仅支持 all、ipv4 或 ipv6")
	}
	if cfg.delay < 0 {
		cfg.delay = 0
	}
	if strings.TrimSpace(cfg.outFile) == "" {
		cfg.outFile = "ip.csv"
	}
	inputName := cfg.file
	content := ""
	var err error
	if strings.TrimSpace(cfg.file) != "" {
		content, err = getFileContent(cfg.file)
		if err != nil {
			return err
		}
	} else {
		parsedURL, parseErr := url.Parse(cfg.sourceURL)
		if parseErr != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
			return errors.New("-sourceurl 必须是有效的 http/https 地址")
		}
		inputName = cfg.sourceURL
		content, err = getURLContent(cfg.sourceURL)
		if err != nil {
			return fmt.Errorf("获取非标网络输入失败: %w", err)
		}
	}

	session := newCLISession(cfg)
	if err := session.runTaskSync(func(ctx context.Context, session *appSession) {
		runNSBTask(ctx, session, inputName, content, cfg.outFile, cfg.threads, cfg.speedTest, speedTestURL, cfg.enableTLS, cfg.delay, cfg.resultLimit, cfg.nsbDC, cfg.nsbSpeedMin, cfg.nsbSpeedLimit, cfg.compactNSB)
	}); err != nil {
		return cliTaskError(err)
	}
	session.nsbMutex.Lock()
	rows := nsbPayloadRows(session.nsbHeaders, session.nsbRows)
	session.nsbMutex.Unlock()
	rows = filterCLIResultRowsByIPType(rows, cfg.nsbIPType)
	rows = filterCLIResultRowsByQualification(rows, cfg.nsbQualified, cfg.speedTest > 0 && cfg.nsbSpeedLimit > 0, cfg.nsbSpeedMin)
	if len(rows) == 0 {
		return nil
	}
	return writeCLIExportAndMaybeUpload(cfg, rows, "nsb")
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
		results[i].Speed = fmt.Sprintf("%.2fMB/s", speedMB)
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

	fmt.Printf("%s %s\n", colorize("CFData-WEB 版本:", ansiBold+ansiGreen), appVersion)
	checkAndPrintUpdate("")
	fmt.Println(colorize("[cli-config] 当前命令参数", ansiBold+ansiGreen))
	printGroup("通用参数", []item{
		{"cli", lookupCLIFlagDescription(cliCommonFlags, "cli"), strconv.FormatBool(cfg.enabled), "false"},
		{"mode", lookupCLIFlagDescription(cliCommonFlags, "mode"), cfg.mode, "official"},
		{"threads", lookupCLIFlagDescription(cliCommonFlags, "threads"), strconv.Itoa(cfg.threads), "100"},
		{"out", lookupCLIFlagDescription(cliCommonFlags, "out"), cfg.outFile, "ip.csv"},
		{"progress", lookupCLIFlagDescription(cliCommonFlags, "progress"), strconv.FormatBool(cfg.showProgress), "true"},
		{"nocolor", lookupCLIFlagDescription(cliCommonFlags, "nocolor"), strconv.FormatBool(cfg.noColor), "false"},
		{"url", lookupCLIFlagDescription(cliCommonFlags, "url"), speedTestURL, "speed.cloudflare.com/__down?bytes=99999999"},
		{"debug", lookupCLIFlagDescription(cliCommonFlags, "debug"), strconv.FormatBool(debugMode), "false"},
		{"compactipv4", lookupCLIFlagDescription(cliCommonFlags, "compactipv4"), strconv.FormatBool(cfg.compactIPv4), "false"},
		{"config", lookupCLIFlagDescription(cliCommonFlags, "config"), cfg.export.ConfigFile, "二进制目录/cfdata-config.json"},
		{"format", lookupCLIFlagDescription(cliCommonFlags, "format"), cfg.export.Format, "csv"},
		{"fields", lookupCLIFlagDescription(cliCommonFlags, "fields"), cfg.export.Fields, "compact"},
		{"github", lookupCLIFlagDescription(cliCommonFlags, "github"), strconv.FormatBool(cfg.export.GitHub), "false"},
		{"ghrepo", lookupCLIFlagDescription(cliCommonFlags, "ghrepo"), cfg.export.GHRepo, ""},
		{"ghbranch", lookupCLIFlagDescription(cliCommonFlags, "ghbranch"), cfg.export.GHBranch, "main"},
		{"ghpath", lookupCLIFlagDescription(cliCommonFlags, "ghpath"), cfg.export.GHPath, "<自动>"},
		{"ghmessage", lookupCLIFlagDescription(cliCommonFlags, "ghmessage"), cfg.export.GHMessage, "update cfdata results"},
		{"ghtoken", lookupCLIFlagDescription(cliCommonFlags, "ghtoken"), maskSecret(cfg.export.GHToken), ""},
		{"ghtokenfile", lookupCLIFlagDescription(cliCommonFlags, "ghtokenfile"), cfg.export.GHTokenFile, ""},
		{"ghupload", lookupCLIFlagDescription(cliCommonFlags, "ghupload"), cfg.export.GHUpload, ""},
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
		{"sourceurl", lookupCLIFlagDescription(cliNSBFlags, "sourceurl"), cfg.sourceURL, ""},
		{"nsbiptype", lookupCLIFlagDescription(cliNSBFlags, "nsbiptype"), cfg.nsbIPType, "all"},
		{"nsbqualified", lookupCLIFlagDescription(cliNSBFlags, "nsbqualified"), strconv.FormatBool(cfg.nsbQualified), "true"},
		{"speedtest", lookupCLIFlagDescription(cliNSBFlags, "speedtest"), strconv.Itoa(cfg.speedTest), "0"},
		{"nsbdc", lookupCLIFlagDescription(cliNSBFlags, "nsbdc"), cfg.nsbDC, ""},
		{"tls", lookupCLIFlagDescription(cliNSBFlags, "tls"), strconv.FormatBool(cfg.enableTLS), "true"},
		{"compact", lookupCLIFlagDescription(cliNSBFlags, "compact"), strconv.FormatBool(cfg.compactNSB), "true"},
		{"resultlimit", lookupCLIFlagDescription(cliNSBFlags, "resultlimit"), strconv.Itoa(cfg.resultLimit), "1000"},
		{"nsbspeedmin", lookupCLIFlagDescription(cliNSBFlags, "nsbspeedmin"), fmt.Sprintf("%.2f", cfg.nsbSpeedMin), "0.1"},
		{"nsbspeedlimit", lookupCLIFlagDescription(cliNSBFlags, "nsbspeedlimit"), strconv.Itoa(cfg.nsbSpeedLimit), "20"},
	})
	fmt.Println(colorize("----------------------------------------", ansiCyan))
}

func maskSecret(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	if len(value) <= 8 {
		return "********"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

func printCLIUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "%s\n", colorize("CFData 命令行帮助", ansiBold+ansiGreen))
	fmt.Fprintf(flag.CommandLine.Output(), "版本: %s\n", appVersion)
	checkAndPrintUpdate("")
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
	if strings.Contains(strings.ToLower(speed), "错误") || strings.Contains(speed, "失败") || strings.Contains(speed, "0MB/s") {
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

func writeCLIExportAndMaybeUpload(cfg *cliConfig, rows []cliResultRow, mode string) error {
	if len(rows) == 0 {
		return nil
	}
	content, err := formatCLIResults(rows, cfg.export)
	if err != nil {
		return err
	}
	filename := cfg.outFile
	if strings.TrimSpace(filename) == "" {
		filename = "ip." + cfg.export.Format
	}
	if ext := "." + cfg.export.Format; !strings.HasSuffix(strings.ToLower(filename), ext) {
		filename = strings.TrimSuffix(filename, filepath.Ext(filename)) + ext
	}
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

	if _, err := io.WriteString(file, content); err != nil {
		return err
	}
	fmt.Printf("[%s-output] %s (%d rows, %s)\n", mode, filename, len(rows), cfg.export.Format)
	if cfg.export.GitHub {
		if err := uploadCLIExportToGitHub(cfg, content); err != nil {
			return err
		}
	}
	return nil
}

func formatCLIResults(rows []cliResultRow, cfg cliExportConfig) (string, error) {
	fields := resolveCLIFields(cfg.Fields, cfg.Format, rows)
	if cfg.Format == "txt" {
		var b strings.Builder
		for _, row := range rows {
			ipport := row["ipport"]
			if ipport == "" {
				ipport = row["ip"] + ":" + row["port"]
			}
			extras := make([]string, 0, len(fields))
			for _, field := range fields {
				if field == "ipport" {
					continue
				}
				if value := strings.TrimSpace(row[field]); value != "" {
					extras = append(extras, value)
				}
			}
			b.WriteString(ipport)
			if len(extras) > 0 {
				b.WriteString("#")
				b.WriteString(strings.Join(extras, "-"))
			}
			b.WriteString("\n")
		}
		return b.String(), nil
	}

	var b strings.Builder
	writer := csv.NewWriter(&b)
	headers := make([]string, 0, len(fields))
	for _, field := range fields {
		headers = append(headers, cliFieldLabel(field))
	}
	if err := writer.Write(headers); err != nil {
		return "", err
	}
	for _, row := range rows {
		values := make([]string, 0, len(fields))
		for _, field := range fields {
			values = append(values, row[field])
		}
		if err := writer.Write(values); err != nil {
			return "", err
		}
	}
	writer.Flush()
	return b.String(), writer.Error()
}

func resolveCLIFields(spec, format string, rows []cliResultRow) []string {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" || spec == "compact" {
		if format == "txt" {
			return []string{"ipport", "dc", "loc"}
		}
		if rowsAreOfficial(rows) {
			if rowsHaveField(rows, "speed") {
				return []string{"ip", "port", "latency", "speed", "dc", "region", "city"}
			}
			return []string{"ip", "port", "latency", "dc", "region", "city"}
		}
		return []string{"ip", "port", "tls", "latency", "speed", "outboundIP", "ipType", "dc", "loc", "region", "city", "asnNumber", "asnOrg"}
	}
	if spec == "ipport" {
		return []string{"ipport"}
	}
	if spec == "all" {
		fields := make([]string, 0, len(cliResultFields))
		for _, field := range cliResultFields {
			if field.Key == "ipport" {
				continue
			}
			for _, row := range rows {
				if strings.TrimSpace(row[field.Key]) != "" {
					fields = append(fields, field.Key)
					break
				}
			}
		}
		return fields
	}
	parts := strings.Split(spec, ",")
	fields := make([]string, 0, len(parts))
	for _, part := range parts {
		field := strings.TrimSpace(part)
		if field != "" {
			fields = append(fields, field)
		}
	}
	if len(fields) == 0 {
		return []string{"ipport"}
	}
	return fields
}

func rowsAreOfficial(rows []cliResultRow) bool {
	if len(rows) == 0 {
		return false
	}
	for _, row := range rows {
		if hasAnyCLIField(row, "tls", "outboundIP", "ipType", "loc", "asnNumber", "asnOrg", "visitScheme", "tlsVersion", "sni", "httpVersion", "warp", "gateway", "rbi", "kex", "timestamp") {
			return false
		}
	}
	return true
}

func rowsHaveField(rows []cliResultRow, field string) bool {
	for _, row := range rows {
		if strings.TrimSpace(row[field]) != "" {
			return true
		}
	}
	return false
}

func hasAnyCLIField(row cliResultRow, fields ...string) bool {
	for _, field := range fields {
		if strings.TrimSpace(row[field]) != "" {
			return true
		}
	}
	return false
}

func cliFieldLabel(key string) string {
	for _, field := range cliResultFields {
		if field.Key == key {
			return field.Label
		}
	}
	return key
}

func officialScanRows(scanResults []ScanResult) []cliResultRow {
	rows := make([]cliResultRow, 0, len(scanResults))
	for _, res := range scanResults {
		rows = append(rows, cliResultRow{"ip": res.IP, "port": strconv.Itoa(res.Port), "ipport": fmt.Sprintf("%s:%d", res.IP, res.Port), "dc": res.DataCenter, "region": res.Region, "city": res.City, "latency": res.LatencyStr})
	}
	return rows
}

func officialResultRows(scanResults []ScanResult, testResults []TestResult) []cliResultRow {
	if len(testResults) == 0 {
		rows := officialScanRows(scanResults)
		sortOfficialRows(rows)
		return rows
	}
	scanByIP := make(map[string]ScanResult, len(scanResults))
	for _, res := range scanResults {
		scanByIP[res.IP] = res
	}
	rows := make([]cliResultRow, 0, len(testResults))
	for _, res := range testResults {
		scan := scanByIP[res.IP]
		port := scan.Port
		if port == 0 {
			port = res.Port
		}
		rows = append(rows, cliResultRow{"ip": res.IP, "port": strconv.Itoa(port), "ipport": fmt.Sprintf("%s:%d", res.IP, port), "dc": scan.DataCenter, "region": scan.Region, "city": scan.City, "latency": fmt.Sprintf("%dms", res.AvgLatency/time.Millisecond), "speed": res.Speed})
		if rows[len(rows)-1]["dc"] == "" {
			rows[len(rows)-1]["dc"] = res.DataCenter
			rows[len(rows)-1]["region"] = res.Region
			rows[len(rows)-1]["city"] = res.City
		}
	}
	sortOfficialRows(rows)
	return rows
}

func sortOfficialRows(rows []cliResultRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		speedI, okI := parseSpeedMBForSort(rows[i]["speed"])
		speedJ, okJ := parseSpeedMBForSort(rows[j]["speed"])
		if okI != okJ {
			return okI
		}
		if okI && speedI != speedJ {
			return speedI > speedJ
		}
		latencyI := parseLatencyMSForSort(rows[i]["latency"])
		latencyJ := parseLatencyMSForSort(rows[j]["latency"])
		if latencyI != latencyJ {
			return latencyI < latencyJ
		}
		return rows[i]["ip"] < rows[j]["ip"]
	})
}

func parseSpeedMBForSort(value string) (float64, bool) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "MB/s") {
		return 0, false
	}
	speed, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(value, "MB/s")), 64)
	if err != nil {
		return 0, false
	}
	return speed, true
}

func parseLatencyMSForSort(value string) float64 {
	latency, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(value, "ms")), 64)
	if err != nil {
		return math.MaxFloat64
	}
	return latency
}

func nsbPayloadRows(headers []string, rows [][]string) []cliResultRow {
	result := make([]cliResultRow, 0, len(rows))
	for _, row := range rows {
		item := cliResultRow{}
		for idx, header := range headers {
			if idx >= len(row) {
				continue
			}
			if key := cliFieldKeyFromHeader(header); key != "" {
				item[key] = row[idx]
			}
		}
		item["ipport"] = item["ip"] + ":" + item["port"]
		result = append(result, item)
	}
	return result
}

func filterCLIResultRowsByIPType(rows []cliResultRow, filter string) []cliResultRow {
	filter = normalizeIPTypeFilter(filter)
	if filter == "all" {
		return rows
	}
	filtered := make([]cliResultRow, 0, len(rows))
	for _, row := range rows {
		if strings.EqualFold(strings.TrimSpace(row["ipType"]), filter) {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func filterCLIResultRowsByQualification(rows []cliResultRow, onlyQualified bool, speedEnabled bool, speedMin float64) []cliResultRow {
	if !onlyQualified || !speedEnabled {
		return rows
	}
	filtered := make([]cliResultRow, 0, len(rows))
	for _, row := range rows {
		if nsbRowQualified(row["speed"], speedMin) {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func nsbRowQualified(speed string, speedMin float64) bool {
	value, ok := parseSpeedMBForSort(speed)
	return ok && value >= speedMin
}

func normalizeIPTypeFilter(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "all", "全部", "全部展示":
		return "all"
	case "4", "ipv4":
		return "ipv4"
	case "6", "ipv6":
		return "ipv6"
	default:
		return ""
	}
}

func cliFieldKeyFromHeader(header string) string {
	header = normalizeNSBHeaderForCLI(header)
	for _, field := range cliResultFields {
		if field.Label == header {
			return field.Key
		}
	}
	return ""
}

func normalizeNSBHeaderForCLI(header string) string {
	switch strings.TrimSpace(header) {
	case "IP":
		return "IP地址"
	case "端口":
		return "端口号"
	default:
		return strings.TrimSpace(header)
	}
}

func uploadCLIExportToGitHub(cfg *cliConfig, content string) error {
	parts := strings.Split(strings.TrimSpace(cfg.export.GHRepo), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("-ghrepo 必须是 owner/repo")
	}
	if strings.TrimSpace(cfg.export.GHToken) == "" {
		return fmt.Errorf("启用 -github 时需要 -ghtoken、-ghtokenfile、CFDATA_GHTOKEN 或 GITHUB_TOKEN")
	}
	params := githubUploadRequest{Token: cfg.export.GHToken, Owner: parts[0], Repo: parts[1], Branch: cfg.export.GHBranch, Path: cfg.export.GHPath, Message: cfg.export.GHMessage, Content: content}
	downloadURL, err := uploadGitHubContent(context.Background(), params)
	if err != nil {
		return err
	}
	fmt.Printf("%s[github]%s uploaded %s\n", ansiGreen, ansiReset, downloadURL)
	return nil
}
