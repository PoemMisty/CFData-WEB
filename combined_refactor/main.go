package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var webUser, webPassword string
var webSessionMinutes int
var boolFlagNames = []string{"cli", "tls", "progress", "debug", "nocolor", "compactipv4", "compact", "github", "nsbqualified"}

type latestReleaseInfo struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

func getLatestRelease(ctx context.Context) (latestReleaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/PoemMisty/CFData-WEB/releases/latest", nil)
	if err != nil {
		return latestReleaseInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "CFData-WEB/"+appVersion)
	client := http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return latestReleaseInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return latestReleaseInfo{}, fmt.Errorf("GitHub 返回状态 %d", resp.StatusCode)
	}
	var info latestReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return latestReleaseInfo{}, err
	}
	if info.HTMLURL == "" {
		info.HTMLURL = releaseLatestURL
	}
	return info, nil
}

func versionIsOlder(current, latest string) bool {
	current = strings.TrimPrefix(strings.TrimSpace(current), "v")
	latest = strings.TrimPrefix(strings.TrimSpace(latest), "v")
	if current == "" || latest == "" || current == "dev" {
		return false
	}
	cParts := strings.FieldsFunc(current, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	lParts := strings.FieldsFunc(latest, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	for i := 0; i < len(cParts) || i < len(lParts); i++ {
		c, l := 0, 0
		if i < len(cParts) {
			c, _ = strconv.Atoi(cParts[i])
		}
		if i < len(lParts) {
			l, _ = strconv.Atoi(lParts[i])
		}
		if c != l {
			return c < l
		}
	}
	return false
}

func checkAndPrintUpdate(prefix string) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	info, err := getLatestRelease(ctx)
	if err != nil {
		fmt.Printf("%s更新检测失败: %v\n", prefix, err)
		return
	}
	if versionIsOlder(appVersion, info.TagName) {
		fmt.Printf("%s发现新版本 %s，下载: %s\n", prefix, info.TagName, releaseLatestURL)
	}
}

func rewriteBoolFlagArgs() {
	if len(os.Args) <= 2 {
		return
	}
	boolSet := map[string]struct{}{}
	for _, n := range boolFlagNames {
		boolSet[n] = struct{}{}
	}
	rewritten := append([]string(nil), os.Args[:1]...)
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if name, ok := matchBoolFlag(arg, boolSet); ok && i+1 < len(os.Args) {
			next := strings.ToLower(os.Args[i+1])
			if next == "true" || next == "false" || next == "1" || next == "0" || next == "t" || next == "f" {
				rewritten = append(rewritten, "-"+name+"="+next)
				i++
				continue
			}
		}
		rewritten = append(rewritten, arg)
	}
	os.Args = rewritten
}

func matchBoolFlag(arg string, boolSet map[string]struct{}) (string, bool) {
	if !strings.HasPrefix(arg, "-") {
		return "", false
	}
	name := strings.TrimLeft(arg, "-")
	if strings.Contains(name, "=") {
		return "", false
	}
	if _, ok := boolSet[name]; ok {
		return name, true
	}
	return "", false
}

func hasNoColorArg() bool {
	for _, arg := range os.Args[1:] {
		name := strings.TrimLeft(arg, "-")
		if name == "nocolor" || strings.HasPrefix(name, "nocolor=") {
			if name == "nocolor" || strings.EqualFold(strings.TrimPrefix(name, "nocolor="), "true") {
				return true
			}
		}
	}
	return false
}

func main() {
	rewriteBoolFlagArgs()
	if !enableTerminalANSI() || os.Getenv("NO_COLOR") != "" || hasNoColorArg() {
		disableANSIColors()
	}
	cliCfg := registerCLIFlags()

	flag.IntVar(&listenPort, "port", 13335, "服务监听端口")
	flag.StringVar(&speedTestURL, "url", "speed.cloudflare.com/__down?bytes=99999999", "测速下载地址（不含协议前缀）")
	flag.StringVar(&customDNSServer, "dns", defaultDNSServers, "自定义 DNS 服务器，例如 223.5.5.5、8.8.8.8:53 或逗号分隔多个；留空使用系统 DNS")
	flag.BoolVar(&debugMode, "debug", false, "开启调试输出（导出失败明细 CSV）")
	flag.StringVar(&webUser, "user", "", "Web 认证用户名（不设置则不启用认证）")
	flag.StringVar(&webPassword, "password", "", "Web 认证密码（需同时设置 -user）")
	flag.IntVar(&webSessionMinutes, "session", 720, "Web 登录会话有效期（分钟）")
	flag.Parse()
	if cliCfg.enabled {
		if err := prepareCLIConfig(cliCfg); err != nil {
			if errors.Is(err, errCLIConfigCreated) {
				return
			}
			fmt.Printf("CLI 执行失败: %v\n", err)
			return
		}
	}
	speedTestWorkers = cliCfg.speedTest
	configureHTTPClients()
	if webSessionMinutes <= 0 {
		webSessionMinutes = 720
	}
	webSessionTTL = time.Duration(webSessionMinutes) * time.Minute

	initLocations()
	if cliCfg.enabled {
		if err := runCLI(cliCfg); err != nil {
			fmt.Printf("CLI 执行失败: %v\n", err)
		}
		return
	}

	http.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleLoginPost(w, r)
			return
		}
		handleLoginPage(w, r)
	})
	http.HandleFunc("/auth/logout", handleLogout)

	http.HandleFunc("/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile("index.html")
		if err != nil {
			http.Error(w, "无法加载页面", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	}))
	http.HandleFunc("/ws", requireAuth(handleWebSocket))

	addr := fmt.Sprintf(":%d", listenPort)
	fmt.Printf("CFData-WEB 版本: %s\n", appVersion)
	go checkAndPrintUpdate("")
	fmt.Printf("服务启动于 http://localhost:%d\n", listenPort)
	if webUser != "" && webPassword != "" {
		fmt.Printf("Web 认证已启用，用户名: %s\n", webUser)
		fmt.Printf("Web 会话有效期: %s 分钟\n", strconv.Itoa(webSessionMinutes))
	} else if webUser != "" || webPassword != "" {
		fmt.Println("警告： 需要同时设置 -user 和 -password 才会启用认证")
	}
	fmt.Printf("当前测速网址: %s\n", speedTestURL)
	if strings.TrimSpace(customDNSServer) == "" {
		fmt.Println("当前 DNS: 系统 DNS")
	} else {
		fmt.Printf("当前 DNS: %s\n", customDNSServer)
	}
	fmt.Printf("调试模式: %v\n", debugMode)
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("启动失败: %v\n", err)
	}
}
