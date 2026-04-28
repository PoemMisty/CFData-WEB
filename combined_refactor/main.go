package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var webUser, webPassword string
var webSessionMinutes int
var boolFlagNames = []string{"cli", "tls", "progress", "debug", "nocolor", "compactipv4", "compact"}

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
	flag.IntVar(&speedTestWorkers, "speedtest", 5, "默认测速并发")
	flag.BoolVar(&debugMode, "debug", false, "开启调试输出（导出失败明细 CSV）")
	flag.StringVar(&webUser, "user", "", "Web 认证用户名（不设置则不启用认证）")
	flag.StringVar(&webPassword, "password", "", "Web 认证密码（需同时设置 -user）")
	flag.IntVar(&webSessionMinutes, "session", 720, "Web 登录会话有效期（分钟）")
	flag.Parse()
	if webSessionMinutes <= 0 {
		webSessionMinutes = 720
	}
	webSessionTTL = time.Duration(webSessionMinutes) * time.Minute

	initLocations()
	if cliCfg.enabled {
		if err := runCLI(cliCfg); err != nil {
			if errors.Is(err, errCLIConfigCreated) {
				return
			}
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
	fmt.Printf("服务启动于 http://localhost:%d\n", listenPort)
	if webUser != "" && webPassword != "" {
		fmt.Printf("Web 认证已启用，用户名: %s\n", webUser)
		fmt.Printf("Web 会话有效期: %s 分钟\n", strconv.Itoa(webSessionMinutes))
	} else if webUser != "" || webPassword != "" {
		fmt.Println("警告： 需要同时设置 -user 和 -password 才会启用认证")
	}
	fmt.Printf("当前测速网址: %s\n", speedTestURL)
	fmt.Printf("调试模式: %v\n", debugMode)
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("启动失败: %v\n", err)
	}
}
