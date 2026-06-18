package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	wsPingInterval  = 30 * time.Second
	wsWriteDeadline = 10 * time.Second
	wsReadDeadline  = 90 * time.Second
)

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("WebSocket 升级失败:", err)
		return
	}

	session := &appSession{ws: ws}
	defer func() {
		if session.shouldCancelOnDisconnect() {
			session.cancelTaskSilently()
		}
		ws.Close()
	}()

	ws.SetReadDeadline(time.Now().Add(wsReadDeadline))
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(wsReadDeadline))
		return nil
	})

	pingStop := make(chan struct{})
	defer close(pingStop)
	safeGo("ws-ping", session, func() {
		ticker := time.NewTicker(wsPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-pingStop:
				return
			case <-ticker.C:
				session.wsMutex.Lock()
				if session.wsClosed {
					session.wsMutex.Unlock()
					return
				}
				err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(wsWriteDeadline))
				session.wsMutex.Unlock()
				if err != nil {
					return
				}
			}
		}
	})

	cfCountry := ""
	cfCountryOK := false
	if !skipGeoCheck {
		ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
		cfCountry, cfCountryOK = detectCloudflareTraceCountry(ctx)
		cancel()
	}
	defaultSpeedURL, speedISP, speedISPErr := resolveStartupSpeedTestURL(r.Context(), speedTestURL)
	if speedISPErr != nil {
		recordDebugError("speed_isp_check", speedISPErr.Error())
	}
	if speedISPErr == nil {
		recordDebugByLevel("all", "speed_isp_check", fmt.Sprintf("asn=%d org=%s mobile=%v selected=%s", speedISP.ASN, speedISP.ASOrganization, isChinaMobileISP(speedISP), currentAutoSpeedURLDefault()))
	}
	session.sendWSMessage("init_config", map[string]interface{}{
		"speedTestURL":     speedTestURL,
		"speedTestDefault": defaultSpeedURL,
		"speedTestWorkers": speedTestWorkers,
		"debug":            debugMode,
		"version":          appVersion,
		"releaseURL":       releaseLatestURL,
		"cfCountry":        cfCountry,
		"proxyWarning":     !skipGeoCheck && (!cfCountryOK || shouldWarnProxyCountry(cfCountry)),
		"geoCheckOK":       cfCountryOK,
		"skipGeoCheck":     skipGeoCheck,
	})
	if backgroundSession := currentBackgroundTaskSession(); backgroundSession != nil {
		session.sendWSMessage("background_task_found", backgroundSession.backgroundSummary())
	}
	safeGo("version-check", session, func() {
		ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
		defer cancel()
		info, err := getLatestRelease(ctx)
		if err != nil {
			recordDebugError("version_check", err.Error())
			session.sendWSMessage("version_info", map[string]interface{}{"version": appVersion, "releaseURL": releaseLatestURL, "error": err.Error()})
			return
		}
		session.sendWSMessage("version_info", map[string]interface{}{"version": appVersion, "latest": info.TagName, "releaseURL": releaseLatestURL, "hasUpdate": versionIsOlder(appVersion, info.TagName)})
	})

	safeHandler := func(name string, fn func(json.RawMessage), data json.RawMessage) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("handler %s panic: %v\n%s\n", name, r, debug.Stack())
				recordProgramDebugError("handler_panic", fmt.Sprintf("%s: %v\n%s", name, r, debug.Stack()))
				session.sendWSMessage("error", fmt.Sprintf("内部错误（%s），请重试；若持续发生请查看后端日志", name))
				session.cancelTaskSilently()
			}
		}()
		fn(data)
	}

	handlers := map[string]func(json.RawMessage){
		"start_task": func(data json.RawMessage) {
			var params startTaskRequest
			if err := json.Unmarshal(data, &params); err != nil {
				session.sendWSMessage("error", "start_task 参数解析失败")
				return
			}
			if params.Threads <= 0 {
				params.Threads = 100
			}
			if params.Port <= 0 {
				params.Port = 443
			}
			if params.Delay < 0 {
				params.Delay = 0
			}
			session.startTaskNamed("官方优选扫描", "official", map[string]interface{}{"ipType": params.IPType, "threads": params.Threads, "port": params.Port, "delay": params.Delay}, func(ctx context.Context, session *appSession) {
				runOfficialTask(ctx, session, params.IPType, params.Threads, params.Port)
			})
		},
		"start_test": func(data json.RawMessage) {
			var params startTestRequest
			if err := json.Unmarshal(data, &params); err != nil {
				session.sendWSMessage("error", "start_test 参数解析失败")
				return
			}
			if params.Port <= 0 {
				params.Port = 443
			}
			if params.Delay < 0 {
				params.Delay = 0
			}
			session.startTaskNamed("官方详细测试", "official", map[string]interface{}{"dc": params.DC, "port": params.Port, "delay": params.Delay}, func(ctx context.Context, session *appSession) {
				runDetailedTest(ctx, session, params.DC, params.Port, params.Delay)
			})
		},
		"start_speed_test": func(data json.RawMessage) {
			var params startSpeedTestRequest
			if err := json.Unmarshal(data, &params); err != nil {
				session.sendWSMessage("error", "start_speed_test 参数解析失败")
				return
			}
			if params.Port <= 0 {
				params.Port = 443
			}
			session.startTaskNamed("单 IP 测速", "official", map[string]interface{}{"ip": params.IP, "port": params.Port, "url": params.URL}, func(ctx context.Context, session *appSession) {
				runSpeedTest(ctx, session, params.IP, params.Port, params.URL)
			})
		},
		"start_official_speed_batch": func(data json.RawMessage) {
			var params startOfficialSpeedBatchRequest
			if err := json.Unmarshal(data, &params); err != nil {
				session.sendWSMessage("error", "start_official_speed_batch 参数解析失败")
				return
			}
			if params.Port <= 0 {
				params.Port = 443
			}
			if params.SpeedLimit < 0 {
				params.SpeedLimit = 0
			}
			if params.SpeedMin <= 0 {
				params.SpeedMin = 0.1
			}
			if strings.TrimSpace(params.URL) == "" {
				params.URL = speedTestURL
			}
			session.startTaskNamed("官方批量测速", "official", map[string]interface{}{"port": params.Port, "url": params.URL, "speedLimit": params.SpeedLimit, "speedMin": params.SpeedMin, "skipTested": params.SkipTested}, func(ctx context.Context, session *appSession) {
				runOfficialSpeedBatch(ctx, session, params.Port, params.URL, params.SpeedLimit, params.SpeedMin, params.Results, params.SkipTested)
			})
		},
		"start_nsb_task": func(data json.RawMessage) {
			var params startNSBTaskRequest
			if err := json.Unmarshal(data, &params); err != nil {
				session.sendWSMessage("error", "start_nsb_task 参数解析失败")
				return
			}
			if params.MaxThreads <= 0 {
				params.MaxThreads = speedTestWorkers
			}
			if params.SpeedTest < 0 {
				params.SpeedTest = 0
			}
			if params.Delay < 0 {
				params.Delay = 0
			}
			if params.ResultLimit < 0 {
				params.ResultLimit = 0
			}
			if params.SpeedLimit < 0 {
				params.SpeedLimit = 0
			}
			if params.SpeedMin < 0 {
				params.SpeedMin = 0
			}
			if strings.TrimSpace(params.SpeedURL) == "" {
				params.SpeedURL = speedTestURL
			}
			if strings.TrimSpace(params.OutFile) == "" {
				params.OutFile = "ip.csv"
			}
			hasFileContent := strings.TrimSpace(params.FileContent) != ""
			hasSourceURL := strings.TrimSpace(params.SourceURL) != ""
			if hasFileContent == hasSourceURL {
				session.sendWSMessage("error", "请选择本地文件或网络URL（二选一）")
				return
			}
			if hasSourceURL {
				parsedURL, err := url.Parse(params.SourceURL)
				if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
					session.sendWSMessage("error", "网络URL必须是有效的 http/https 地址")
					return
				}
			}
			session.startTaskNamed("非标优选", "nsb", map[string]interface{}{"fileName": params.FileName, "sourceURL": params.SourceURL, "outFile": params.OutFile, "maxThreads": params.MaxThreads, "fallbackPort": params.FallbackPort, "speedTest": params.SpeedTest, "speedURL": params.SpeedURL, "enableTLS": params.EnableTLS, "delay": params.Delay, "resultLimit": params.ResultLimit, "dc": params.DC, "speedMin": params.SpeedMin, "speedLimit": params.SpeedLimit, "compact": params.Compact}, func(ctx context.Context, session *appSession) {
				fileName := params.FileName
				fileContent := params.FileContent
				if hasSourceURL {
					session.sendWSMessage("log", "正在获取非标网络输入: "+params.SourceURL)
					content, err := getURLContentWithContext(ctx, params.SourceURL)
					if err != nil {
						if ctx.Err() != nil {
							return
						}
						session.sendWSMessage("error", "获取非标网络输入失败: "+err.Error())
						return
					}
					fileName = params.SourceURL
					fileContent = content
				}
				runNSBTask(ctx, session, fileName, fileContent, params.OutFile, params.MaxThreads, params.FallbackPort, params.SpeedTest, params.SpeedURL, params.EnableTLS, params.Delay, params.ResultLimit, params.DC, params.SpeedMin, params.SpeedLimit, params.Compact)
			})
		},
		"start_nsb_speed_batch": func(data json.RawMessage) {
			var params startNSBSpeedBatchRequest
			if err := json.Unmarshal(data, &params); err != nil {
				session.sendWSMessage("error", "start_nsb_speed_batch 参数解析失败")
				return
			}
			if params.SpeedTest < 0 {
				params.SpeedTest = 0
			}
			if params.SpeedLimit < 0 {
				params.SpeedLimit = 0
			}
			if params.SpeedMin <= 0 {
				params.SpeedMin = 0.1
			}
			if strings.TrimSpace(params.SpeedURL) == "" {
				params.SpeedURL = speedTestURL
			}
			if len(params.Results) == 0 {
				session.sendWSMessage("error", "没有可测速的非标结果")
				return
			}
			session.startTaskNamed("非标批量测速", "nsb", map[string]interface{}{"speedTest": params.SpeedTest, "speedURL": params.SpeedURL, "enableTLS": params.EnableTLS, "speedMin": params.SpeedMin, "speedLimit": params.SpeedLimit, "skipTested": params.SkipTested, "compact": params.Compact}, func(ctx context.Context, session *appSession) {
				runNSBSpeedBatch(ctx, session, params.Results, params.SpeedTest, params.SpeedURL, params.EnableTLS, params.SpeedMin, params.SpeedLimit, params.SkipTested, params.Compact)
			})
		},
		"stop_task": func(data json.RawMessage) {
			if backgroundSession := currentBackgroundTaskSession(); backgroundSession != nil {
				if session != backgroundSession {
					backgroundSession.attachWebSocket(ws)
					session = backgroundSession
				}
				backgroundSession.stopTask()
				return
			}
			session.stopTask()
		},
		"run_in_background": func(data json.RawMessage) {
			if !session.enableBackgroundTask() {
				session.sendWSMessage("error", "当前没有可转入后台的运行任务")
				return
			}
			session.sendWSMessage("background_task_enabled", session.backgroundSummary())
			session.sendWSMessage("log", "当前任务已转入后台运行")
		},
		"follow_background_task": func(data json.RawMessage) {
			backgroundSession := currentBackgroundTaskSession()
			if backgroundSession == nil {
				session.sendWSMessage("error", "当前没有可跟随的后台任务")
				return
			}
			backgroundSession.attachWebSocket(ws)
			session = backgroundSession
			snapshot := backgroundSession.backgroundSummary()
			backgroundSession.sendWSMessage("background_task_following", snapshot)
			
			if !snapshot.Running && snapshot.Phase == "完成" {
				backgroundSession.nsbMutex.Lock()
				payload := backgroundSession.nsbCompletePayload
				backgroundSession.nsbMutex.Unlock()
				if payload != nil {
					backgroundSession.sendWSMessage("nsb_csv_complete", *payload)
				}
			}
		},
		"get_background_task_status": func(data json.RawMessage) {
			backgroundSession := currentBackgroundTaskSession()
			if backgroundSession == nil {
				session.sendWSMessage("background_task_missing", nil)
				return
			}
			session.sendWSMessage("background_task_update", backgroundSession.backgroundSummary())
		},
		"compact_ipv4": func(data json.RawMessage) {
			session.startTaskNamed("IPv4 地址库精简", "official", nil, func(ctx context.Context, session *appSession) {
				runCompactIPv4Task(ctx, session)
			})
		},
		"reset_all_config": func(data json.RawMessage) {
			resetAllConfigFiles(session)
		},
		"check_proxy_country": func(data json.RawMessage) {
			if skipGeoCheck {
				session.sendWSMessage("proxy_country_result", map[string]interface{}{"cfCountry": "SKIPPED", "proxyWarning": false, "skipGeoCheck": true})
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
			country, countryOK := detectCloudflareTraceCountry(ctx)
			cancel()
			session.sendWSMessage("proxy_country_result", map[string]interface{}{"cfCountry": country, "proxyWarning": !countryOK || shouldWarnProxyCountry(country), "geoCheckOK": countryOK})
		},
		"github_upload": func(data json.RawMessage) {
			var params githubUploadRequest
			if err := json.Unmarshal(data, &params); err != nil {
				session.sendWSMessage("error", "github_upload 参数解析失败")
				return
			}
			safeGo("github-upload", session, func() {
				downloadURL, err := uploadGitHubContentWithRetry(r.Context(), params, func(attempt, total int, err error) {
					if params.Silent {
						return
					}
					if err == nil {
						session.sendWSMessage("github_upload_status", map[string]interface{}{"attempt": attempt, "total": total, "message": fmt.Sprintf("第 %d/%d 次上传中", attempt, total)})
						return
					}
					session.sendWSMessage("github_upload_status", map[string]interface{}{"attempt": attempt, "total": total, "message": fmt.Sprintf("第 %d/%d 次上传失败，准备重试: %s", attempt, total, err.Error())})
				})
				if err != nil {
					session.sendWSMessage("github_upload_error", map[string]interface{}{"path": params.Path, "message": "上传 GitHub 失败: " + err.Error(), "silent": params.Silent})
					return
				}
				session.sendWSMessage("github_upload_result", map[string]interface{}{"path": params.Path, "rawURL": downloadURL, "silent": params.Silent})
			})
		},
	}

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			recordDebugNotice("websocket_read", err.Error())
			break
		}

		var request wsRequest
		if err := json.Unmarshal(msg, &request); err != nil {
			session.sendWSMessage("error", "请求格式错误")
			continue
		}

		handler, ok := handlers[request.Type]
		if !ok {
			session.sendWSMessage("error", "未知请求类型")
			continue
		}
		safeHandler(request.Type, handler, request.Data)
	}
}

const githubUploadMaxAttempts = 3

func uploadGitHubContentWithRetry(ctx context.Context, params githubUploadRequest, onAttempt func(attempt, total int, err error)) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= githubUploadMaxAttempts; attempt++ {
		if onAttempt != nil {
			onAttempt(attempt, githubUploadMaxAttempts, nil)
		}
		downloadURL, err := uploadGitHubContent(ctx, params)
		if err == nil {
			return downloadURL, nil
		}
		lastErr = err
		recordDebugError("github_upload_attempt", fmt.Sprintf("attempt=%d/%d path=%s err=%v", attempt, githubUploadMaxAttempts, params.Path, err))
		if onAttempt != nil {
			onAttempt(attempt, githubUploadMaxAttempts, err)
		}
		if attempt < githubUploadMaxAttempts {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
	}
	return "", lastErr
}

func uploadGitHubContent(ctx context.Context, params githubUploadRequest) (string, error) {
	params.Token = strings.TrimSpace(params.Token)
	params.Owner = strings.TrimSpace(params.Owner)
	params.Repo = strings.TrimSpace(params.Repo)
	params.Branch = strings.TrimSpace(params.Branch)
	params.Path = strings.Trim(strings.TrimSpace(params.Path), "/")
	params.Message = strings.TrimSpace(params.Message)
	if params.Token == "" || params.Owner == "" || params.Repo == "" || params.Path == "" || strings.TrimSpace(params.Content) == "" {
		return "", fmt.Errorf("token、仓库、路径和内容不能为空")
	}
	if params.Branch == "" {
		params.Branch = "main"
	}
	if params.Message == "" {
		params.Message = "update cfdata results"
	}

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", url.PathEscape(params.Owner), url.PathEscape(params.Repo), escapeGitHubContentPath(params.Path))
	sha, err := getGitHubContentSHA(ctx, apiURL, params.Token, params.Branch)
	if err != nil {
		return "", err
	}
	payload := map[string]string{
		"message": params.Message,
		"content": base64.StdEncoding.EncodeToString([]byte(params.Content)),
		"branch":  params.Branch,
	}
	if sha != "" {
		payload["sha"] = sha
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, apiURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	setGitHubHeaders(req, params.Token)
	resp, err := upstreamHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("GitHub API 返回 %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	io.Copy(io.Discard, resp.Body)
	return githubRawURL(params), nil
}

func githubRawURL(params githubUploadRequest) string {
	branch := strings.TrimSpace(params.Branch)
	if branch == "" {
		branch = "main"
	}
	path := strings.Trim(strings.TrimSpace(params.Path), "/")
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/refs/heads/%s/%s", url.PathEscape(strings.TrimSpace(params.Owner)), url.PathEscape(strings.TrimSpace(params.Repo)), url.PathEscape(branch), escapeGitHubContentPath(path))
}

func getGitHubContentSHA(ctx context.Context, apiURL, token, branch string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"?ref="+url.QueryEscape(branch), nil)
	if err != nil {
		return "", err
	}
	setGitHubHeaders(req, token)
	resp, err := upstreamHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("查询 GitHub 文件失败 %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var payload struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return payload.SHA, nil
}

func setGitHubHeaders(req *http.Request, token string) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cfdata")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

func escapeGitHubContentPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}
