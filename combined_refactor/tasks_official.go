package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func scanOfficialIP(ctx context.Context, ip string, port int, delay int) (*ScanResult, string, string) {
	dialer := &net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, "tcp_connect_failed", err.Error()
	}

	if delay > 0 && time.Since(start).Milliseconds() > int64(delay) {
		conn.Close()
		return nil, "delay_exceeded", fmt.Sprintf("connect=%dms, delay=%dms", time.Since(start).Milliseconds(), delay)
	}

	connClosed := false
	closeConn := func() {
		if !connClosed {
			connClosed = true
			conn.Close()
		}
	}
	defer closeConn()

	tcpDuration := time.Since(start)
	scheme := "http://"
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	if isTLSPort(port) {
		scheme = "https://"
		transport.TLSClientConfig = tlsConfigWithRootCAs("speed.cloudflare.com")
	}

	client := http.Client{
		Transport: wrapDebugTransport("official-trace", transport),
		Timeout:   3 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", scheme+requestURL, nil)
	if err != nil {
		return nil, "request_create_failed", err.Error()
	}
	req.Host = "speed.cloudflare.com"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		return nil, "trace_request_failed", err.Error()
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if err != nil {
		return nil, "trace_read_failed", err.Error()
	}
	bodyStr := string(bodyBytes)
	trace := parseTraceResponse(bodyStr)
	dataCenter := strings.TrimSpace(trace["colo"])
	if dataCenter == "" {
		if debugMode {
			sendLog(fmt.Sprintf("[official-scan-debug] trace missing colo: ip=%s port=%d body=%q", ip, port, strings.TrimSpace(bodyStr)))
		}
		return nil, "trace_missing_colo", strings.TrimSpace(bodyStr)
	}

	loc := locationMap[dataCenter]
	res := &ScanResult{
		IP:          ip,
		Port:        port,
		DataCenter:  dataCenter,
		DCCountry:   loc.Cca2,
		Region:      loc.Region,
		City:        loc.City,
		LatencyStr:  fmt.Sprintf("%dms", tcpDuration.Milliseconds()),
		TCPDuration: tcpDuration,
	}
	return res, "", ""
}

func scanOfficialHTTP(ctx context.Context, ip string, port int, delay int) (*ScanResult, string, string) {
	mul := latencyMultiplier(scanModeHTTPing, isTLSPort(port))
	effectiveDelay := int(float64(delay) * mul)

	dialer := &net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, "tcp_connect_failed", err.Error()
	}
	if delay > 0 {
		if time.Since(start).Milliseconds() > int64(effectiveDelay) {
			conn.Close()
			return nil, "delay_exceeded", fmt.Sprintf("connect=%dms, effective_delay=%dms", time.Since(start).Milliseconds(), effectiveDelay)
		}
	}

	connClosed := false
	closeConn := func() {
		if !connClosed {
			connClosed = true
			conn.Close()
		}
	}
	defer closeConn()

	scheme := "http://"
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	if isTLSPort(port) {
		scheme = "https://"
		transport.TLSClientConfig = tlsConfigWithRootCAs("speed.cloudflare.com")
	}

	client := http.Client{
		Transport: wrapDebugTransport("official-httping", transport),
		Timeout:   3 * time.Second,
	}

	reqStart := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", scheme+requestURL, nil)
	if err != nil {
		return nil, "request_create_failed", err.Error()
	}
	req.Host = "speed.cloudflare.com"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		return nil, "http_get_failed", err.Error()
	}
	reqDuration := time.Since(reqStart)

	if delay > 0 && reqDuration.Milliseconds() > int64(effectiveDelay) {
		resp.Body.Close()
		return nil, "delay_exceeded", fmt.Sprintf("ttfb=%dms, effective_delay=%dms", reqDuration.Milliseconds(), effectiveDelay)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if err != nil {
		return nil, "trace_read_failed", err.Error()
	}
	bodyStr := string(bodyBytes)
	trace := parseTraceResponse(bodyStr)
	dataCenter := strings.TrimSpace(trace["colo"])
	if dataCenter == "" {
		if debugMode {
			sendLog(fmt.Sprintf("[official-httping-debug] trace missing colo: ip=%s port=%d body=%q", ip, port, strings.TrimSpace(bodyStr)))
		}
		return nil, "trace_missing_colo", strings.TrimSpace(bodyStr)
	}

	loc := locationMap[dataCenter]
	res := &ScanResult{
		IP:          ip,
		Port:        port,
		DataCenter:  dataCenter,
		DCCountry:   loc.Cca2,
		Region:      loc.Region,
		City:        loc.City,
		LatencyStr:  fmt.Sprintf("%dms", reqDuration.Milliseconds()),
		TCPDuration: reqDuration,
	}
	return res, "", ""
}

func testIPLatency(ctx context.Context, ip string, port int, delay int, scanMode string) (*TestResult, string, string) {
	isHTTPing := scanMode == scanModeHTTPing
	mul := 1.0
	if isHTTPing {
		mul = latencyMultiplier(scanModeHTTPing, isTLSPort(port))
	}
	effectiveDelay := int(float64(delay) * mul)
	dialerTimeout := time.Duration(delay) * time.Millisecond
	if delay <= 0 {
		dialerTimeout = 3 * time.Second
	}
	dialer := &net.Dialer{Timeout: dialerTimeout}
	successCount := 0
	failureCount := 0
	lastFailure := ""
	var totalLatency time.Duration
	minLatency := time.Duration(1<<63 - 1)
	maxLatency := time.Duration(0)

	for i := 0; i < 10; i++ {
		select {
		case <-ctx.Done():
			return nil, "test_canceled", ctx.Err().Error()
		default:
		}

		var latency time.Duration
		if isHTTPing {
			latency, lastFailure = measureHTTPTTFB(ctx, ip, port, effectiveDelay)
			if latency < 0 {
				failureCount++
				continue
			}
		} else {
			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			if err != nil {
				failureCount++
				lastFailure = err.Error()
				continue
			}
			latency = time.Since(start)
			if delay > 0 && latency > time.Duration(delay)*time.Millisecond {
				conn.Close()
				failureCount++
				lastFailure = fmt.Sprintf("latency %s exceeds delay %dms", latency, delay)
				continue
			}
			conn.Close()
		}
		successCount++
		totalLatency += latency
		if latency < minLatency {
			minLatency = latency
		}
		if latency > maxLatency {
			maxLatency = latency
		}
	}

	if successCount == 0 {
		if lastFailure == "" {
			lastFailure = fmt.Sprintf("all %d attempts failed", failureCount)
		}
		return nil, "latency_test_failed", lastFailure
	}

	avgLatency := totalLatency / time.Duration(successCount)
	lossRate := float64(10-successCount) / 10.0
	return &TestResult{
		IP:         ip,
		Port:       port,
		MinLatency: minLatency,
		MaxLatency: maxLatency,
		AvgLatency: avgLatency,
		LossRate:   lossRate,
	}, "", ""
}

func measureHTTPTTFB(ctx context.Context, ip string, port int, effectiveDelay int) (time.Duration, string) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return -1, err.Error()
	}
	defer conn.Close()

	scheme := "http://"
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	if isTLSPort(port) {
		scheme = "https://"
		transport.TLSClientConfig = tlsConfigWithRootCAs("speed.cloudflare.com")
	}
	client := http.Client{
		Transport: wrapDebugTransport("official-httping-test", transport),
		Timeout:   time.Duration(effectiveDelay)*time.Millisecond + time.Second,
	}
	reqStart := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", scheme+requestURL, nil)
	if err != nil {
		return -1, "request_create_failed"
	}
	req.Host = "speed.cloudflare.com"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		return -1, "http_get_failed: " + err.Error()
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	ttfb := time.Since(reqStart)
	if effectiveDelay > 0 && ttfb.Milliseconds() > int64(effectiveDelay) {
		return -1, fmt.Sprintf("ttfb %s exceeds effective delay %dms", ttfb, effectiveDelay)
	}
	return ttfb, ""
}

func runOfficialTask(ctx context.Context, session *appSession, ipType int, scanMaxThreads int, port int, delay int, scanMode string) {
	filename := "ips-v4.txt"
	apiURL := "https://www.baipiao.eu.org/cloudflare/ips-v4"
	if ipType == 6 {
		filename = "ips-v6.txt"
		apiURL = "https://www.baipiao.eu.org/cloudflare/ips-v6"
	}

	content, err := getIPListContent(filename, apiURL)
	if err != nil {
		session.sendWSMessage("error", err.Error())
		return
	}

	ipList, err := parseIPList(content)
	if err != nil {
		session.sendWSMessage("error", "解析 IP 列表失败: "+err.Error())
		return
	}
	if ipType == 6 {
		ipList = getRandomIPv6s(ipList)
	} else {
		ipList = getRandomIPv4s(ipList)
	}
	session.sendWSMessage("log", fmt.Sprintf("开始扫描：%d 条记录", len(ipList)))

	session.scanMutex.Lock()
	session.scanResults = []ScanResult{}
	session.scanMutex.Unlock()

	total := len(ipList)
	failureCounts := map[string]int{}
	failureSamples := map[string]string{}
	failureMutex := sync.Mutex{}
	recordFailure := func(category, detail string) {
		if category == "" {
			return
		}
		failureMutex.Lock()
		defer failureMutex.Unlock()
		failureCounts[category]++
		if failureSamples[category] == "" && strings.TrimSpace(detail) != "" {
			failureSamples[category] = detail
		}
	}
	session.sendWSMessage("scan_progress", map[string]interface{}{
		"current": 0,
		"total":   total,
	})
	wasCanceled := runBoundedWorkers(ctx, total, scanMaxThreads, 10, func(current, total int) {
		session.sendWSMessage("scan_progress", map[string]interface{}{
			"current": current,
			"total":   total,
		})
	}, func(idx int) {
		ip := ipList[idx]
		select {
		case <-ctx.Done():
			return
		default:
		}

		var res *ScanResult
		var failureCategory, failureDetail string
		if scanMode == scanModeHTTPing {
			res, failureCategory, failureDetail = scanOfficialHTTP(ctx, ip, port, delay)
		} else {
			res, failureCategory, failureDetail = scanOfficialIP(ctx, ip, port, delay)
		}
		if res == nil {
			recordFailure(failureCategory, failureDetail)
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}

		session.scanMutex.Lock()
		session.scanResults = append(session.scanResults, *res)
		session.scanMutex.Unlock()

		session.sendWSMessage("scan_result", *res)
	})

	if wasCanceled || ctx.Err() != nil {
		session.sendWSMessage("log", "扫描任务已终止，正在整理已扫描到的数据...")
	}

	session.scanMutex.Lock()
	resultsCount := len(session.scanResults)
	session.scanMutex.Unlock()

	if resultsCount == 0 {
		if wasCanceled || ctx.Err() != nil {
			session.sendWSMessage("log", "扫描任务已终止，当前没有可整理的有效 IP。")
			return
		}
		session.sendWSMessage("error", "扫描结束或被终止，但未发现任何有效IP。")
		return
	}

	session.scanMutex.Lock()
	sort.Slice(session.scanResults, func(i, j int) bool {
		return session.scanResults[i].TCPDuration < session.scanResults[j].TCPDuration
	})
	scanCopy := append([]ScanResult(nil), session.scanResults...)
	session.scanMutex.Unlock()

	dcMap := make(map[string]*DataCenterInfo)
	for _, res := range scanCopy {
		if _, ok := dcMap[res.DataCenter]; !ok {
			dcMap[res.DataCenter] = &DataCenterInfo{
				DataCenter: res.DataCenter,
				DCCountry:  res.DCCountry,
				City:       res.City,
				IPCount:    0,
				MinLatency: 999999,
			}
		}
		info := dcMap[res.DataCenter]
		info.IPCount++
		lat := int(res.TCPDuration / time.Millisecond)
		if lat < info.MinLatency {
			info.MinLatency = lat
		}
	}

	var dcList []DataCenterInfo
	for _, info := range dcMap {
		dcList = append(dcList, *info)
	}
	sort.Slice(dcList, func(i, j int) bool {
		return dcList[i].MinLatency < dcList[j].MinLatency
	})

	session.sendWSMessage("scan_complete_wait_dc", dcList)
}

func runDetailedTest(ctx context.Context, session *appSession, selectedDC string, port int, delay int, scanMode string) {
	var testIPList []string
	scanByIP := make(map[string]ScanResult)
	session.scanMutex.Lock()
	for _, res := range session.scanResults {
		if selectedDC == "" || res.DataCenter == selectedDC {
			testIPList = append(testIPList, res.IP)
			scanByIP[res.IP] = res
		}
	}
	session.scanMutex.Unlock()

	if len(testIPList) == 0 {
		if strings.TrimSpace(selectedDC) == "" {
			session.sendWSMessage("error", "没有找到可测试的 IP 地址")
		} else {
			session.sendWSMessage("error", fmt.Sprintf("数据中心 %s 未找到可测试的 IP 地址", selectedDC))
		}
		return
	}

	session.sendWSMessage("log", fmt.Sprintf("开始测试：%s，%d 个 IP", selectedDC, len(testIPList)))

	var results []TestResult
	var resMutex sync.Mutex
	failureCounts := map[string]int{}
	failureSamples := map[string]string{}
	failureMutex := sync.Mutex{}
	recordFailure := func(category, detail string) {
		if category == "" {
			return
		}
		failureMutex.Lock()
		defer failureMutex.Unlock()
		failureCounts[category]++
		if failureSamples[category] == "" && strings.TrimSpace(detail) != "" {
			failureSamples[category] = detail
		}
	}

	total := len(testIPList)
	session.sendWSMessage("test_progress", map[string]interface{}{
		"current": 0,
		"total":   total,
	})
	wasCanceled := runBoundedWorkers(ctx, total, 50, 5, func(current, total int) {
		session.sendWSMessage("test_progress", map[string]interface{}{
			"current": current,
			"total":   total,
		})
	}, func(idx int) {
		ip := testIPList[idx]
		select {
		case <-ctx.Done():
			return
		default:
		}

		res, failureCategory, failureDetail := testIPLatency(ctx, ip, port, delay, scanMode)
		if res == nil {
			recordFailure(failureCategory, failureDetail)
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		if scan, ok := scanByIP[ip]; ok {
			res.DataCenter = scan.DataCenter
			res.DCCountry = scan.DCCountry
			res.Region = scan.Region
			res.City = scan.City
		}
		session.sendWSMessage("test_result", *res)

		resMutex.Lock()
		results = append(results, *res)
		resMutex.Unlock()
	})

	if wasCanceled || ctx.Err() != nil {
		session.sendWSMessage("log", "详细测试已被终止，正在呈现当前可用测试结果...")
		return
	}
	if len(results) == 0 {
		session.sendWSMessage("error", "详细测试完成，但没有任何 IP 通过延迟测试。")
		return
	}

	sortOfficialTestResults(results)

	session.testMutex.Lock()
	session.testResults = append([]TestResult(nil), results...)
	session.testMutex.Unlock()

	session.sendWSMessage("test_complete", results)
}

func formatFailureSummary(title string, counts map[string]int, samples map[string]string) string {
	if len(counts) == 0 {
		return title + ": 没有记录到失败原因。"
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		sample := strings.TrimSpace(samples[key])
		if len(sample) > 160 {
			sample = sample[:160] + "..."
		}
		if sample != "" {
			parts = append(parts, fmt.Sprintf("%s=%d（示例: %s）", key, counts[key], sample))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return title + ": " + strings.Join(parts, "; ")
}

func sumFailureCounts(counts map[string]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}

func sortOfficialTestResults(results []TestResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].LossRate != results[j].LossRate {
			return results[i].LossRate < results[j].LossRate
		}
		minI := latencyDisplayMilliseconds(results[i].MinLatency)
		minJ := latencyDisplayMilliseconds(results[j].MinLatency)
		if minI != minJ {
			return minI < minJ
		}
		maxI := latencyDisplayMilliseconds(results[i].MaxLatency)
		maxJ := latencyDisplayMilliseconds(results[j].MaxLatency)
		if maxI != maxJ {
			return maxI < maxJ
		}
		avgI := latencyDisplayMilliseconds(results[i].AvgLatency)
		avgJ := latencyDisplayMilliseconds(results[j].AvgLatency)
		if avgI != avgJ {
			return avgI < avgJ
		}
		return results[i].IP < results[j].IP
	})
}

func latencyDisplayMilliseconds(value time.Duration) int64 {
	return int64((value + time.Millisecond/2) / time.Millisecond)
}
