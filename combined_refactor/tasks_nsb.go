package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type nsbFailureRecord struct {
	index  int
	ipAddr string
	port   string
	phase  string
	reason string
	detail string
}

func scanNSBEntry(ctx context.Context, item string, fallbackPort int, enableTLS bool, delay int, targetDC string, inputIndex int) (*iptestResult, *nsbFailureRecord) {
	parts := strings.Fields(item)
	if len(parts) < 1 || len(parts) > 2 {
		record := &nsbFailureRecord{index: inputIndex, phase: "scan", reason: "格式错误", detail: "需要每行格式为: IP [端口]"}
		if len(parts) > 0 {
			record.ipAddr = parts[0]
		}
		if len(parts) > 1 {
			record.port = parts[1]
		}
		return nil, record
	}
	ipAddr := parts[0]
	portStr := strconv.Itoa(fallbackPort)
	if len(parts) == 2 {
		portStr = parts[1]
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "端口无效", detail: err.Error()}
	}
	if port <= 0 {
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "端口无效", detail: "端口必须大于 0"}
	}

	const nsbLatencyAttempts = 3
	successCount := 0
	var totalLatency time.Duration
	var firstConn net.Conn

	for i := 0; i < nsbLatencyAttempts; i++ {
		start := time.Now()
		conn, err := dialContextWithTimeout(ctx, "tcp", net.JoinHostPort(ipAddr, strconv.Itoa(port)), timeout)
		if err != nil {
			continue
		}
		tcpDuration := time.Since(start)
		if delay > 0 && tcpDuration.Milliseconds() > int64(delay) {
			conn.Close()
			continue
		}
		successCount++
		totalLatency += tcpDuration
		if firstConn == nil {
			firstConn = conn
		} else {
			conn.Close()
		}
	}
	if successCount == 0 {
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "TCP连接失败", detail: fmt.Sprintf("%d次连接均失败或超过延迟阈值", nsbLatencyAttempts)}
	}
	conn := firstConn
	tcpDuration := totalLatency / time.Duration(successCount)
	lossRate := float64(nsbLatencyAttempts-successCount) / float64(nsbLatencyAttempts)

	connClosed := false
	closeConn := func() {
		if !connClosed {
			connClosed = true
			conn.Close()
		}
	}
	defer closeConn()

	protocol := "http://"
	if enableTLS {
		protocol = "https://"
	}

	start := time.Now()
	httpCtx, httpCancel := context.WithTimeout(ctx, maxDuration)
	defer httpCancel()
	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return conn, nil
		},
		TLSClientConfig: tlsConfigWithRootCAs("speed.cloudflare.com"),
	}
	client := http.Client{
		Transport: wrapDebugTransport("nsb-trace", transport),
	}
	req, err := http.NewRequestWithContext(httpCtx, "GET", protocol+requestURL, nil)
	if err != nil {
		closeConn()
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "构建请求失败", detail: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "Trace请求失败", detail: err.Error()}
	}
	duration := time.Since(start)
	if duration > maxDuration {
		resp.Body.Close()
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "Trace请求超时", detail: fmt.Sprintf("duration=%dms, max=%dms", duration.Milliseconds(), maxDuration.Milliseconds())}
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		errorBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, &nsbFailureRecord{
			index:  inputIndex,
			ipAddr: ipAddr,
			port:   portStr,
			phase:  "scan",
			reason: "HTTP状态异常",
			detail: formatHTTPFailureDetail(resp.Status, errorBody),
		}
	}

	bodyData, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if err != nil {
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "读取响应失败", detail: err.Error()}
	}

	trace := parseTraceResponse(string(bodyData))
	dataCenter := trace["colo"]
	locCode := trace["loc"]
	if dataCenter == "" {
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "Trace校验失败", detail: "trace 中未返回 colo 字段"}
	}
	if strings.TrimSpace(targetDC) != "" && !strings.EqualFold(dataCenter, strings.TrimSpace(targetDC)) {
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "数据中心不匹配", detail: fmt.Sprintf("colo=%s, target=%s", dataCenter, targetDC)}
	}

	loc := locationMap[dataCenter]
	asnNumber, asnOrg := lookupASN(trace["ip"])
	return &iptestResult{
		ipAddr:      ipAddr,
		port:        port,
		dataCenter:  dataCenter,
		locCode:     locCode,
		region:      loc.Region,
		city:        loc.City,
		latency:     fmt.Sprintf("%dms", tcpDuration.Milliseconds()),
		lossRate:    lossRate,
		tcpDuration: tcpDuration,
		outboundIP:  trace["ip"],
		ipType:      getIPType(trace["ip"]),
		asnNumber:   asnNumber,
		asnOrg:      asnOrg,
		visitScheme: trace["visit_scheme"],
		tlsVersion:  trace["tls"],
		sni:         trace["sni"],
		httpVersion: trace["http"],
		warp:        trace["warp"],
		gateway:     trace["gateway"],
		rbi:         trace["rbi"],
		kex:         trace["kex"],
		timestamp:   trace["ts"],
	}, nil
}

func sortNSBResults(results []iptestResult, speedTest int) {
	if speedTest > 0 {
		sort.Slice(results, func(i, j int) bool {
			if results[i].speedQualified != results[j].speedQualified {
				return results[i].speedQualified
			}
			if results[i].lossRate != results[j].lossRate {
				return results[i].lossRate < results[j].lossRate
			}
			if results[i].speedTested != results[j].speedTested {
				return results[i].speedTested
			}
			if results[i].speedQualified && results[i].downloadSpeed != results[j].downloadSpeed {
				return results[i].downloadSpeed > results[j].downloadSpeed
			}
			return results[i].tcpDuration < results[j].tcpDuration
		})
		return
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].lossRate != results[j].lossRate {
			return results[i].lossRate < results[j].lossRate
		}
		return results[i].tcpDuration < results[j].tcpDuration
	})
}

func runNSBScanWorkers(ctx context.Context, total, maxWorkers, resultLimit int, onProgress func(current int), work func(idx int) int) bool {
	if total == 0 {
		return false
	}
	if maxWorkers <= 0 {
		maxWorkers = 1
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	inFlight := 0
	wasCanceled := false
	completion := make(chan int, maxWorkers)

	worker := func() {
		defer wg.Done()
		for idx := range jobs {
			select {
			case <-ctx.Done():
				return
			default:
			}
			acceptedTotal := work(idx)
			select {
			case completion <- acceptedTotal:
			case <-ctx.Done():
				return
			}
		}
	}

	workers := min(maxWorkers, total)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	next := 0
	for next < total {
		if wasCanceled {
			break
		}
		mu.Lock()
		shouldStop := resultLimit > 0 && accepted >= resultLimit
		mu.Unlock()
		if shouldStop {
			break
		}
		select {
		case <-ctx.Done():
			wasCanceled = true
			next = total
		case acceptedTotal := <-completion:
			mu.Lock()
			inFlight--
			if acceptedTotal > accepted {
				accepted = acceptedTotal
			}
			currentAccepted := accepted
			mu.Unlock()
			if onProgress != nil {
				onProgress(currentAccepted)
			}
		case jobs <- next:
			mu.Lock()
			inFlight++
			mu.Unlock()
			next++
		}
	}
	close(jobs)
	if wasCanceled {
		return true
	}
	for {
		mu.Lock()
		remaining := inFlight
		mu.Unlock()
		if remaining <= 0 {
			break
		}
		var acceptedTotal int
		select {
		case <-ctx.Done():
			return true
		case acceptedTotal = <-completion:
		}
		mu.Lock()
		inFlight--
		if acceptedTotal > accepted {
			accepted = acceptedTotal
		}
		currentAccepted := accepted
		mu.Unlock()
		if onProgress != nil {
			onProgress(currentAccepted)
		}
	}
	return wasCanceled
}

func runNSBDownloadSpeed(ctx context.Context, ip string, port int, enableTLS bool, testURL string) (float64, string) {
	const speedWindow = 10 * time.Second
	const speedMaxBytes = 200 * 1024 * 1024

	scheme := "http"
	if enableTLS {
		scheme = "https"
	}

	parsedURL, err := parseSpeedTestURL(testURL, scheme)
	if err != nil {
		return 0, "测速地址解析失败: " + err.Error()
	}

	transport := &http.Transport{
		DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
			return dialContextWithTimeout(c, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 5*time.Second)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfigWithRootCAs(parsedURL.Hostname()),
		DisableCompression:  true,
	}
	client := http.Client{
		Transport: wrapDebugTransport("nsb-speed", transport),
		Timeout:   speedWindow + 5*time.Second,
	}

	speedCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(speedCtx, "GET", parsedURL.String(), nil)
	if err != nil {
		return 0, "测速请求构建失败: " + err.Error()
	}
	req.Host = parsedURL.Host
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept-Encoding", "identity")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, "测速请求失败: " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return 0, formatSpeedHTTPFailure(resp.StatusCode)
	}

	buf := make([]byte, 32*1024)
	type readChunk struct {
		n   int
		err error
	}
	chunks := make(chan readChunk, 16)
	readerDone := make(chan struct{})
	safeGo("nsb-speed-reader", nil, func() {
		defer close(readerDone)
		for {
			n, err := resp.Body.Read(buf)
			select {
			case chunks <- readChunk{n: n, err: err}:
			case <-speedCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	})

	windowTimer := time.NewTimer(speedWindow)
	defer windowTimer.Stop()

	var written int64
	for {
		select {
		case <-ctx.Done():
			cancel()
			resp.Body.Close()
			<-readerDone
			return 0, "测速任务已终止"
		case <-windowTimer.C:
			cancel()
			resp.Body.Close()
			<-readerDone
			goto done
		case chunk := <-chunks:
			if chunk.n > 0 {
				written += int64(chunk.n)
				if written >= speedMaxBytes {
					cancel()
					resp.Body.Close()
					<-readerDone
					goto done
				}
			}
			if chunk.err != nil {
				if chunk.err != io.EOF {
					cancel()
					resp.Body.Close()
					<-readerDone
					return 0, "测速下载失败: " + chunk.err.Error()
				}
				cancel()
				resp.Body.Close()
				<-readerDone
				goto done
			}
		}
	}

done:
	duration := time.Since(start)
	if duration <= 0 {
		return 0, "测速耗时异常: duration<=0"
	}

	return float64(written) / duration.Seconds() / 1024, ""
}

func runNSBTask(ctx context.Context, session *appSession, fileName, fileContent, outFile string, maxThreads, fallbackPort, speedTest int, speedURL string, enableTLS bool, delay int, resultLimit int, targetDC string, speedMin float64, speedLimit int, compact bool) {
	session.sendWSMessage("log", fmt.Sprintf("开始非标优选：%s", fileName))

	tmpFile, err := os.CreateTemp("", "cfdata-nsb-*.txt")
	if err != nil {
		session.sendWSMessage("error", "无法创建临时文件: "+err.Error())
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.WriteString(tmpFile, fileContent); err != nil {
		tmpFile.Close()
		session.sendWSMessage("error", "写入临时文件失败: "+err.Error())
		return
	}
	if err := tmpFile.Close(); err != nil {
		session.sendWSMessage("error", "关闭临时文件失败: "+err.Error())
		return
	}

	if fallbackPort <= 0 {
		session.sendWSMessage("error", "备用端口必须为 1-65535")
		return
	}
	ips, err := readIPsWithFallbackPort(tmpPath, fallbackPort)
	if err != nil {
		session.sendWSMessage("error", "解析上传文件失败: "+err.Error())
		return
	}
	if len(ips) == 0 {
		session.sendWSMessage("error", "上传文件中未找到有效的 ip 端口行")
		return
	}
	if resultLimit <= 0 {
		session.sendWSMessage("error", "延迟结果上限必须是非 0 正整数")
		return
	}
	if resultLimit > 0 {
		session.sendWSMessage("log", fmt.Sprintf("开始扫描：%d 条记录，目标上限=%d", len(ips), resultLimit))
	} else {
		session.sendWSMessage("log", fmt.Sprintf("开始扫描：%d 条记录", len(ips)))
	}

	nsbResults := make([]iptestResult, 0, len(ips))
	resMutex := &sync.Mutex{}
	var failures []nsbFailureRecord
	var failMutex sync.Mutex
	if debugMode {
		failures = make([]nsbFailureRecord, 0, len(ips))
		defer func() {
			for _, failure := range sortedNSBFailures(failures) {
				recordAllDebugError("nsb_failure", fmt.Sprintf("ip=%s port=%s phase=%s reason=%s detail=%s", failure.ipAddr, failure.port, failure.phase, failure.reason, failure.detail))
			}
		}()
	}

	total := len(ips)
	if resultLimit > 0 && resultLimit < total {
		total = resultLimit
	}
	reportNSBProgress(session, "scan", 0, total, "扫描中")
	wasCanceled := runNSBScanWorkers(ctx, len(ips), maxThreads, resultLimit, func(current int) {
		reportNSBProgress(session, "scan", min(current, total), total, "扫描中")
	}, func(idx int) int {
		itemCtx, itemCancel := context.WithTimeout(ctx, 10*time.Second)
		defer itemCancel()

		select {
		case <-itemCtx.Done():
			return 0
		default:
		}

		item := ips[idx]
		res, failure := scanNSBEntry(itemCtx, item, fallbackPort, enableTLS, delay, targetDC, idx)
		if debugMode && failure != nil {
			failMutex.Lock()
			failures = append(failures, *failure)
			failMutex.Unlock()
		}
		if res == nil {
			return 0
		}

		resMutex.Lock()
		nsbResults = append(nsbResults, *res)
		accepted := len(nsbResults)
		resMutex.Unlock()
		session.sendWSMessage("nsb_scan_result", res.toNSBLiveMessage("", compact))
		return accepted
	})

	if wasCanceled || ctx.Err() != nil {
		session.sendWSMessage("log", "非标优选延迟扫描已终止，正在整理已扫描到的数据...")
	}

	if len(nsbResults) == 0 {
		if wasCanceled || ctx.Err() != nil {
			session.sendWSMessage("log", "非标优选延迟扫描已终止，当前没有可整理的有效 IP。")
			return
		}
		session.sendWSMessage("error", "未发现有效 IP")
		return
	}

	sortNSBResults(nsbResults, 0)
	if resultLimit > 0 && len(nsbResults) > resultLimit {
		nsbResults = nsbResults[:resultLimit]
	}
	sortedScanRows := make([]nsbScanMessage, 0, len(nsbResults))
	for i := range nsbResults {
		sortedScanRows = append(sortedScanRows, nsbResults[i].toNSBLiveMessage("", compact))
	}
	session.sendWSMessage("nsb_scan_sorted", sortedScanRows)

	completionStatus := "complete"
	completionMessage := "测试完成"
	qualifiedCount := 0
	if (wasCanceled || ctx.Err() != nil) && speedTest > 0 && speedLimit > 0 {
		completionStatus = "partial"
		completionMessage = "任务已手动终止，已整理当前扫描结果"
	}
	if !wasCanceled && ctx.Err() == nil && speedTest > 0 && speedLimit > 0 {
		session.sendWSMessage("log", fmt.Sprintf("开始测速：%d 条记录，线程数=%d，目标上限=%d，测速阈值=%.2fMB/s", len(nsbResults), speedTest, speedLimit, speedMin))

		reportNSBProgress(session, "speed", 0, speedLimit, "测速中")
		speedCanceled := runNSBSpeedWorkers(ctx, nsbResults, speedTest, speedLimit, speedMin, func(tested, qualified int) {
			reportNSBProgress(session, "speed", min(qualified, speedLimit), speedLimit, "测速中")
		}, func(idx int, speedErr string) {
			res := &nsbResults[idx]
			session.sendWSMessage("nsb_scan_result", res.toNSBLiveMessage(res.speedText, compact))
			if debugMode && speedErr != "" {
				failMutex.Lock()
				failures = append(failures, nsbFailureRecord{
					index:  idx,
					ipAddr: res.ipAddr,
					port:   strconv.Itoa(res.port),
					phase:  "speed",
					reason: "测速失败",
					detail: speedErr,
				})
				failMutex.Unlock()
			}
		}, func(idx int) (float64, string) {
			res := &nsbResults[idx]
			return runNSBDownloadSpeed(ctx, res.ipAddr, res.port, enableTLS, speedURL)
		})
		if speedCanceled {
			wasCanceled = true
		}
		for i := range nsbResults {
			if nsbResults[i].speedTested && nsbResults[i].speedText == "" {
				nsbResults[i].speedText = fmt.Sprintf("%.2fMB/s", nsbResults[i].downloadSpeed/1024)
			}
			if nsbResults[i].speedTested && nsbResults[i].downloadSpeed/1024 >= speedMin {
				nsbResults[i].speedQualified = true
				qualifiedCount++
			}
		}
		sortNSBResults(nsbResults, speedTest)
		if qualifiedCount == 0 {
			completionStatus = "failed"
			completionMessage = "未找到符合要求的结果"
		} else if speedLimit > 0 && qualifiedCount < speedLimit {
			completionStatus = "partial"
			completionMessage = "测试完成，未能完成任务需求结果"
		}
	}

	if wasCanceled || ctx.Err() != nil {
		session.sendWSMessage("log", "非标测速任务已终止，正在整理当前可用测速结果...")
		completionStatus = "partial"
		completionMessage = "任务已手动终止，已整理当前可用结果"
	}

	if err := writeNSBCSV(outFile, nsbResults, speedTest, compact); err != nil {
		session.sendWSMessage("error", "导出 CSV 失败: "+err.Error())
		return
	}

	headers, rows, err := parseCSVFile(outFile)
	if err != nil {
		session.sendWSMessage("error", "读取导出 CSV 失败: "+err.Error())
		return
	}

	session.sendWSMessage("nsb_csv_complete", nsbCSVCompletePayload{Headers: headers, Rows: rows, File: outFile, Status: completionStatus, Message: completionMessage, QualifiedCount: qualifiedCount})
	session.sendWSMessage("log", fmt.Sprintf("非标优选完成，结果文件: %s", outFile))
}

func runNSBSpeedBatch(ctx context.Context, session *appSession, rows []nsbScanMessage, maxWorkers int, speedURL string, enableTLS bool, speedMin float64, speedLimit int, skipTested bool, compact bool) {
	if speedLimit <= 0 {
		session.sendWSMessage("log", "非标批量测速已关闭（测速上限 0）")
		session.sendWSMessage("nsb_speed_complete", map[string]interface{}{"qualified": 0, "limit": speedLimit})
		return
	}
	if speedMin <= 0 {
		speedMin = 0.1
	}
	if maxWorkers <= 0 {
		maxWorkers = 1
	}

	results := make([]iptestResult, 0, len(rows))
	for _, row := range rows {
		res, ok := nsbMessageToResult(row)
		if !ok {
			continue
		}
		status := getNSBSpeedStatus(res.speedText, speedMin)
		if skipTested && status != "untested" {
			continue
		}
		results = append(results, res)
	}

	if len(results) == 0 {
		if skipTested {
			session.sendWSMessage("log", "没有未测速的非标结果，跳过继续测速")
		} else {
			session.sendWSMessage("log", "没有可测速的非标结果")
		}
		session.sendWSMessage("nsb_speed_complete", map[string]interface{}{"qualified": 0, "limit": speedLimit})
		return
	}

	session.sendWSMessage("log", fmt.Sprintf("开始非标测速：%d 条记录，线程数=%d，目标上限=%d，测速阈值=%.2fMB/s", len(results), maxWorkers, speedLimit, speedMin))
	reportNSBProgress(session, "speed", 0, speedLimit, "测速中")
	speedCanceled := runNSBSpeedWorkers(ctx, results, maxWorkers, speedLimit, speedMin, func(tested, qualified int) {
		reportNSBProgress(session, "speed", qualified, speedLimit, "测速中")
	}, func(idx int, speedErr string) {
		res := &results[idx]
		session.sendWSMessage("nsb_scan_result", res.toNSBLiveMessage(res.speedText, compact))
	}, func(idx int) (float64, string) {
		res := &results[idx]
		return runNSBDownloadSpeed(ctx, res.ipAddr, res.port, enableTLS, speedURL)
	})

	qualifiedCount := 0
	for i := range results {
		if results[i].speedTested && results[i].speedText == "" {
			results[i].speedText = fmt.Sprintf("%.2fMB/s", results[i].downloadSpeed/1024)
		}
		if results[i].speedTested && results[i].downloadSpeed/1024 >= speedMin {
			results[i].speedQualified = true
			qualifiedCount++
		}
	}
	if speedCanceled || ctx.Err() != nil {
		session.sendWSMessage("log", "非标批量测速已终止")
		return
	}
	totalQualified := countNSBTotalQualified(rows, results, speedMin)
	session.sendWSMessage("log", fmt.Sprintf("非标批量测速完成，达标 %d/%d，总达标 %d", qualifiedCount, speedLimit, totalQualified))
	session.sendWSMessage("nsb_speed_complete", map[string]interface{}{"qualified": qualifiedCount, "totalQualified": totalQualified, "limit": speedLimit})
}

func countNSBTotalQualified(rows []nsbScanMessage, updated []iptestResult, speedMin float64) int {
	updatedSpeed := make(map[string]string, len(updated))
	for _, result := range updated {
		updatedSpeed[result.ipAddr+":"+strconv.Itoa(result.port)] = result.speedText
	}
	count := 0
	for _, row := range rows {
		key := strings.TrimSpace(row.IP) + ":" + strings.TrimSpace(row.Port)
		speedText := row.Speed
		if speed, ok := updatedSpeed[key]; ok {
			speedText = speed
		}
		if getNSBSpeedStatus(speedText, speedMin) == "qualified" {
			count++
		}
	}
	return count
}

func nsbMessageToResult(row nsbScanMessage) (iptestResult, bool) {
	port, err := strconv.Atoi(strings.TrimSpace(row.Port))
	if err != nil || port <= 0 || strings.TrimSpace(row.IP) == "" {
		return iptestResult{}, false
	}
	return iptestResult{
		ipAddr:      strings.TrimSpace(row.IP),
		port:        port,
		dataCenter:  row.DC,
		locCode:     row.Loc,
		region:      row.Region,
		city:        row.City,
		latency:     row.Latency,
		lossRate:    parsePercent(row.LossRate),
		outboundIP:  row.OutboundIP,
		ipType:      row.IPType,
		asnNumber:   row.ASNNumber,
		asnOrg:      row.ASNOrg,
		visitScheme: firstNonEmpty(row.VisitScheme, mapBoolTLS(row.TLS)),
		tlsVersion:  row.TLSVersion,
		sni:         row.SNI,
		httpVersion: row.HTTPVersion,
		warp:        row.Warp,
		gateway:     row.Gateway,
		rbi:         row.RBI,
		kex:         row.Kex,
		timestamp:   row.Timestamp,
		speedText:   row.Speed,
	}, true
}

func parsePercent(value string) float64 {
	percent, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(value), "%"), 64)
	if err != nil {
		return 0
	}
	return percent / 100
}

func mapBoolTLS(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "true") {
		return "https"
	}
	return "http"
}

func getNSBSpeedStatus(value string, speedMin float64) string {
	text := strings.TrimSpace(value)
	if text == "" || text == "-" || text == "未测速" {
		return "untested"
	}
	if strings.Contains(text, "MB/s") {
		speed, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(text, "MB/s")), "MB/s"), 64)
		if err == nil && speed >= speedMin {
			return "qualified"
		}
	}
	return "unqualified"
}

func runNSBSpeedWorkers(ctx context.Context, results []iptestResult, maxWorkers, targetQualified int, speedMin float64, onProgress func(tested, qualified int), onResult func(idx int, speedErr string), work func(idx int) (float64, string)) bool {
	if len(results) == 0 {
		return false
	}
	if maxWorkers <= 0 {
		maxWorkers = 1
	}
	if targetQualified <= 0 {
		return false
	}

	type speedDone struct {
		idx int
		err string
	}
	jobs := make(chan int)
	done := make(chan speedDone, maxWorkers)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for idx := range jobs {
			select {
			case <-ctx.Done():
				return
			default:
			}
			speed, speedErr := work(idx)
			select {
			case <-ctx.Done():
				return
			default:
			}
			results[idx].downloadSpeed = speed
			results[idx].speedTested = true
			if speedErr != "" {
				results[idx].speedText = "测速失败"
			} else {
				results[idx].speedText = fmt.Sprintf("%.2fMB/s", speed/1024)
				results[idx].speedQualified = speed/1024 >= speedMin
			}
			select {
			case done <- speedDone{idx: idx, err: speedErr}:
			case <-ctx.Done():
				return
			}
		}
	}

	workers := min(maxWorkers, len(results))
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	next := 0
	inFlight := 0
	completed := 0
	qualified := 0
	wasCanceled := false
	shouldSend := func() bool {
		return next < len(results) && qualified+inFlight < targetQualified
	}

	for shouldSend() || inFlight > 0 {
		var jobCh chan int
		if shouldSend() {
			jobCh = jobs
		}
		select {
		case <-ctx.Done():
			wasCanceled = true
			next = len(results)
			close(jobs)
			return true
		case item := <-done:
			inFlight--
			completed++
			if results[item.idx].speedQualified {
				qualified++
			}
			if onResult != nil {
				onResult(item.idx, item.err)
			}
			if onProgress != nil {
				onProgress(completed, qualified)
			}
		case jobCh <- next:
			next++
			inFlight++
		}
	}
	close(jobs)
	wg.Wait()
	return wasCanceled
}

func writeNSBCSV(outFile string, results []iptestResult, speedTest int, compact bool) error {
	outFile = safeFilename(outFile)
	file, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := writeUTF8BOM(file); err != nil {
		os.Remove(outFile)
		return err
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write(nsbCSVHeaders(compact)); err != nil {
		return err
	}

	for _, res := range results {
		if err := writer.Write(nsbCSVRow(res, speedTest > 0, compact)); err != nil {
			return err
		}
	}

	return nil
}

func nsbCSVHeaders(compact bool) []string {
	if compact {
		return []string{"IP地址", "端口号", "TLS", "丢包率", "网络延迟", "下载速度", "出站IP", "IP类型", "数据中心", "源IP位置", "地区", "城市", "ASN号码", "ASN组织"}
	}
	headers := []string{"IP地址", "端口号", "TLS", "丢包率", "网络延迟", "下载速度", "出站IP", "IP类型", "数据中心", "源IP位置", "地区", "城市", "ASN号码", "ASN组织"}
	headers = append(headers, "访问协议", "TLS版本", "SNI", "HTTP版本", "WARP", "Gateway", "RBI", "密钥交换", "时间戳")
	return headers
}

func nsbCSVRow(res iptestResult, includeSpeed bool, compact bool) []string {
	speed := "-"
	if includeSpeed {
		speed = res.speedText
		if strings.TrimSpace(speed) == "" {
			if res.speedTested {
				speed = fmt.Sprintf("%.2fMB/s", res.downloadSpeed/1024)
			} else {
				speed = "未测速"
			}
		}
	}
	if compact {
		return []string{
			res.ipAddr,
			strconv.Itoa(res.port),
			strconv.FormatBool(res.visitScheme == "https"),
			fmt.Sprintf("%.0f%%", res.lossRate*100),
			res.latency,
			speed,
			res.outboundIP,
			res.ipType,
			res.dataCenter,
			res.locCode,
			res.region,
			res.city,
			fallbackDash(res.asnNumber),
			fallbackDash(res.asnOrg),
		}
	}
	row := []string{
		res.ipAddr,
		strconv.Itoa(res.port),
		strconv.FormatBool(res.visitScheme == "https"),
		fmt.Sprintf("%.0f%%", res.lossRate*100),
		res.latency,
		speed,
		res.outboundIP,
		res.ipType,
		res.dataCenter,
		res.locCode,
		res.region,
		res.city,
		fallbackDash(res.asnNumber),
		fallbackDash(res.asnOrg),
	}
	row = append(row,
		res.visitScheme,
		res.tlsVersion,
		res.sni,
		res.httpVersion,
		res.warp,
		res.gateway,
		res.rbi,
		res.kex,
		res.timestamp,
	)
	return row
}

func fallbackDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func sortedNSBFailures(failures []nsbFailureRecord) []nsbFailureRecord {
	next := append([]nsbFailureRecord(nil), failures...)
	sort.SliceStable(next, func(i, j int) bool {
		if next[i].index == next[j].index {
			return next[i].phase < next[j].phase
		}
		return next[i].index < next[j].index
	})
	return next
}

func formatHTTPFailureDetail(status string, body []byte) string {
	bodyText := sanitizeErrorText(string(body), 500)
	if bodyText == "" {
		return status
	}
	return status + " | 响应: " + bodyText
}

func sanitizeErrorText(text string, maxLen int) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.Join(strings.Fields(text), " ")
	if maxLen > 0 && len(text) > maxLen {
		return text[:maxLen] + "..."
	}
	return text
}
