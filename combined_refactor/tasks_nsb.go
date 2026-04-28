package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

func scanNSBEntry(ctx context.Context, item string, enableTLS bool, delay int, inputIndex int) (*iptestResult, *nsbFailureRecord) {
	parts := strings.Fields(item)
	if len(parts) != 2 {
		record := &nsbFailureRecord{index: inputIndex, phase: "scan", reason: "格式错误", detail: "需要每行格式为: IP 空格 端口"}
		if len(parts) > 0 {
			record.ipAddr = parts[0]
		}
		if len(parts) > 1 {
			record.port = parts[1]
		}
		return nil, record
	}
	ipAddr := parts[0]
	portStr := parts[1]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "端口无效", detail: err.Error()}
	}

	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 0}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ipAddr, strconv.Itoa(port)))
	if err != nil {
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "TCP连接失败", detail: err.Error()}
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
	if delay > 0 && tcpDuration.Milliseconds() > int64(delay) {
		return nil, &nsbFailureRecord{index: inputIndex, ipAddr: ipAddr, port: portStr, phase: "scan", reason: "延迟超过阈值", detail: fmt.Sprintf("tcp=%dms, threshold=%dms", tcpDuration.Milliseconds(), delay)}
	}

	protocol := "http://"
	if enableTLS {
		protocol = "https://"
	}

	start = time.Now()
	httpCtx, httpCancel := context.WithTimeout(ctx, maxDuration)
	defer httpCancel()
	client := http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
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

	loc := locationMap[dataCenter]
	asnNumber, asnOrg := lookupASN(trace["ip"])
	return &iptestResult{
		ipAddr:      ipAddr,
		port:        port,
		dataCenter:  dataCenter,
		locCode:     locCode,
		region:      loc.Region,
		city:        loc.City,
		latency:     fmt.Sprintf("%d ms", tcpDuration.Milliseconds()),
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
			return results[i].downloadSpeed > results[j].downloadSpeed
		})
		return
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].tcpDuration < results[j].tcpDuration
	})
}

func runNSBDownloadSpeed(ctx context.Context, ip string, port int, enableTLS bool, testURL string) (float64, string) {
	const speedWindow = 10 * time.Second
	const speedMaxBytes = 200 * 1024 * 1024

	if strings.TrimSpace(testURL) == "" {
		testURL = speedTestURL
	}

	scheme := "http://"
	if enableTLS {
		scheme = "https://"
	}
	if !strings.HasPrefix(testURL, "http://") && !strings.HasPrefix(testURL, "https://") {
		testURL = scheme + testURL
	}

	parsedURL, err := url.Parse(testURL)
	if err != nil {
		return 0, "测速地址解析失败: " + err.Error()
	}

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				return dialer.DialContext(c, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			},
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	fullURL := fmt.Sprintf("%s%s%s", scheme, parsedURL.Host, parsedURL.RequestURI())

	speedCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(speedCtx, "GET", fullURL, nil)
	if err != nil {
		return 0, "测速请求构建失败: " + err.Error()
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, "测速请求失败: " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return 0, "测速失败"
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

func runNSBTask(ctx context.Context, session *appSession, fileName, fileContent, outFile string, maxThreads, speedTest int, speedURL string, enableTLS bool, delay int, compact bool) {
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

	ips, err := readIPs(tmpPath, enableTLS)
	if err != nil {
		session.sendWSMessage("error", "解析上传文件失败: "+err.Error())
		return
	}
	if len(ips) == 0 {
		session.sendWSMessage("error", "上传文件中未找到有效的 ip 端口行")
		return
	}

	session.sendWSMessage("log", fmt.Sprintf("共读取 %d 条 ip 端口，开始延迟检测", len(ips)))

	nsbResults := make([]iptestResult, 0, len(ips))
	resMutex := &sync.Mutex{}
	var failures []nsbFailureRecord
	var failMutex sync.Mutex
	if debugMode {
		failures = make([]nsbFailureRecord, 0, len(ips))
		failureCSVFile := buildNSBFailureCSVName(outFile)
		defer func() {
			if err := writeNSBFailureCSV(failureCSVFile, failures); err != nil {
				session.sendWSMessage("log", "写入非标失败明细 CSV 失败: "+err.Error())
				return
			}
			session.sendWSMessage("log", fmt.Sprintf("非标失败明细已导出: %s (失败 %d 条)", failureCSVFile, len(failures)))
		}()
	}

	total := len(ips)
	reportNSBProgress(session, "scan", 0, total, "延迟扫描")
	wasCanceled := runBoundedWorkers(ctx, total, maxThreads, 1, func(current, total int) {
		reportNSBProgress(session, "scan", current, total, "延迟扫描")
	}, func(idx int) {
		item := ips[idx]
		select {
		case <-ctx.Done():
			return
		default:
		}

		res, failure := scanNSBEntry(ctx, item, enableTLS, delay, idx)
		if debugMode && failure != nil {
			failMutex.Lock()
			failures = append(failures, *failure)
			failMutex.Unlock()
		}
		if res == nil {
			return
		}

		resMutex.Lock()
		nsbResults = append(nsbResults, *res)
		resMutex.Unlock()
		session.sendWSMessage("nsb_scan_result", res.toNSBMessage(""))
	})

	if wasCanceled || ctx.Err() != nil {
		session.sendWSMessage("log", "检测到停止命令，非标优选延迟扫描已强制终止")
		session.sendWSMessage("error", "任务已被手动终止，未生成最终结果")
		return
	}

	if len(nsbResults) == 0 {
		session.sendWSMessage("error", "未发现有效 IP")
		return
	}

	if speedTest > 0 {
		session.sendWSMessage("log", fmt.Sprintf("开始测速：%d 条记录，线程数=%d", len(nsbResults), speedTest))

		total := len(nsbResults)
		reportNSBProgress(session, "speed", 0, total, "速度测试")
		speedCanceled := runBoundedWorkers(ctx, total, speedTest, 1, func(current, total int) {
			reportNSBProgress(session, "speed", current, total, "速度测试")
		}, func(idx int) {
			select {
			case <-ctx.Done():
				return
			default:
			}

			res := &nsbResults[idx]
			speed, speedErr := runNSBDownloadSpeed(ctx, res.ipAddr, res.port, enableTLS, speedURL)
			res.downloadSpeed = speed

			var speedStr string
			if speedErr != "" {
				speedStr = speedErr
			} else {
				speedStr = fmt.Sprintf("%.2f MB/s", speed/1024)
			}

			session.sendWSMessage("nsb_scan_result", res.toNSBMessage(speedStr))

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
		})
		if speedCanceled {
			wasCanceled = true
		}
	}

	if wasCanceled || ctx.Err() != nil {
		session.sendWSMessage("log", "检测到停止命令，非标测速任务已强制终止")
		session.sendWSMessage("error", "测速任务已被手动终止，不再进行结果整理")
		return
	}

	sortNSBResults(nsbResults, speedTest)

	if err := writeNSBCSV(outFile, nsbResults, speedTest, compact); err != nil {
		session.sendWSMessage("error", "导出 CSV 失败: "+err.Error())
		return
	}

	headers, rows, err := parseCSVFile(outFile)
	if err != nil {
		session.sendWSMessage("error", "读取导出 CSV 失败: "+err.Error())
		return
	}

	session.sendWSMessage("nsb_csv_complete", csvHeaderPayload{Headers: headers, Rows: rows, File: outFile})
	session.sendWSMessage("log", fmt.Sprintf("非标优选完成，结果文件: %s", outFile))
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
		return []string{"IP地址", "端口号", "TLS", "网络延迟", "下载速度", "出站IP", "IP类型", "数据中心", "源IP位置", "地区", "城市", "ASN号码", "ASN组织"}
	}
	headers := []string{"IP地址", "端口号", "TLS", "网络延迟", "下载速度", "出站IP", "IP类型", "数据中心", "源IP位置", "地区", "城市", "ASN号码", "ASN组织"}
	headers = append(headers, "访问协议", "TLS版本", "SNI", "HTTP版本", "WARP", "Gateway", "RBI", "密钥交换", "时间戳")
	return headers
}

func nsbCSVRow(res iptestResult, includeSpeed bool, compact bool) []string {
	speed := "-"
	if includeSpeed {
		speed = fmt.Sprintf("%.2f MB/s", res.downloadSpeed/1024)
	}
	if compact {
		return []string{
			res.ipAddr,
			strconv.Itoa(res.port),
			strconv.FormatBool(res.visitScheme == "https"),
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

func buildNSBFailureCSVName(outFile string) string {
	safeOut := safeFilename(outFile)
	ext := filepath.Ext(safeOut)
	name := strings.TrimSuffix(safeOut, ext)
	if name == "" {
		name = "ip"
	}
	if ext == "" {
		ext = ".csv"
	}
	return name + "_failures" + ext
}

func writeNSBFailureCSV(outFile string, failures []nsbFailureRecord) error {
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

	if err := writer.Write([]string{"IP", "端口", "阶段", "失败原因", "错误详情"}); err != nil {
		return err
	}

	sort.SliceStable(failures, func(i, j int) bool {
		if failures[i].index == failures[j].index {
			return failures[i].phase < failures[j].phase
		}
		return failures[i].index < failures[j].index
	})

	for _, failure := range failures {
		if err := writer.Write([]string{failure.ipAddr, failure.port, failure.phase, failure.reason, failure.detail}); err != nil {
			return err
		}
	}

	return nil
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
