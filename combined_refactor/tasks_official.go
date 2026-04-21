package main

import (
    "context"
    "fmt"
    "io"
    "math"
    "net"
    "net/http"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"
)

var coloRegex = regexp.MustCompile(`colo=([A-Z]+)`)

func scanOfficialIP(ctx context.Context, ip string, port int) *ScanResult {
    dialer := &net.Dialer{Timeout: timeout}
    start := time.Now()
    conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "80"))
    if err != nil {
        return nil
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
    client := http.Client{
        Transport: &http.Transport{
            DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                return conn, nil
            },
        },
        Timeout: 1 * time.Second,
    }

    req, err := http.NewRequestWithContext(ctx, "GET", "http://"+requestURL, nil)
    if err != nil {
        return nil
    }
    req.Host = "speed.cloudflare.com"
    req.Header.Set("User-Agent", "Mozilla/5.0")
    req.Close = true

    resp, err := client.Do(req)
    if err != nil {
        return nil
    }
    bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
    resp.Body.Close()
    if err != nil {
        return nil
    }
    bodyStr := string(bodyBytes)

    if !strings.Contains(bodyStr, "uag=Mozilla/5.0") {
        return nil
    }

    dataCenter := ""
    if matches := coloRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
        dataCenter = matches[1]
    }
    if dataCenter == "" {
        return nil
    }

    loc := locationMap[dataCenter]
	res := &ScanResult{
		IP:          ip,
		Port:        port,
		DataCenter:  dataCenter,
		Region:      loc.Region,
		City:        loc.City,
		LatencyStr:  fmt.Sprintf("%d ms", tcpDuration.Milliseconds()),
		TCPDuration: tcpDuration,
	}
	return res
}

func testIPLatency(ctx context.Context, ip string, port int, delay int) *TestResult {
    dialerTimeout := time.Duration(delay) * time.Millisecond
    if delay <= 0 {
        dialerTimeout = 3 * time.Second
    }
    dialer := &net.Dialer{Timeout: dialerTimeout}
    successCount := 0
    var totalLatency time.Duration
    minLatency := time.Duration(math.MaxInt64)
    maxLatency := time.Duration(0)

    for i := 0; i < 10; i++ {
        select {
        case <-ctx.Done():
            return nil
        default:
        }

        start := time.Now()
        conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
        if err != nil {
            continue
        }
        latency := time.Since(start)
        if delay > 0 && latency > time.Duration(delay)*time.Millisecond {
            conn.Close()
            continue
        }
        successCount++
        totalLatency += latency
        if latency < minLatency {
            minLatency = latency
        }
        if latency > maxLatency {
            maxLatency = latency
        }
        conn.Close()
    }

    if successCount == 0 {
        return nil
    }

    avgLatency := totalLatency / time.Duration(successCount)
    lossRate := float64(10-successCount) / 10.0
    return &TestResult{
        IP:         ip,
        MinLatency: minLatency,
        MaxLatency: maxLatency,
        AvgLatency: avgLatency,
        LossRate:   lossRate,
    }
}

func runOfficialTask(ctx context.Context, session *appSession, ipType int, scanMaxThreads int, port int) {
    session.sendWSMessage("log", "开始扫描任务...")

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

    session.scanMutex.Lock()
    session.scanResults = []ScanResult{}
    session.scanMutex.Unlock()

    session.sendWSMessage("log", fmt.Sprintf("正在扫描 %d 个 IP 地址...", len(ipList)))

	total := len(ipList)
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

		res := scanOfficialIP(ctx, ip, port)
		if res == nil {
			return
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

func runDetailedTest(ctx context.Context, session *appSession, selectedDC string, port int, delay int) {
    var testIPList []string
    session.scanMutex.Lock()
    for _, res := range session.scanResults {
        if selectedDC == "" || res.DataCenter == selectedDC {
            testIPList = append(testIPList, res.IP)
        }
    }
    session.scanMutex.Unlock()

    if len(testIPList) == 0 {
        session.sendWSMessage("error", "没有找到可测试的 IP 地址")
        return
    }

    session.sendWSMessage("log", fmt.Sprintf("开始对 %s 的 %d 个 IP 进行详细测试...", selectedDC, len(testIPList)))

    var results []TestResult
    var resMutex sync.Mutex

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

        res := testIPLatency(ctx, ip, port, delay)
        if res == nil {
            return
        }
        session.sendWSMessage("test_result", *res)

        resMutex.Lock()
        results = append(results, *res)
        resMutex.Unlock()
    })

    if wasCanceled || ctx.Err() != nil {
        session.sendWSMessage("log", "详细测试已被终止，正在呈现当前可用测试结果...")
    }

    sort.Slice(results, func(i, j int) bool {
        if results[i].LossRate != results[j].LossRate {
            return results[i].LossRate < results[j].LossRate
        }
        minI := results[i].MinLatency / time.Millisecond
        minJ := results[j].MinLatency / time.Millisecond
        if minI != minJ {
            return minI < minJ
        }
        if results[i].MaxLatency != results[j].MaxLatency {
            return results[i].MaxLatency < results[j].MaxLatency
        }
        return results[i].AvgLatency < results[j].AvgLatency
    })

    session.sendWSMessage("test_complete", results)
}
