package main

import (
    "context"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "time"
)

func isTLSPort(port int) bool {
	return port == 443 || port == 2053 || port == 2083 || port == 2087 || port == 2096 || port == 8443
}

func runWindowedSpeedTest(ctx context.Context, ip string, port int, customURL string) (float64, string) {
	scheme := "http"
	if isTLSPort(port) {
		scheme = "https"
	}

	testURL := speedTestURL
	if customURL != "" {
		testURL = customURL
	}
	if !strings.HasPrefix(testURL, "http://") && !strings.HasPrefix(testURL, "https://") {
		testURL = scheme + "://" + testURL
	}

	parsedURL, err := url.Parse(testURL)
	if err != nil {
		return 0, "URL解析错误"
	}

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				return dialer.DialContext(c, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			},
			TLSHandshakeTimeout: 10 * time.Second,
		},
		Timeout: 15 * time.Second,
	}

	fullURL := fmt.Sprintf("%s://%s%s", scheme, parsedURL.Hostname(), parsedURL.RequestURI())
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return 0, "请求构造错误"
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, "连接错误"
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return 0, "测速失败"
	}

	buf := make([]byte, 32*1024)
	var totalBytes int64
	var maxSpeedMB float64

	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	readerCtx, readerCancel := context.WithCancel(ctx)
	defer readerCancel()

	type readChunk struct {
		n   int
		err error
	}
	chunks := make(chan readChunk, 16)
	readerDone := make(chan struct{})
	safeGo("speed-reader", nil, func() {
		defer close(readerDone)
		for {
			n, err := resp.Body.Read(buf)
			select {
			case chunks <- readChunk{n: n, err: err}:
			case <-readerCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	})

	lastBytes := int64(0)
	lastTime := start
	done := false
	canceled := false
loop:
	for !done {
		select {
		case <-ctx.Done():
			canceled = true
			done = true
		case <-timeout:
			done = true
		case now := <-ticker.C:
			duration := now.Sub(lastTime).Seconds()
			if duration > 0 {
				diff := totalBytes - lastBytes
				currentSpeedMB := float64(diff) / duration / 1024 / 1024
				if currentSpeedMB > maxSpeedMB {
					maxSpeedMB = currentSpeedMB
				}
			}
			lastBytes = totalBytes
			lastTime = now
		case chunk := <-chunks:
			if chunk.n > 0 {
				totalBytes += int64(chunk.n)
			}
			if chunk.err != nil {
				done = true
				break loop
			}
		}
	}

	readerCancel()
	resp.Body.Close()
	<-readerDone

	if canceled {
		return 0, "测速任务已终止"
	}

	if totalBytes <= 0 || maxSpeedMB <= 0 {
		return 0, "0 MB/s"
	}

	duration := time.Since(start).Seconds()
	if duration == 0 {
		duration = 1
	}
	realSpeedMB := float64(totalBytes) / duration / 1024 / 1024
	if maxSpeedMB > realSpeedMB {
		return maxSpeedMB, ""
	}
	return realSpeedMB, ""
}

func runSpeedTest(ctx context.Context, session *appSession, ip string, port int, customURL string) {
    session.sendWSMessage("log", fmt.Sprintf("开始对 IP %s 端口 %d 进行测速...", ip, port))

	speedMB, speedErr := runWindowedSpeedTest(ctx, ip, port, customURL)
	if speedErr != "" {
		session.sendWSMessage("speed_test_result", map[string]string{"ip": ip, "speed": speedErr})
		session.sendWSMessage("log", "测速失败: "+speedErr)
		return
	}
	speedStr := fmt.Sprintf("%.2f MB/s", speedMB)

    session.sendWSMessage("speed_test_result", map[string]string{"ip": ip, "speed": speedStr})
    session.sendWSMessage("log", fmt.Sprintf("IP %s 测速完成: %s", ip, speedStr))
}
