package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	compactIPv4File            = "ips-v4.txt"
	compactIPv4API             = "https://www.baipiao.eu.org/cloudflare/ips-v4"
	compactIPv4Threads         = 100
	compactIPv4MaxEmptyRounds  = 2
	compactIPv4ConnectTimeout  = time.Second
	compactIPv4Port            = 80
)

type compactSubnetState struct {
	subnet  string
	usedIPs map[int]bool
	found   bool
}

func runCompactIPv4Task(ctx context.Context, session *appSession) {
	session.sendWSMessage("log", "开始精简本地 IPv4 地址库...")

	content, err := getIPListContent(compactIPv4File, compactIPv4API)
	if err != nil {
		session.sendWSMessage("error", "读取 IPv4 地址库失败: "+err.Error())
		return
	}

	rawList, err := parseIPList(content)
	if err != nil {
		session.sendWSMessage("error", "解析 IPv4 地址库失败: "+err.Error())
		return
	}
	if len(rawList) == 0 {
		session.sendWSMessage("error", "IPv4 地址库为空，无法精简")
		return
	}

	states := initCompactSubnetStates(rawList)
	if len(states) == 0 {
		session.sendWSMessage("error", "未识别到可精简的 /24 子网条目")
		return
	}

	validSubnets := map[string]bool{}
	emptyRounds := 0
	pass := 1
	canceled := false

	for {
		select {
		case <-ctx.Done():
			canceled = true
		default:
		}
		if canceled {
			break
		}

		toScan := collectPendingSubnets(states)
		if len(toScan) == 0 {
			break
		}
		ips := generateOneIPPerPendingSubnet(toScan)
		if len(ips) == 0 {
			break
		}

		session.sendWSMessage("log", fmt.Sprintf("精简第 %d 轮开始，本轮待测 %d 个子网", pass, len(ips)))
		reportCompactProgress(session, pass, 0, len(ips), len(validSubnets), fmt.Sprintf("精简第 %d 轮", pass))

		validIPs, scanCanceled := scanCompactIPv4(ctx, session, ips, compactIPv4Threads, pass, len(validSubnets))
		if scanCanceled {
			canceled = true
		}

		if len(validIPs) == 0 {
			emptyRounds++
			session.sendWSMessage("log", fmt.Sprintf("第 %d 轮未发现有效子网", pass))
			if emptyRounds >= compactIPv4MaxEmptyRounds {
				session.sendWSMessage("log", fmt.Sprintf("连续 %d 轮未发现新子网，停止精简", compactIPv4MaxEmptyRounds))
				break
			}
		} else {
			emptyRounds = 0
			session.sendWSMessage("log", fmt.Sprintf("第 %d 轮发现 %d 个有效子网", pass, len(validIPs)))
		}

		for _, ip := range validIPs {
			subnet := extractCompactSubnet(ip)
			if subnet == "" {
				continue
			}
			if state, ok := states[subnet]; ok {
				state.found = true
			}
			validSubnets[subnet] = true
		}
		session.sendWSMessage("log", fmt.Sprintf("第 %d 轮结束，累计保留 %d 个子网", pass, len(validSubnets)))
		pass++
	}

	status := "精简完成"
	if canceled {
		status = "精简已终止"
	}
	reportCompactProgress(session, pass-1, len(validSubnets), len(validSubnets), len(validSubnets), status)

	if len(validSubnets) == 0 {
		session.sendWSMessage("error", "未发现任何可保留的 IPv4 子网，已保留原始地址库")
		return
	}

	subnets := sortedCompactSubnets(validSubnets)
	compactContent := strings.Join(subnets, "\n") + "\n"
	if err := atomicWriteFile(compactIPv4File, []byte(compactContent), 0644); err != nil {
		session.sendWSMessage("error", "写入精简后的 IPv4 地址库失败: "+err.Error())
		return
	}

	session.sendWSMessage("compact_ipv4_done", map[string]interface{}{
		"count": len(subnets),
		"file":  compactIPv4File,
	})
	session.sendWSMessage("log", fmt.Sprintf("精简完成：保留 %d 个 /24 子网，已覆盖 %s", len(subnets), compactIPv4File))
}

func reportCompactProgress(session *appSession, pass, current, total, found int, status string) {
	percent := 0.0
	if total > 0 {
		percent = float64(current) / float64(total) * 100
	}
	session.sendWSMessage("compact_ipv4_progress", map[string]interface{}{
		"pass":    pass,
		"current": current,
		"total":   total,
		"found":   found,
		"percent": fmt.Sprintf("%.2f", percent),
		"status":  status,
	})
}

func initCompactSubnetStates(ipList []string) map[string]*compactSubnetState {
	states := make(map[string]*compactSubnetState, len(ipList))
	for _, raw := range ipList {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			raw = raw + "/24"
		}
		for _, cidr := range expandCIDRTo24s(raw) {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			baseIP := ipNet.IP.To4()
			if baseIP == nil {
				continue
			}
			key := fmt.Sprintf("%d.%d.%d.0/24", baseIP[0], baseIP[1], baseIP[2])
			if _, exists := states[key]; exists {
				continue
			}
			states[key] = &compactSubnetState{
				subnet:  key,
				usedIPs: make(map[int]bool),
			}
		}
	}
	return states
}

func collectPendingSubnets(states map[string]*compactSubnetState) []*compactSubnetState {
	pending := make([]*compactSubnetState, 0, len(states))
	for _, state := range states {
		if !state.found && len(state.usedIPs) < 256 {
			pending = append(pending, state)
		}
	}
	return pending
}

func generateOneIPPerPendingSubnet(states []*compactSubnetState) []string {
	ips := make([]string, 0, len(states))
	for _, state := range states {
		if len(state.usedIPs) >= 256 {
			continue
		}
		lastOctet := rand.Intn(256)
		for state.usedIPs[lastOctet] {
			lastOctet = (lastOctet + 1) % 256
		}
		state.usedIPs[lastOctet] = true

		baseIP := strings.TrimSuffix(state.subnet, "/24")
		octets := strings.Split(baseIP, ".")
		if len(octets) != 4 {
			continue
		}
		octets[3] = strconv.Itoa(lastOctet)
		ips = append(ips, strings.Join(octets, "."))
	}
	return ips
}

func scanCompactIPv4(ctx context.Context, session *appSession, ipList []string, maxThreads, pass, foundCount int) ([]string, bool) {
	total := len(ipList)
	results := make([]string, 0, total)
	var resultsMutex sync.Mutex

	canceled := runBoundedWorkers(ctx, total, maxThreads, 10, func(current, total int) {
		resultsMutex.Lock()
		currentFound := foundCount + len(results)
		resultsMutex.Unlock()
		reportCompactProgress(session, pass, current, total, currentFound, fmt.Sprintf("精简第 %d 轮", pass))
	}, func(idx int) {
		ip := ipList[idx]
		select {
		case <-ctx.Done():
			return
		default:
		}
		dialer := &net.Dialer{Timeout: compactIPv4ConnectTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(compactIPv4Port)))
		if err != nil {
			return
		}
		conn.Close()
		resultsMutex.Lock()
		results = append(results, ip)
		resultsMutex.Unlock()
		if debugMode {
			session.sendWSMessage("compact_ipv4_hit", map[string]interface{}{
				"pass": pass,
				"ip":   ip,
			})
		}
	})

	return results, canceled
}

func extractCompactSubnet(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
}

func sortedCompactSubnets(set map[string]bool) []string {
	subnets := make([]string, 0, len(set))
	for subnet := range set {
		subnets = append(subnets, subnet)
	}
	sort.Slice(subnets, func(i, j int) bool {
		a := strings.TrimSuffix(subnets[i], "/24")
		b := strings.TrimSuffix(subnets[j], "/24")
		ai := strings.Split(a, ".")
		bi := strings.Split(b, ".")
		if len(ai) != 4 || len(bi) != 4 {
			return subnets[i] < subnets[j]
		}
		for k := 0; k < 4; k++ {
			na, _ := strconv.Atoi(ai[k])
			nb, _ := strconv.Atoi(bi[k])
			if na != nb {
				return na < nb
			}
		}
		return false
	})
	return subnets
}
