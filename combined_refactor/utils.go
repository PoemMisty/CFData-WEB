package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	urlCandidateRegex         = regexp.MustCompile(`(?i)\b(?:https?|ws|wss)://[^\s|，,]+`)
	bracketIPv6PortRegex      = regexp.MustCompile(`\[([0-9A-Fa-f:.]+)\]\s*[:#，,]\s*(\d{1,5})`)
	hostPortSeparatorRegex    = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9.:-])((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)\s*[:：#，,]\s*(\d{1,5})`)
	hostPortWhitespaceRegex   = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9.:-])((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)\s+(\d{1,5})(?:\s|$)`)
	bareIPv4OrDomainRegex     = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9.:-])((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)(?:\s|$|[|，,。；;、])`)
	possibleBareIPv6LineRegex = regexp.MustCompile(`(?i)([0-9a-f]{1,4}:[0-9a-f:.]+)`)
)

type nsbEndpoint struct {
	host string
	port int
	pos  int
}

func readNonEmptyLines(reader io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(reader)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

func parseIPList(content string) ([]string, error) {
	return readNonEmptyLines(strings.NewReader(content))
}

func readIPs(filename string, enableTLS bool) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parseNSBInputs(string(data), defaultNSBPort(enableTLS)), nil
}

func defaultNSBPort(enableTLS bool) int {
	if enableTLS {
		return 443
	}
	return 80
}

func parseNSBInputs(content string, fallbackPort int) []string {
	var endpoints []nsbEndpoint
	seen := make(map[string]bool)
	add := func(ep nsbEndpoint) {
		ep.host = normalizeNSBHost(ep.host)
		if !isValidNSBHost(ep.host) || !isValidPort(ep.port) {
			return
		}
		key := fmt.Sprintf("%s %d", ep.host, ep.port)
		if seen[key] {
			return
		}
		seen[key] = true
		endpoints = append(endpoints, ep)
	}
	for _, ep := range parseNSBCSVDocument(content, fallbackPort) {
		add(ep)
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		for _, ep := range parseNSBLine(scanner.Text(), fallbackPort) {
			add(ep)
		}
	}

	items := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		items = append(items, fmt.Sprintf("%s %d", ep.host, ep.port))
	}
	return items
}

func parseNSBCSVDocument(content string, fallbackPort int) []nsbEndpoint {
	reader := csv.NewReader(strings.NewReader(content))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return nil
	}
	hostIdx, portIdx := findNSBCSVColumns(records[0])
	if hostIdx < 0 {
		return nil
	}
	var endpoints []nsbEndpoint
	for _, record := range records[1:] {
		if hostIdx >= len(record) {
			continue
		}
		port := fallbackPort
		if portIdx >= 0 && portIdx < len(record) {
			if parsedPort, ok := parsePort(record[portIdx]); ok {
				port = parsedPort
			}
		}
		endpoints = append(endpoints, nsbEndpoint{host: record[hostIdx], port: port})
	}
	return endpoints
}

func findNSBCSVColumns(header []string) (int, int) {
	hostIdx := -1
	portIdx := -1
	for i, name := range header {
		normalized := normalizeNSBCSVHeader(name)
		if hostIdx < 0 && isNSBHostHeader(normalized) {
			hostIdx = i
		}
		if portIdx < 0 && isNSBPortHeader(normalized) {
			portIdx = i
		}
	}
	return hostIdx, portIdx
}

func normalizeNSBCSVHeader(name string) string {
	name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "\ufeff")))
	replacer := strings.NewReplacer(" ", "", "_", "", "-", "", ".", "", "：", "", ":", "")
	return replacer.Replace(name)
}

func isNSBHostHeader(name string) bool {
	switch name {
	case "ip", "ip地址", "host", "hostname", "domain", "address", "addr", "server", "endpoint", "target", "目标", "地址", "域名", "主机", "服务器", "节点":
		return true
	default:
		return false
	}
}

func isNSBPortHeader(name string) bool {
	switch name {
	case "port", "端口", "端口号", "serverport", "targetport":
		return true
	default:
		return false
	}
}

func parseNSBLine(line string, fallbackPort int) []nsbEndpoint {
	line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	if line == "" {
		return nil
	}
	var endpoints []nsbEndpoint
	if ep, ok := parseNSBFieldsAsCSV(line, fallbackPort); ok {
		endpoints = append(endpoints, ep)
	}
	endpoints = append(endpoints, parseNSBURLs(line, fallbackPort)...)
	endpoints = append(endpoints, parseNSBRegexAll(line, bracketIPv6PortRegex, 1, 2, 0)...)
	endpoints = append(endpoints, parseNSBRegexAll(line, hostPortSeparatorRegex, 2, 3, 0)...)
	endpoints = append(endpoints, parseNSBRegexAll(line, hostPortWhitespaceRegex, 2, 3, 0)...)
	if len(endpoints) > 0 {
		sortNSBEndpointsByPosition(endpoints)
		return endpoints
	}
	endpoints = append(endpoints, parseBareIPv6WithPort(line)...)
	if len(endpoints) > 0 {
		sortNSBEndpointsByPosition(endpoints)
		return endpoints
	}
	if ep, ok := parseBareIPv6(line, fallbackPort); ok {
		return []nsbEndpoint{ep}
	}
	endpoints = append(endpoints, parseNSBRegexAll(line, bareIPv4OrDomainRegex, 2, 0, fallbackPort)...)
	if len(endpoints) > 0 {
		sortNSBEndpointsByPosition(endpoints)
		return endpoints
	}
	return nil
}

func sortNSBEndpointsByPosition(endpoints []nsbEndpoint) {
	sort.SliceStable(endpoints, func(i, j int) bool {
		return endpoints[i].pos < endpoints[j].pos
	})
}

func parseNSBFieldsAsCSV(line string, fallbackPort int) (nsbEndpoint, bool) {
	reader := csv.NewReader(strings.NewReader(line))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	fields, err := reader.Read()
	if err != nil || len(fields) < 2 {
		return nsbEndpoint{}, false
	}
	var host string
	port := 0
	for _, field := range fields {
		field = cleanNSBToken(field)
		if host == "" && isValidNSBHost(normalizeNSBHost(field)) {
			host = field
			continue
		}
		if port == 0 {
			if p, ok := parsePort(field); ok {
				port = p
			}
		}
	}
	if host == "" {
		return nsbEndpoint{}, false
	}
	if port == 0 {
		port = fallbackPort
	}
	return nsbEndpoint{host: host, port: port}, true
}

func parseNSBURLs(line string, fallbackPort int) []nsbEndpoint {
	matches := urlCandidateRegex.FindAllString(line, -1)
	endpoints := make([]nsbEndpoint, 0, len(matches))
	for _, match := range matches {
		parsed, err := url.Parse(match)
		if err != nil {
			continue
		}
		host := parsed.Hostname()
		port := fallbackPort
		if parsed.Port() != "" {
			parsedPort, ok := parsePort(parsed.Port())
			if !ok {
				continue
			}
			port = parsedPort
		}
		endpoints = append(endpoints, nsbEndpoint{host: host, port: port, pos: strings.Index(line, match)})
	}
	return endpoints
}

func parseNSBRegexAll(line string, re *regexp.Regexp, hostIdx, portIdx, defaultPort int) []nsbEndpoint {
	matches := re.FindAllStringSubmatchIndex(line, -1)
	endpoints := make([]nsbEndpoint, 0, len(matches))
	for _, match := range matches {
		if len(match) <= hostIdx*2+1 {
			continue
		}
		if ep, ok := parseNSBRegexMatch(line, match, hostIdx, portIdx, defaultPort); ok {
			endpoints = append(endpoints, ep)
		}
	}
	return endpoints
}

func parseNSBRegexMatch(line string, match []int, hostIdx, portIdx, defaultPort int) (nsbEndpoint, bool) {
	port := defaultPort
	if portIdx > 0 {
		if len(match) <= portIdx*2+1 || match[portIdx*2] < 0 {
			return nsbEndpoint{}, false
		}
		parsedPort, ok := parsePort(line[match[portIdx*2]:match[portIdx*2+1]])
		if !ok {
			return nsbEndpoint{}, false
		}
		port = parsedPort
	}
	if port == 0 {
		port = defaultPort
	}
	return nsbEndpoint{host: line[match[hostIdx*2]:match[hostIdx*2+1]], port: port, pos: match[0]}, true
}

func parseBareIPv6(line string, fallbackPort int) (nsbEndpoint, bool) {
	line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
	match := possibleBareIPv6LineRegex.FindStringSubmatch(line)
	if len(match) < 2 {
		return nsbEndpoint{}, false
	}
	host := cleanNSBToken(match[1])
	if _, err := netip.ParseAddr(host); err != nil || !strings.Contains(host, ":") {
		return nsbEndpoint{}, false
	}
	return nsbEndpoint{host: host, port: fallbackPort}, true
}

func parseBareIPv6WithPort(line string) []nsbEndpoint {
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == '，' || r == '#' || r == '|' || r == ';' || r == '；'
	})
	var endpoints []nsbEndpoint
	for i := 0; i+1 < len(fields); i++ {
		host := cleanNSBToken(fields[i])
		if _, err := netip.ParseAddr(host); err != nil || !strings.Contains(host, ":") {
			continue
		}
		port, ok := parsePort(fields[i+1])
		if !ok {
			continue
		}
		endpoints = append(endpoints, nsbEndpoint{host: host, port: port, pos: strings.Index(line, fields[i])})
	}
	return endpoints
}

func normalizeNSBHost(host string) string {
	host = cleanNSBToken(host)
	if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
		host = strings.TrimPrefix(strings.SplitN(host, "]", 2)[0], "[")
	}
	return strings.TrimSpace(strings.Trim(host, "'\"`<>()[]{}"))
}

func cleanNSBToken(value string) string {
	value = strings.TrimSpace(strings.TrimPrefix(value, "\ufeff"))
	value = strings.Trim(value, "'\"`<>()[]{}")
	return strings.TrimSpace(value)
}

func isValidNSBHost(host string) bool {
	host = normalizeNSBHost(host)
	if host == "" {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsValid()
	}
	if looksLikeIPv4Literal(host) {
		return false
	}
	return isValidDomain(host)
}

func looksLikeIPv4Literal(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func isValidDomain(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if len(host) < 4 || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	if strings.Trim(host, "0123456789.") == "" {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func parsePort(value string) (int, bool) {
	value = cleanNSBToken(value)
	port, err := strconv.Atoi(value)
	if err != nil || !isValidPort(port) {
		return 0, false
	}
	return port, true
}

func isValidPort(port int) bool {
	return port > 0 && port <= 65535
}

func parseTraceResponse(body string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

func getIPType(ip string) string {
	if ip == "" {
		return "未知"
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "无效IP"
	}
	if parsedIP.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

func safeFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "ip.csv"
	}
	base := filepath.Base(name)
	if strings.TrimSpace(base) == "" {
		return "ip.csv"
	}
	return base
}

const maxIPv4SubnetExpansion = 1 << 16

func expandCIDRTo24s(subnet string) []string {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(subnet))
	if err != nil {
		return nil
	}

	ones, _ := ipNet.Mask.Size()
	if ones >= 24 {
		return []string{subnet}
	}

	baseIP := ipNet.IP.To4()
	if baseIP == nil {
		return nil
	}

	shift := 24 - ones
	if shift > 16 {
		shift = 16
	}
	count := 1 << uint(shift)
	if count > maxIPv4SubnetExpansion {
		count = maxIPv4SubnetExpansion
	}

	networkInt := uint32(baseIP[0])<<24 | uint32(baseIP[1])<<16 | uint32(baseIP[2])<<8 | uint32(baseIP[3])
	subnets := make([]string, 0, count)
	for i := 0; i < count; i++ {
		cur := networkInt + uint32(i)*256
		ip := net.IPv4(byte(cur>>24), byte(cur>>16), byte(cur>>8), 0)
		subnets = append(subnets, ip.String()+"/24")
	}

	return subnets
}

func randomIPFromCIDR(subnet string) (string, bool) {
	ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(subnet))
	if err != nil {
		return "", false
	}

	baseIP := ip.Mask(ipNet.Mask)
	if ipv4 := baseIP.To4(); ipv4 != nil {
		baseIP = ipv4
	} else {
		baseIP = baseIP.To16()
		if baseIP == nil {
			return "", false
		}
	}

	randomIP := make(net.IP, len(baseIP))
	copy(randomIP, baseIP)

	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return randomIP.String(), true
	}

	for i := len(randomIP) - 1; i >= 0 && hostBits > 0; i-- {
		bitsThisByte := hostBits
		if bitsThisByte > 8 {
			bitsThisByte = 8
		}
		maxValue := 1 << bitsThisByte
		randomIP[i] |= byte(rand.Intn(maxValue))
		hostBits -= bitsThisByte
	}

	return randomIP.String(), true
}

func getRandomIPv4s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		subnets := expandCIDRTo24s(subnet)
		if subnets == nil {
			continue
		}
		for _, cidr := range subnets {
			randomIP, ok := randomIPFromCIDR(cidr)
			if !ok {
				continue
			}
			if net.ParseIP(randomIP).To4() == nil {
				continue
			}
			randomIPs = append(randomIPs, randomIP)
		}
	}
	return randomIPs
}

const maxIPv6SubnetExpansion = 1 << 16

func expandCIDRTo48s(subnet string) []string {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(subnet))
	if err != nil {
		return nil
	}

	ones, _ := ipNet.Mask.Size()
	if ones >= 48 {
		return []string{subnet}
	}

	baseIP := ipNet.IP.To16()
	if baseIP == nil {
		return nil
	}

	shift := 48 - ones
	if shift > 16 {
		shift = 16
	}
	count := 1 << uint(shift)
	if count > maxIPv6SubnetExpansion {
		count = maxIPv6SubnetExpansion
	}

	var networkInt uint64
	for j := 0; j < 6; j++ {
		networkInt = (networkInt << 8) | uint64(baseIP[j])
	}

	subnets := make([]string, 0, count)
	for i := 0; i < count; i++ {
		cur := networkInt + uint64(i)
		ip := make(net.IP, 16)
		for j := 5; j >= 0; j-- {
			ip[j] = byte(cur & 0xFF)
			cur >>= 8
		}
		subnets = append(subnets, ip.String()+"/48")
	}

	return subnets
}

func getRandomIPv6s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		subnets := expandCIDRTo48s(subnet)
		if subnets == nil {
			continue
		}
		for _, cidr := range subnets {
			randomIP, ok := randomIPFromCIDR(cidr)
			if !ok {
				continue
			}
			parsed := net.ParseIP(randomIP)
			if parsed == nil || parsed.To4() != nil {
				continue
			}
			randomIPs = append(randomIPs, randomIP)
		}
	}
	return randomIPs
}
