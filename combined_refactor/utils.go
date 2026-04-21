package main

import (
	"bufio"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
    "strings"
)

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

func readIPs(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    return readNonEmptyLines(file)
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
