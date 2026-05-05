package main

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestParseNSBInputsNoisyFormats(t *testing.T) {
	input := `ws://cdn-test.example.com:2096 // 临时
[2026/03/22 21:07] Zoe: 172.16.24.9:8443
random words 203.0.113.44:9443 ok
http://beta.example.net:5001 # 主用
李四：example.io:443
备用 | 198.51.100.99:60000
cloudflare.com    优选
[2001:db8:cafe::8]:10443
2001:db8:abcd::7 备注
2001:db8:abcd::7#备注
你好https://192.0.2.201:18080
8.8.8.8 官方
1.2.3.4#1234
110.233.110.333,520`

	got := parseNSBInputs(input, defaultNSBPort(true))
	want := []string{
		"cdn-test.example.com 2096",
		"172.16.24.9 8443",
		"203.0.113.44 9443",
		"beta.example.net 5001",
		"example.io 443",
		"198.51.100.99 60000",
		"cloudflare.com 443",
		"2001:db8:cafe::8 10443",
		"2001:db8:abcd::7 443",
		"192.0.2.201 18080",
		"8.8.8.8 443",
		"1.2.3.4 1234",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseNSBInputs() = %#v, want %#v", got, want)
	}
}

func TestOfficialResultRowsUsesTestMetadataWithoutScan(t *testing.T) {
	rows := officialResultRows(nil, []TestResult{{
		IP:         "203.0.113.10",
		Port:       8443,
		DataCenter: "NRT",
		Region:     "Asia Pacific",
		City:       "Tokyo",
		AvgLatency: 35 * time.Millisecond,
		Speed:      "12.30MB/s",
	}})
	if len(rows) != 1 {
		t.Fatalf("officialResultRows len = %d, want 1", len(rows))
	}
	row := rows[0]
	if row["dc"] != "NRT" || row["region"] != "Asia Pacific" || row["city"] != "Tokyo" {
		t.Fatalf("officialResultRows metadata = %#v", row)
	}
	if row["ipport"] != "203.0.113.10:8443" || row["latency"] != "35ms" || row["speed"] != "12.30MB/s" {
		t.Fatalf("officialResultRows fields = %#v", row)
	}
}

func TestResolveCLIFieldsOfficialCompactMatchesNSBOrder(t *testing.T) {
	rows := []cliResultRow{{"ip": "203.0.113.10", "port": "8443", "latency": "35ms", "speed": "12.30MB/s", "dc": "NRT", "region": "Asia Pacific", "city": "Tokyo"}}
	got := resolveCLIFields("compact", "csv", rows)
	want := []string{"ip", "port", "latency", "speed", "dc", "region", "city"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveCLIFields official compact = %#v, want %#v", got, want)
	}
}

func TestOfficialResultRowsSortsLikeNSB(t *testing.T) {
	rows := officialResultRows(nil, []TestResult{
		{IP: "203.0.113.3", Port: 443, AvgLatency: 10 * time.Millisecond, Speed: "5.00MB/s"},
		{IP: "203.0.113.1", Port: 443, AvgLatency: 30 * time.Millisecond},
		{IP: "203.0.113.2", Port: 443, AvgLatency: 20 * time.Millisecond, Speed: "20.00MB/s"},
	})
	got := []string{rows[0]["ip"], rows[1]["ip"], rows[2]["ip"]}
	want := []string{"203.0.113.2", "203.0.113.3", "203.0.113.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("officialResultRows order = %#v, want %#v", got, want)
	}
}

func TestRunNSBSpeedWorkersContinuesUntilQualifiedTarget(t *testing.T) {
	results := []iptestResult{{ipAddr: "1"}, {ipAddr: "2"}, {ipAddr: "3"}, {ipAddr: "4"}}
	runNSBSpeedWorkers(context.Background(), results, 2, 2, 5, nil, nil, func(idx int) (float64, string) {
		if idx < 2 {
			return 4 * 1024, ""
		}
		return 6 * 1024, ""
	})
	tested := 0
	qualified := 0
	for _, res := range results {
		if res.speedTested {
			tested++
		}
		if res.speedQualified {
			qualified++
		}
	}
	if tested != 4 {
		t.Fatalf("speed tested count = %d, want 4", tested)
	}
	if qualified != 2 {
		t.Fatalf("qualified count = %d, want 2", qualified)
	}
	if len(results) != 4 {
		t.Fatalf("results len = %d, want 4", len(results))
	}
}

func TestFilterCLIResultRowsByIPType(t *testing.T) {
	rows := []cliResultRow{
		{"ip": "192.0.2.1", "ipType": "IPv4"},
		{"ip": "2001:db8::1", "ipType": "IPv6"},
		{"ip": "192.0.2.2", "ipType": "IPv4"},
	}
	got := filterCLIResultRowsByIPType(rows, "ipv6")
	if len(got) != 1 || got[0]["ip"] != "2001:db8::1" {
		t.Fatalf("filterCLIResultRowsByIPType ipv6 = %#v", got)
	}
	if gotAll := filterCLIResultRowsByIPType(rows, "all"); len(gotAll) != len(rows) {
		t.Fatalf("filterCLIResultRowsByIPType all len = %d, want %d", len(gotAll), len(rows))
	}
}

func TestFilterCLIResultRowsByQualification(t *testing.T) {
	rows := []cliResultRow{
		{"ip": "192.0.2.1", "speed": "6.00MB/s"},
		{"ip": "192.0.2.2", "speed": "4.99MB/s"},
		{"ip": "192.0.2.3", "speed": "未测速"},
	}
	got := filterCLIResultRowsByQualification(rows, true, true, 5)
	if len(got) != 1 || got[0]["ip"] != "192.0.2.1" {
		t.Fatalf("filterCLIResultRowsByQualification = %#v", got)
	}
	if gotAll := filterCLIResultRowsByQualification(rows, true, false, 5); len(gotAll) != len(rows) {
		t.Fatalf("filterCLIResultRowsByQualification no speed len = %d, want %d", len(gotAll), len(rows))
	}
}

func TestParseNSBInputsCSVHeadersAndMultipleEndpoints(t *testing.T) {
	input := `备注,IP地址,端口号
主用,203.0.113.1,443
备用,example.com,8443
多个 198.51.100.1:2053 和 https://cdn.example.net:2096`

	got := parseNSBInputs(input, defaultNSBPort(true))
	want := []string{
		"203.0.113.1 443",
		"example.com 8443",
		"198.51.100.1 2053",
		"cdn.example.net 2096",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseNSBInputs() = %#v, want %#v", got, want)
	}
}

func TestParseNSBInputsDefaultPortFollowsTLS(t *testing.T) {
	input := "cloudflare.com\n2001:db8:abcd::7\n8.8.8.8 官方"
	gotTLS := parseNSBInputs(input, defaultNSBPort(true))
	wantTLS := []string{"cloudflare.com 443", "2001:db8:abcd::7 443", "8.8.8.8 443"}
	if !reflect.DeepEqual(gotTLS, wantTLS) {
		t.Fatalf("parseNSBInputs(TLS) = %#v, want %#v", gotTLS, wantTLS)
	}

	gotPlain := parseNSBInputs(input, defaultNSBPort(false))
	wantPlain := []string{"cloudflare.com 80", "2001:db8:abcd::7 80", "8.8.8.8 80"}
	if !reflect.DeepEqual(gotPlain, wantPlain) {
		t.Fatalf("parseNSBInputs(no TLS) = %#v, want %#v", gotPlain, wantPlain)
	}
}

func TestParseNSBInputsIPv6Safety(t *testing.T) {
	input := `2001:db8::1 8443
2001:db8::2#2053
2001:db8::3,2083
2001:db8::4:443`

	got := parseNSBInputs(input, defaultNSBPort(true))
	want := []string{
		"2001:db8::1 8443",
		"2001:db8::2 2053",
		"2001:db8::3 2083",
		"2001:db8::4:443 443",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseNSBInputs() = %#v, want %#v", got, want)
	}
}
