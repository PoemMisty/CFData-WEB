package main

import (
	"reflect"
	"testing"
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
