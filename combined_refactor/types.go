package main

import (
	"context"
	"embed"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	requestURL = "speed.cloudflare.com/cdn-cgi/trace"
)

const (
	timeout     = 3 * time.Second
	maxDuration = 5 * time.Second
)

var (
	//go:embed index.html login.html
	staticFiles embed.FS
)

type location struct {
	Iata      string  `json:"iata"`
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	Cca2      string  `json:"cca2"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Region_zh string  `json:"region_zh"`
	Country   string  `json:"country"`
	City_zh   string  `json:"city_zh"`
	Emoji     string  `json:"emoji"`
}

type DataCenterInfo struct {
	DataCenter string
	City       string
	IPCount    int
	MinLatency int
}

type ScanResult struct {
	IP          string
	Port        int
	DataCenter  string
	Region      string
	City        string
	LatencyStr  string
	TCPDuration time.Duration
}

type TestResult struct {
	IP         string
	Port       int
	MinLatency time.Duration
	MaxLatency time.Duration
	AvgLatency time.Duration
	LossRate   float64
	Speed      string
}

type iptestResult struct {
	ipAddr        string
	port          int
	dataCenter    string
	locCode       string
	region        string
	city          string
	latency       string
	tcpDuration   time.Duration
	outboundIP    string
	ipType        string
	visitScheme   string
	tlsVersion    string
	sni           string
	httpVersion   string
	warp          string
	gateway       string
	rbi           string
	kex           string
	timestamp     string
	downloadSpeed float64
}

type nsbScanMessage struct {
	IP          string `json:"ip"`
	Port        string `json:"port"`
	TLS         string `json:"tls"`
	DC          string `json:"dc"`
	Loc         string `json:"loc"`
	Region      string `json:"region"`
	City        string `json:"city"`
	Latency     string `json:"latency"`
	Speed       string `json:"speed"`
	OutboundIP  string `json:"outboundIP"`
	IPType      string `json:"ipType"`
	VisitScheme string `json:"visitScheme"`
	TLSVersion  string `json:"tlsVersion"`
	SNI         string `json:"sni"`
	HTTPVersion string `json:"httpVersion"`
	Warp        string `json:"warp"`
	Gateway     string `json:"gateway"`
	RBI         string `json:"rbi"`
	Kex         string `json:"kex"`
	Timestamp   string `json:"timestamp"`
}

func (r *iptestResult) toNSBMessage(speedStr string) nsbScanMessage {
	return nsbScanMessage{
		IP:          r.ipAddr,
		Port:        strconv.Itoa(r.port),
		TLS:         strconv.FormatBool(r.visitScheme == "https"),
		DC:          r.dataCenter,
		Loc:         r.locCode,
		Region:      r.region,
		City:        r.city,
		Latency:     r.latency,
		Speed:       speedStr,
		OutboundIP:  r.outboundIP,
		IPType:      r.ipType,
		VisitScheme: r.visitScheme,
		TLSVersion:  r.tlsVersion,
		SNI:         r.sni,
		HTTPVersion: r.httpVersion,
		Warp:        r.warp,
		Gateway:     r.gateway,
		RBI:         r.rbi,
		Kex:         r.kex,
		Timestamp:   r.timestamp,
	}
}

type csvHeaderPayload struct {
	Headers []string   `json:"headers"`
	Rows    [][]string `json:"rows"`
	File    string     `json:"file"`
}

type resetConfigResult struct {
	Success  bool     `json:"success"`
	Deleted  []string `json:"deleted"`
	Missing  []string `json:"missing"`
	Failed   []string `json:"failed"`
	Reminder string   `json:"reminder"`
}

type appSession struct {
	ws                   *websocket.Conn
	emit                 func(msgType string, data interface{})
	wsMutex              sync.Mutex
	taskMutex            sync.Mutex
	isTaskRunning        bool
	taskCancel           context.CancelFunc
	wsClosed             bool
	scanMutex            sync.Mutex
	scanResults          []ScanResult
	testMutex            sync.Mutex
	testResults          []TestResult
	progressMutex        sync.Mutex
	progressState        map[string][2]int
	progressPrintTime    map[string]time.Time
	progressPrintPercent map[string]float64
}

type taskStarter func(ctx context.Context, session *appSession)

var (
	locationMap map[string]location

	upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	configResetMutex sync.Mutex

	listenPort       int
	speedTestURL     string
	speedTestWorkers = 5
	debugMode        bool
)
