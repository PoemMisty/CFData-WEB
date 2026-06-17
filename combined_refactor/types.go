package main

import (
	"context"
	"embed"
	"fmt"
	"net"
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
	//go:embed index.html login.html favicon.png
	staticFiles     embed.FS
	customDNSServer string
	customDNSForced bool
	customResolver  *net.Resolver
)

const defaultDNSServers = "223.5.5.5,8.8.8.8"

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
	DCCountry  string
	City       string
	IPCount    int
	MinLatency int
}

type ScanResult struct {
	IP          string
	Port        int
	DataCenter  string
	DCCountry   string
	Region      string
	City        string
	LatencyStr  string
	TCPDuration time.Duration
}

type TestResult struct {
	IP         string
	Port       int
	DataCenter string
	DCCountry  string
	Region     string
	City       string
	MinLatency time.Duration
	MaxLatency time.Duration
	AvgLatency time.Duration
	LossRate   float64
	Speed      string
}

type iptestResult struct {
	ipAddr         string
	originalInput  string
	port           int
	dataCenter     string
	locCode        string
	region         string
	city           string
	latency        string
	lossRate       float64
	tcpDuration    time.Duration
	outboundIP     string
	ipType         string
	asnNumber      string
	asnOrg         string
	visitScheme    string
	tlsVersion     string
	sni            string
	httpVersion    string
	warp           string
	gateway        string
	rbi            string
	kex            string
	timestamp      string
	downloadSpeed  float64
	speedText      string
	speedTested    bool
	speedQualified bool
}

type nsbScanMessage struct {
	IP             string `json:"ip"`
	OriginalInput  string `json:"originalInput,omitempty"`
	Port           string `json:"port"`
	TLS            string `json:"tls,omitempty"`
	DC             string `json:"dc,omitempty"`
	Loc            string `json:"loc,omitempty"`
	Region         string `json:"region,omitempty"`
	City           string `json:"city,omitempty"`
	Latency        string `json:"latency,omitempty"`
	LossRate       string `json:"lossRate,omitempty"`
	Speed          string `json:"speed,omitempty"`
	SpeedQualified bool   `json:"speedQualified,omitempty"`
	OutboundIP     string `json:"outboundIP,omitempty"`
	IPType         string `json:"ipType,omitempty"`
	ASNNumber      string `json:"asnNumber,omitempty"`
	ASNOrg         string `json:"asnOrg,omitempty"`
	VisitScheme    string `json:"visitScheme,omitempty"`
	TLSVersion     string `json:"tlsVersion,omitempty"`
	SNI            string `json:"sni,omitempty"`
	HTTPVersion    string `json:"httpVersion,omitempty"`
	Warp           string `json:"warp,omitempty"`
	Gateway        string `json:"gateway,omitempty"`
	RBI            string `json:"rbi,omitempty"`
	Kex            string `json:"kex,omitempty"`
	Timestamp      string `json:"timestamp,omitempty"`
}

type nsbCSVCompletePayload struct {
	Headers        []string   `json:"headers"`
	Rows           [][]string `json:"rows"`
	File           string     `json:"file"`
	Status         string     `json:"status"`
	Message        string     `json:"message"`
	QualifiedCount int        `json:"qualifiedCount"`
}

func (r *iptestResult) toNSBMessage(speedStr string) nsbScanMessage {
	return nsbScanMessage{
		IP:             r.ipAddr,
		OriginalInput:  r.originalInput,
		Port:           strconv.Itoa(r.port),
		TLS:            strconv.FormatBool(r.visitScheme == "https"),
		DC:             r.dataCenter,
		Loc:            r.locCode,
		Region:         r.region,
		City:           r.city,
		Latency:        r.latency,
		LossRate:       fmt.Sprintf("%.0f%%", r.lossRate*100),
		Speed:          speedStr,
		SpeedQualified: r.speedQualified,
		OutboundIP:     r.outboundIP,
		IPType:         r.ipType,
		ASNNumber:      r.asnNumber,
		ASNOrg:         r.asnOrg,
		VisitScheme:    r.visitScheme,
		TLSVersion:     r.tlsVersion,
		SNI:            r.sni,
		HTTPVersion:    r.httpVersion,
		Warp:           r.warp,
		Gateway:        r.gateway,
		RBI:            r.rbi,
		Kex:            r.kex,
		Timestamp:      r.timestamp,
	}
}

func (r *iptestResult) toNSBLiveMessage(speedStr string, compact bool) nsbScanMessage {
	if compact {
		return r.toCompactNSBMessage(speedStr)
	}
	return r.toNSBMessage(speedStr)
}

func (r *iptestResult) toCompactNSBMessage(speedStr string) nsbScanMessage {
	return nsbScanMessage{
		IP:             r.ipAddr,
		OriginalInput:  r.originalInput,
		Port:           strconv.Itoa(r.port),
		TLS:            strconv.FormatBool(r.visitScheme == "https"),
		DC:             r.dataCenter,
		Loc:            r.locCode,
		Region:         r.region,
		City:           r.city,
		Latency:        r.latency,
		LossRate:       fmt.Sprintf("%.0f%%", r.lossRate*100),
		Speed:          speedStr,
		SpeedQualified: r.speedQualified,
		OutboundIP:     r.outboundIP,
		IPType:         r.ipType,
		ASNNumber:      r.asnNumber,
		ASNOrg:         r.asnOrg,
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
	backgroundTask       bool
	backgroundSnapshot   backgroundTaskSnapshot
	wsClosed             bool
	scanMutex            sync.Mutex
	scanResults          []ScanResult
	testMutex            sync.Mutex
	testResults          []TestResult
	nsbMutex             sync.Mutex
	nsbHeaders           []string
	nsbRows              [][]string
	progressMutex        sync.Mutex
	progressState        map[string][2]int
	progressPrintTime    map[string]time.Time
	progressPrintPercent map[string]float64
}

type backgroundTaskSnapshot struct {
	Label          string                 `json:"label"`
	Mode           string                 `json:"mode"`
	Phase          string                 `json:"phase"`
	Message        string                 `json:"message"`
	Current        int                    `json:"current"`
	Total          int                    `json:"total"`
	Percent        float64                `json:"percent"`
	ResultCount    int                    `json:"resultCount"`
	SpeedCount     int                    `json:"speedCount"`
	ScanTotal      int                    `json:"scanTotal"`
	ScanSuccess    int                    `json:"scanSuccess"`
	ScanFailed     int                    `json:"scanFailed"`
	SpeedTotal     int                    `json:"speedTotal"`
	SpeedSuccess   int                    `json:"speedSuccess"`
	SpeedFailed    int                    `json:"speedFailed"`
	SpeedQualified int                    `json:"speedQualified"`
	TestCount      int                    `json:"testCount"`
	DCCount        int                    `json:"dcCount"`
	Running        bool                   `json:"running"`
	StartedAt      time.Time              `json:"startedAt"`
	UpdatedAt      time.Time              `json:"updatedAt"`
	Params         map[string]interface{} `json:"params,omitempty"`
}

type taskStarter func(ctx context.Context, session *appSession)

var (
	locationMap map[string]location

	upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	configResetMutex sync.Mutex

	listenPort       int
	listenHost       string
	speedTestURL     string
	speedTestWorkers = 5
	debugMode        bool
	debugLevel       = "error"
	skipGeoCheck     bool
)
