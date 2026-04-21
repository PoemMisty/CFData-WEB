package main

import "encoding/json"

type wsRequest struct {
    Type string          `json:"type"`
    Data json.RawMessage `json:"data"`
}

type startTaskRequest struct {
    IPType  int `json:"ipType"`
    Threads int `json:"threads"`
    Port    int `json:"port"`
}

type startTestRequest struct {
    DC    string `json:"dc"`
    Port  int    `json:"port"`
    Delay int    `json:"delay"`
}

type startSpeedTestRequest struct {
    IP   string `json:"ip"`
    Port int    `json:"port"`
    URL  string `json:"url"`
}

type startNSBTaskRequest struct {
    FileName    string `json:"fileName"`
    FileContent string `json:"fileContent"`
    OutFile     string `json:"outFile"`
    MaxThreads  int    `json:"maxThreads"`
    SpeedTest   int    `json:"speedTest"`
    SpeedURL    string `json:"speedURL"`
    EnableTLS   bool   `json:"enableTLS"`
    Delay       int    `json:"delay"`
}
