package main

import (
    "context"
    "fmt"
    "runtime/debug"
    "sync"
    "time"
)

const progressEmitInterval = 250 * time.Millisecond

func runBoundedWorkers(ctx context.Context, total, maxWorkers, progressEvery int, onProgress func(current, total int), work func(idx int)) bool {
    if total == 0 {
        return false
    }

    var wg sync.WaitGroup
    wg.Add(total)

    slots := make(chan struct{}, maxWorkers)
    var count int
    var countMutex sync.Mutex
    var lastEmit time.Time
    wasCanceled := false

    for i := 0; i < total; i++ {
        select {
        case <-ctx.Done():
            wasCanceled = true
            wg.Done()
            continue
        case slots <- struct{}{}:
        }

        go func(idx int) {
            defer func() {
                if r := recover(); r != nil {
                    fmt.Printf("worker panic (idx=%d): %v\n%s\n", idx, r, debug.Stack())
                }
                <-slots
                wg.Done()

                countMutex.Lock()
                count++
                current := count
                shouldEmit := false
                now := time.Now()
                if current == total {
                    shouldEmit = true
                } else if progressEvery > 1 && current%progressEvery == 0 {
                    shouldEmit = true
                } else if now.Sub(lastEmit) >= progressEmitInterval {
                    shouldEmit = true
                }
                if shouldEmit {
                    lastEmit = now
                }
                countMutex.Unlock()

                if onProgress != nil && shouldEmit {
                    func() {
                        defer func() {
                            if r := recover(); r != nil {
                                fmt.Printf("onProgress panic: %v\n%s\n", r, debug.Stack())
                            }
                        }()
                        onProgress(current, total)
                    }()
                }
            }()

            select {
            case <-ctx.Done():
                return
            default:
            }

            work(idx)
        }(i)
    }

    wg.Wait()
    return wasCanceled
}

func reportNSBProgress(session *appSession, phase string, current, total int, text string) {
    percentage := 0.0
    if total > 0 {
        percentage = float64(current) / float64(total) * 100
    }
    session.sendWSMessage("nsb_progress", map[string]interface{}{
        "phase":   phase,
        "current": current,
        "total":   total,
        "percent": fmt.Sprintf("%.2f", percentage),
        "text":    text,
    })
}
