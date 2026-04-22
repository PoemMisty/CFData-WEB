package main

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"time"
)

var globalRunningTasks int32

func anyTaskRunning() bool {
	return atomic.LoadInt32(&globalRunningTasks) > 0
}

func safeGo(label string, session *appSession, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				msg := fmt.Sprintf("%s panic: %v", label, r)
				fmt.Printf("%s\n%s\n", msg, debug.Stack())
				if session != nil {
					session.sendWSMessage("error", "内部错误: "+msg)
				}
			}
		}()
		fn()
	}()
}

func (s *appSession) sendWSMessage(msgType string, data interface{}) {
	if s.emit != nil {
		s.emit(msgType, data)
		return
	}
	if s.ws == nil {
		return
	}
	s.wsMutex.Lock()
	defer s.wsMutex.Unlock()
	if s.wsClosed {
		return
	}
	msg := map[string]interface{}{
		"type": msgType,
		"data": data,
	}
	s.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := s.ws.WriteJSON(msg); err != nil {
		s.wsClosed = true
		sendLog("WebSocket 发送失败: " + err.Error())
	}
}

func (s *appSession) startTask(run taskStarter) {
	ctx, cancel := context.WithCancel(context.Background())
	started := s.beginTask(cancel)
	if !started {
		cancel()
		s.sendWSMessage("error", "已有任务正在运行，请等待完成后再试")
		return
	}
	safeGo("task", s, func() {
		defer cancel()
		defer s.endTask()
		run(ctx, s)
	})
}

func (s *appSession) runTaskSync(run taskStarter) error {
	ctx, cancel := context.WithCancel(context.Background())
	started := s.beginTask(cancel)
	if !started {
		cancel()
		return context.Canceled
	}
	defer cancel()
	defer s.endTask()
	run(ctx, s)
	return nil
}

func (s *appSession) stopTask() {
	s.cancelTask(true)
}

func (s *appSession) cancelTaskSilently() {
	s.cancelTask(false)
}

func (s *appSession) cancelTask(withLog bool) {
	s.taskMutex.Lock()
	cancel := s.taskCancel
	s.taskMutex.Unlock()
	if cancel != nil {
		cancel()
		if withLog {
			s.sendWSMessage("log", "已发送强制终止信号，正在清理当前任务...")
		}
	}
}

func (s *appSession) beginTask(cancel context.CancelFunc) bool {
	if anyTaskRunning() {
		return false
	}
	s.taskMutex.Lock()
	defer s.taskMutex.Unlock()
	if s.isTaskRunning {
		return false
	}
	s.isTaskRunning = true
	s.taskCancel = cancel
	atomic.AddInt32(&globalRunningTasks, 1)
	return true
}

func (s *appSession) endTask() {
	s.taskMutex.Lock()
	defer s.taskMutex.Unlock()
	if s.isTaskRunning {
		atomic.AddInt32(&globalRunningTasks, -1)
	}
	s.isTaskRunning = false
	s.taskCancel = nil
}
