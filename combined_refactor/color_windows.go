//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

const enableVirtualTerminalProcessing uint32 = 0x0004

var (
	kernel32DLL        = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32DLL.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32DLL.NewProc("SetConsoleMode")
)

func enableTerminalANSI() bool {
	enabled := enableVTForHandle(os.Stdout)
	if !enableVTForHandle(os.Stderr) {
		return false
	}
	return enabled
}

func enableVTForHandle(f *os.File) bool {
	if f == nil {
		return false
	}
	handle := syscall.Handle(f.Fd())
	var mode uint32
	ret, _, _ := procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if ret == 0 {
		return false
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	ret, _, _ = procSetConsoleMode.Call(uintptr(handle), uintptr(mode|enableVirtualTerminalProcessing))
	return ret != 0
}
