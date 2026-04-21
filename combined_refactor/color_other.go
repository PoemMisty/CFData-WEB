//go:build !windows

package main

func enableTerminalANSI() bool {
	return true
}
