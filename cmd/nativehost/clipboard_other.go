//go:build !windows

package main

func scheduleClipboardClearWindows() {
	// no-op on non-Windows; handled by scheduleClipboardClear
}
