//go:build !windows

package main

import "fmt"

func scheduleClipboardClearWindows() {
	// no-op on non-Windows; handled by scheduleClipboardClear
}

func secureCopyClipboardWindows(text string) error {
	return fmt.Errorf("not supported on this platform")
}
