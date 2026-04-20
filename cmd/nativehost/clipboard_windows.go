package main

import (
	"os/exec"
	"syscall"
)

func scheduleClipboardClearWindows() {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
		"Start-Sleep -Seconds 30; Set-Clipboard -Value $null")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	_ = cmd.Start()
}
