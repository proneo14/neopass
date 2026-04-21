package main

import (
	"syscall"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
)

var (
	user32                      = syscall.NewLazyDLL("user32.dll")
	kernel32                    = syscall.NewLazyDLL("kernel32.dll")
	pOpenClipboard              = user32.NewProc("OpenClipboard")
	pEmptyClipboard             = user32.NewProc("EmptyClipboard")
	pCloseClipboard             = user32.NewProc("CloseClipboard")
	pSetClipboardData           = user32.NewProc("SetClipboardData")
	pRegisterClipboardFormatW   = user32.NewProc("RegisterClipboardFormatW")
	pGlobalAlloc                = kernel32.NewProc("GlobalAlloc")
	pGlobalLock                 = kernel32.NewProc("GlobalLock")
	pGlobalUnlock               = kernel32.NewProc("GlobalUnlock")
	pRtlMoveMemory              = kernel32.NewProc("RtlMoveMemory")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

// secureCopyClipboardWindows copies text to the clipboard using Win32 API
// and sets ExcludeClipboardContentFromMonitorProcessing so the password
// doesn't appear in Windows Clipboard History (Win+V).
// No PowerShell is used.
func secureCopyClipboardWindows(text string) error {
	r, _, _ := pOpenClipboard.Call(0)
	if r == 0 {
		return syscall.GetLastError()
	}
	defer pCloseClipboard.Call()

	pEmptyClipboard.Call()

	// Set CF_UNICODETEXT
	utf16, _ := syscall.UTF16FromString(text)
	size := len(utf16) * 2 // 2 bytes per UTF-16 char
	hMem, _, _ := pGlobalAlloc.Call(gmemMoveable, uintptr(size))
	if hMem == 0 {
		return syscall.GetLastError()
	}
	ptr, _, _ := pGlobalLock.Call(hMem)
	if ptr == 0 {
		return syscall.GetLastError()
	}
	// Use RtlMoveMemory to copy UTF-16 data to the locked global memory.
	// This avoids the go vet "possible misuse of unsafe.Pointer" for uintptr→Pointer.
	pRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&utf16[0])), uintptr(len(utf16)*2))
	pGlobalUnlock.Call(hMem)
	pSetClipboardData.Call(cfUnicodeText, hMem)

	// Set ExcludeClipboardContentFromMonitorProcessing = 1
	formatName, _ := syscall.UTF16PtrFromString("ExcludeClipboardContentFromMonitorProcessing")
	fmtID, _, _ := pRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(formatName)))
	if fmtID != 0 {
		hExclude, _, _ := pGlobalAlloc.Call(gmemMoveable, 4)
		if hExclude != 0 {
			pExclude, _, _ := pGlobalLock.Call(hExclude)
			if pExclude != 0 {
				// Write int32(1) to the locked memory via RtlMoveMemory.
				// This avoids the go vet "unsafe.Pointer(uintptr)" false positive.
				val := int32(1)
				pRtlMoveMemory.Call(pExclude, uintptr(unsafe.Pointer(&val)), 4)
				pGlobalUnlock.Call(hExclude)
				pSetClipboardData.Call(fmtID, hExclude)
			}
		}
	}

	return nil
}

// clearClipboardWindows empties the clipboard using Win32 API.
func clearClipboardWindows() {
	r, _, _ := pOpenClipboard.Call(0)
	if r == 0 {
		return
	}
	pEmptyClipboard.Call()
	pCloseClipboard.Call()
}

// scheduleClipboardClearWindows clears the clipboard after 30 seconds
// using an in-process Go timer (no PowerShell).
func scheduleClipboardClearWindows() {
	time.AfterFunc(30*time.Second, func() {
		clearClipboardWindows()
		log.Debug().Msg("clipboard cleared after 30s")
	})
}
