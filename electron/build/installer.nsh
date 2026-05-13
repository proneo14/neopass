; Custom NSIS installer script for NeoPass
; Runs native messaging host registration after install

!macro customInstall
  ; Register native messaging host for Chrome, Edge, and Firefox
  ; Chrome and Edge share the same extension ID (derived from the manifest key)
  DetailPrint "Registering native messaging host..."
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\scripts\install-native-host.ps1" -BinaryPath "$INSTDIR\resources\bin\neopass-native-host.exe" -ChromeExtensionID "eiaibopmeinjkngnlodpmpfllbfbpgpc" -EdgeExtensionID "eiaibopmeinjkngnlodpmpfllbfbpgpc"'
!macroend

!macro customUnInstall
  ; Clean up native messaging host registry entries
  DetailPrint "Removing native messaging host registration..."
  DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\com.quantum.passwordmanager"
  DeleteRegKey HKCU "Software\Microsoft\Edge\NativeMessagingHosts\com.quantum.passwordmanager"
  DeleteRegKey HKCU "Software\Mozilla\NativeMessagingHosts\com.quantum.passwordmanager"
!macroend
