; offveil NSIS hooks — service + TUN lifecycle.
; Tauri only closes the UI process; offveil-core is a Windows service.

!macro NSIS_HOOK_PREINSTALL
  DetailPrint "offveil: stopping offveil-core before file copy"
  nsExec::ExecToLog 'sc.exe stop offveil-core'
  ; Legacy SCM name from earlier betas.
  nsExec::ExecToLog 'sc.exe stop OffveilCore'
  Sleep 2000
  IfFileExists "$INSTDIR\offveil-core.exe" 0 preinstall_no_core
    nsExec::ExecToLog '"$INSTDIR\offveil-core.exe" stop'
    Sleep 1500
  preinstall_no_core:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "offveil: registering offveil-core (StartType=manual, do not auto-start)"
  ; Drop the pre-rename service so upgrades do not leave two SCM entries.
  nsExec::ExecToLog 'sc.exe stop OffveilCore'
  nsExec::ExecToLog 'sc.exe delete OffveilCore'
  ; Refresh image path on upgrade; ignore errors if already absent.
  nsExec::ExecToLog '"$INSTDIR\offveil-core.exe" uninstall'
  nsExec::ExecToLog '"$INSTDIR\offveil-core.exe" install'
  ; AU may StartService without UAC so login auto-connect can bring the demand-start
  ; service up. Same trust model as the named pipe (Authenticated Users → SYSTEM).
  nsExec::ExecToLog "sc.exe sdset offveil-core $\"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;AU)$\""
  ; Quoted path is required — unquoted Program Files paths never launch.
  ; HKCU so the installing user gets autostart without a second instance from HKLM.
  DetailPrint "offveil: enable start on login (default on, skip if user opted out)"
  IfFileExists "$APPDATA\com.offveil.app\autostart-disabled" postinstall_disable_autostart
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "offveil" '"$INSTDIR\${MAINBINARYNAME}.exe" --tray'
    WriteRegBin HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "offveil" 020000000000000000000000
    Goto postinstall_autostart_done
  postinstall_disable_autostart:
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "offveil"
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "offveil"
  postinstall_autostart_done:
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "offveil-ui"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "offveil-ui"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "offveil: TUN teardown + service remove"
  IfFileExists "$INSTDIR\offveil-core.exe" 0 preuninstall_no_core
    nsExec::ExecToLog '"$INSTDIR\offveil-core.exe" stop'
    Sleep 1500
    nsExec::ExecToLog '"$INSTDIR\offveil-core.exe" uninstall'
  preuninstall_no_core:
  nsExec::ExecToLog 'sc.exe stop offveil-core'
  nsExec::ExecToLog 'sc.exe delete offveil-core'
  nsExec::ExecToLog 'sc.exe stop OffveilCore'
  nsExec::ExecToLog 'sc.exe delete OffveilCore'
  Sleep 500
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DetailPrint "offveil: removing login autostart"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "offveil"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "offveil-ui"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "offveil"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "offveil-ui"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "offveil"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "offveil-ui"
  DetailPrint "offveil: removing %ProgramData%\offveil"
  ReadEnvStr $0 ProgramData
  StrCmp $0 "" postuninstall_done
  IfFileExists "$0\offveil" 0 postuninstall_legacy
    RMDir /r "$0\offveil"
  postuninstall_legacy:
  IfFileExists "$0\Offveil" 0 postuninstall_done
    RMDir /r "$0\Offveil"
  postuninstall_done:
!macroend
