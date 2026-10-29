; AvScanner NSIS Installer Script
!include "MUI2.nsh"

;--------------------------------
; General
;--------------------------------
Name "AvScanner"
OutFile "AvScanner-Setup.exe"
InstallDir "$PROGRAMFILES\AvScanner"
InstallDirRegKey HKCU "Software\AvScanner" ""
RequestExecutionLevel admin

;--------------------------------
; Interface Settings
;--------------------------------
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

;--------------------------------
; Pages
;--------------------------------
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

;--------------------------------
; Languages
;--------------------------------
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Russian"

;--------------------------------
; Installer Sections
;--------------------------------
Section "MainSection" SEC01
    SetOutPath "$INSTDIR"

    ; Main executable
    File "..\av-gui\dist\av-gui.exe"

    ; Create uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    ; Registry entries
    WriteRegStr HKCU "Software\AvScanner" "" $INSTDIR
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AvScanner" "DisplayName" "AvScanner"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AvScanner" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AvScanner" "DisplayVersion" "0.1.0"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AvScanner" "Publisher" "AvScanner Project"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AvScanner" "DisplayIcon" "$INSTDIR\av-gui.exe"

    ; Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\AvScanner"
    CreateShortcut "$SMPROGRAMS\AvScanner\AvScanner.lnk" "$INSTDIR\av-gui.exe"
    CreateShortcut "$SMPROGRAMS\AvScanner\Uninstall.lnk" "$INSTDIR\uninstall.exe"

    ; Desktop shortcut
    CreateShortcut "$DESKTOP\AvScanner.lnk" "$INSTDIR\av-gui.exe"
SectionEnd

;--------------------------------
; Uninstaller
;--------------------------------
Section "Uninstall"
    Delete "$INSTDIR\av-gui.exe"
    Delete "$INSTDIR\uninstall.exe"

    Delete "$SMPROGRAMS\AvScanner\AvScanner.lnk"
    Delete "$SMPROGRAMS\AvScanner\Uninstall.lnk"
    RMDir "$SMPROGRAMS\AvScanner"

    Delete "$DESKTOP\AvScanner.lnk"

    DeleteRegKey HKCU "Software\AvScanner"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AvScanner"

    RMDir "$INSTDIR"
SectionEnd