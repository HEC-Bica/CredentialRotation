@echo off
rem Start-CredentialRotation.cmd - launcher for CredentialRotation.ps1 (docs/PLAN.md section 3)
rem
rem Run elevated ("Run as administrator") from C:\temp\CredentialRotation-<version>\ :
rem   Start-CredentialRotation.cmd [/PS2] [-Apply] [-Only <slot>[,<slot>...]]
rem
rem   /PS2  first argument only: run on the PowerShell 2.0 engine (-Version 2).
rem   All other arguments are passed unchanged to CredentialRotation.ps1.
rem
rem NEVER put a password or any other secret on this command line (D4). The tool prompts for them.
rem
rem Exit code: the exit code of CredentialRotation.ps1, or 2 if the launcher cannot start it.
rem Every program is called by its absolute path, because cmd searches the current folder first.

setlocal EnableExtensions DisableDelayedExpansion

rem A 32-bit cmd.exe on 64-bit Windows sees SysWOW64 as System32; sysnative is the 64-bit folder.
set "CR_SYS=%SystemRoot%\System32"
if defined PROCESSOR_ARCHITEW6432 if exist "%SystemRoot%\sysnative\cmd.exe" set "CR_SYS=%SystemRoot%\sysnative"
set "CR_PS=%CR_SYS%\WindowsPowerShell\v1.0\powershell.exe"
set "CR_SCRIPT=%~dp0CredentialRotation.ps1"

if not exist "%CR_PS%" goto :no_powershell
if not exist "%CR_SCRIPT%" goto :no_script

rem Elevation check: fltmc.exe fails without administrator rights.
"%CR_SYS%\fltmc.exe" >nul 2>&1
if errorlevel 1 goto :not_elevated

rem /PS2 (first argument) selects the PowerShell 2.0 engine and is not passed on.
set "CR_VERSION="
set "CR_ARGS=%*"
if /i not "%~1"=="/PS2" goto :policy
set "CR_VERSION=-Version 2"
set "CR_ARGS=%CR_ARGS:*/PS2=%"

:policy
rem A Group Policy execution policy (MachinePolicy/UserPolicy scope) overrides -ExecutionPolicy Bypass.
set "CR_BLOCKED="
call :check_policy "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "computer (MachinePolicy)"
call :check_policy "HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "user (UserPolicy)"
if defined CR_BLOCKED goto :policy_blocked

if defined CR_VERSION echo Starting CredentialRotation.ps1 on the PowerShell 2.0 engine (/PS2).
"%CR_PS%" %CR_VERSION% -NoProfile -ExecutionPolicy Bypass -File "%CR_SCRIPT%" %CR_ARGS%
exit /b %ERRORLEVEL%

rem ---------------------------------------------------------------------------
rem :check_policy <registry key> <scope text>
rem Reads the Group Policy values ExecutionPolicy (REG_SZ) and EnableScripts (REG_DWORD),
rem explains their effect and sets CR_BLOCKED when PowerShell will refuse the unsigned tool.
:check_policy
set "CR_EP="
set "CR_ES="
for /f "tokens=2,*" %%A in ('%CR_SYS%\reg.exe query "%~1" /v ExecutionPolicy 2^>nul') do if /i "%%A"=="REG_SZ" set "CR_EP=%%B"
for /f "tokens=2,*" %%A in ('%CR_SYS%\reg.exe query "%~1" /v EnableScripts 2^>nul') do if /i "%%A"=="REG_DWORD" set "CR_ES=%%B"
if not defined CR_EP if not defined CR_ES exit /b 0
if "%CR_ES%"=="0x0" set "CR_EP=Restricted"
if not defined CR_EP exit /b 0
echo.
echo NOTE: Group Policy sets the PowerShell execution policy for the %~2 scope to "%CR_EP%".
echo       A Group Policy execution policy takes precedence over "-ExecutionPolicy Bypass" used by this launcher.
echo       Group Policy setting: Administrative Templates - Windows Components - Windows PowerShell - Turn on Script Execution
echo       in the Computer or User Configuration, local policy: gpedit.msc
if /i "%CR_EP%"=="Restricted" goto :policy_refuses
if /i "%CR_EP%"=="AllSigned" goto :policy_refuses
if /i "%CR_EP%"=="RemoteSigned" echo       RemoteSigned: the tool runs only if its files are not marked as downloaded from the Internet. If PowerShell refuses, open the file properties of the copied files and click "Unblock".
if /i "%CR_EP%"=="Unrestricted" echo       Unrestricted: PowerShell may ask for confirmation if the files are marked as downloaded from the Internet.
echo.
exit /b 0
:policy_refuses
echo       "%CR_EP%": PowerShell will refuse to run the tool because it is not signed.
echo       Have the policy set to "Allow all scripts" or "Not Configured" for this run, then start the launcher again.
echo.
set "CR_BLOCKED=1"
exit /b 0

rem ---------------------------------------------------------------------------
:policy_blocked
echo ERROR: CredentialRotation.ps1 was not started because of the Group Policy execution policy above.
goto :fail

:no_powershell
echo ERROR: Windows PowerShell was not found: "%CR_PS%"
goto :fail

:no_script
echo ERROR: CredentialRotation.ps1 was not found next to this launcher: "%CR_SCRIPT%"
goto :fail

:not_elevated
echo ERROR: This launcher must run elevated.
echo        Right-click Start-CredentialRotation.cmd and choose "Run as administrator",
echo        or start it from an elevated command prompt.
goto :fail

:fail
rem Keeps a window opened with "Run as administrator" readable; returns at once when input is redirected.
pause
exit /b 2
