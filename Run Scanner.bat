@echo off
rem Opens the Bagel window.
rem Order: Python Launcher (pyw -3), then pythonw on PATH, then a per-user install.
setlocal
set "APP=%~dp0GameSafetyScanner.pyw"

where pyw >nul 2>nul
if not errorlevel 1 (
    start "" pyw -3 "%APP%" %*
    exit /b 0
)

rem Skip the Microsoft Store placeholder in WindowsApps: it is not a real Python.
for /f "delims=" %%P in ('where pythonw 2^>nul') do (
    echo %%P | find /i "WindowsApps" >nul
    if errorlevel 1 (
        start "" "%%P" "%APP%" %*
        exit /b 0
    )
)

for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if exist "%%D\pythonw.exe" (
        start "" "%%D\pythonw.exe" "%APP%" %*
        exit /b 0
    )
)

echo Python was not found on this computer.
echo Install Python 3.9 or newer from https://www.python.org/downloads/
echo and tick "Add python.exe to PATH" during setup. Then run this file again.
pause
exit /b 1
