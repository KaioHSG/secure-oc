@echo off
rem secure-oc launcher for cmd.exe / PowerShell.
setlocal
set "SCRIPT_DIR=%~dp0"
if defined PYTHONPATH (
    set "PYTHONPATH=%SCRIPT_DIR%;%PYTHONPATH%"
) else (
    set "PYTHONPATH=%SCRIPT_DIR%"
)
where py >nul 2>nul && (py -3 -m secure_oc %* & exit /b %ERRORLEVEL%)
where python >nul 2>nul && (python -m secure_oc %* & exit /b %ERRORLEVEL%)
echo secure-oc: Python not found in PATH 1>&2
exit /b 1
