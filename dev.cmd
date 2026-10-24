@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0dev.ps1" %*
set "EXITCODE=%ERRORLEVEL%"
if not "%EXITCODE%"=="0" (
  echo.
  echo [dev] Startup failed with exit code %EXITCODE%. See the error above.
  echo If the port is already in use, run: dev.cmd -Restart
  pause >nul
)
exit /b %EXITCODE%
