@echo off
REM Start the local PostgreSQL 16 cluster used by this project.
REM The instance is a user-space install, so it is not a Windows service and does
REM not start by itself. Run this once per session (or let the logon task do it).
setlocal
set "PGBIN=%LOCALAPPDATA%\Programs\PostgreSQL\16\bin"
set "PGDATA_DIR=%LOCALAPPDATA%\PostgreSQL\data16"

if not exist "%PGBIN%\pg_ctl.exe" (
  echo PostgreSQL binaries not found at "%PGBIN%".
  exit /b 1
)

"%PGBIN%\pg_ctl.exe" -D "%PGDATA_DIR%" -l "%PGDATA_DIR%\server.log" -o "-p 5432" -w start
if errorlevel 1 (
  echo.
  echo Failed to start. Last lines of server.log:
  powershell -NoProfile -Command "Get-Content -Tail 15 '%PGDATA_DIR%\server.log'"
  exit /b 1
)
exit /b 0
