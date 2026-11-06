@echo off
REM Stop the local PostgreSQL 16 cluster used by this project.
setlocal
set "PGBIN=%LOCALAPPDATA%\Programs\PostgreSQL\16\bin"
set "PGDATA_DIR=%LOCALAPPDATA%\PostgreSQL\data16"

"%PGBIN%\pg_ctl.exe" -D "%PGDATA_DIR%" -m fast -w stop
