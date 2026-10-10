@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Missing .venv. Follow the installation instructions in README.md first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m ato.cli observe
if errorlevel 1 pause
endlocal
