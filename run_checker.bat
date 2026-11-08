@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === Sub4ch Checker v2.1 ===
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found. Install from https://python.org and check "Add to PATH".
  pause
  exit /b 1
)
rem Зависимости ставятся только если их ещё нет (не тормозит повторные запуски)
python -c "import requests,socks,yaml" >nul 2>nul || python -m pip install -r requirements.txt --quiet --disable-pip-version-check
python checker.py --loop
pause
