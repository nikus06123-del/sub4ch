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

rem Защита от часового прогона: если конфигов больше 30 тыс. — проверяется
rem случайная выборка. Живых всё равно хватает на обе подписки.
rem Хотите проверить ВСЁ до конца — удалите следующую строку.
set CHECKER_MAX_RUN=30000
rem В подписку — 3000 самых быстрых, в мобильную — топ-200
set CHECKER_MAX_RESULTS=3000
set CHECKER_MOBILE_LIMIT=200

python checker.py --loop
pause
