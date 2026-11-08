@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === Sub4ch Checker v2.3 — ПОЛНАЯ проверка: ВСЕ конфиги за ~5-10 минут ===
echo.
echo Пакетный режим v2.3: одно ядро Xray проверяет сразу 200 конфигов,
echo 6 ядер держат 1200 проверок одновременно. Выборок НЕТ — проверяются
echo все конфиги из всех источников (раньше это занимало около часа).
echo Настройки под ПК: 16 ГБ ОЗУ, гигабитный интернет.
echo.
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found. Install from https://python.org and check "Add to PATH".
  pause
  exit /b 1
)
rem Зависимости ставятся только если их ещё нет (не тормозит повторные запуски)
python -c "import requests,socks,yaml" >nul 2>nul || python -m pip install -r requirements.txt --quiet --disable-pip-version-check

rem --- Полный прогон: БЕЗ выборок (0 = проверять все) ---
set CHECKER_MAX_RUN=0
rem В подписку — 3000 самых быстрых, в мобильную — топ-200
set CHECKER_MAX_RESULTS=3000
set CHECKER_MOBILE_LIMIT=200

rem Таймауты: 3 с на TCP-коннект, 4 с на проверку через ядро
set CHECKER_TCP_TIMEOUT=3
set CHECKER_CORE_TIMEOUT=4

rem Пакетный режим (главное ускорение v2.3):
rem пачка 200 конфигов в одном ядре, 6 ядер одновременно = 1200 в полёте
set CHECKER_BATCH=1
set CHECKER_BATCH_SIZE=200
set CHECKER_BATCH_PARALLEL=6

rem Ступень 1: 6000 одновременных TCP-соединений (под гигабит)
python checker.py --tcp-concurrency 6000 %*
pause
