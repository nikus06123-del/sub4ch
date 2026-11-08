@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === Sub4ch Checker v2.3 — быстрый режим (выборка 10 000, ~2-4 минуты) ===
echo.
echo Проверяется случайная выборка 10 000 конфигов вместо всех + пачечный
echo режим ядра. Удобно, чтобы быстро освежить подписку или проверить,
echo что всё работает. Полная проверка всех конфигов — run_checker.bat
echo.
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found. Install from https://python.org and check "Add to PATH".
  pause
  exit /b 1
)
rem Зависимости ставятся только если их ещё нет (не тормозит повторные запуски)
python -c "import requests,socks,yaml" >nul 2>nul || python -m pip install -r requirements.txt --quiet --disable-pip-version-check

rem --- Быстрые настройки (под ПК 16 ГБ ОЗУ / гигабит) ---
rem выборка 10 000 конфигов на прогон (0 = проверять все)
set CHECKER_MAX_RUN=10000
rem в полную подписку — 3000 самых быстрых, в мобильную — 200
set CHECKER_MAX_RESULTS=3000
set CHECKER_MOBILE_LIMIT=200

rem Таймауты 3/4 сек — «полуживые» серверы отсеются, зато максимально быстро
set CHECKER_TCP_TIMEOUT=3
set CHECKER_CORE_TIMEOUT=4

rem Пакетный режим v2.3: пачка 200 конфигов в одном ядре, 4 ядра сразу
set CHECKER_BATCH=1
set CHECKER_BATCH_SIZE=200
set CHECKER_BATCH_PARALLEL=4

rem TCP: 4000 одновременных соединений
python checker.py --tcp-concurrency 4000 %*
pause
