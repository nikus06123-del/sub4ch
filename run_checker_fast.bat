@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === Sub4ch Checker — БЫСТРЫЙ режим (3-5 минут на прогон) ===
echo.
echo Идея: проверяется случайная выборка 8000 конфигов вместо всех
echo (130 тыс.) + укороченные таймауты + повышенные потоки под мощный ПК.
echo Живых серверов всё равно хватает на обе подписки.
echo.
echo Настройки рассчитаны на 16 ГБ ОЗУ. Если меньше — run_checker.bat
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
rem выборка 10000 конфигов на прогон (вместо всех 130 тыс.)
set CHECKER_MAX_RUN=10000
rem в полную подписку — 3000 самых быстрых, в мобильную — 200
set CHECKER_MAX_RESULTS=3000
set CHECKER_MOBILE_LIMIT=200

rem Таймауты 3/5 сек — «полуживые» серверы отсеются, зато максимально быстро
set CHECKER_TCP_TIMEOUT=3
set CHECKER_CORE_TIMEOUT=5

rem Потоки под 16 ГБ ОЗУ: TCP 3000 соединений, ядро 300 процессов
rem (~6 ГБ ОЗУ в пике — для 16 ГБ неощутимо). На 8 ГБ поставьте 150.
python checker.py --tcp-concurrency 3000 --core-concurrency 300 %*
pause
