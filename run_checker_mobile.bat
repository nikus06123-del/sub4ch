@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === Sub4ch Checker — проверка через МОБИЛЬНЫЙ интернет ===
echo.
echo Перед запуском:
echo  1. Телефон раздаёт интернет (точка доступа Wi-Fi или USB-модем).
echo  2. На телефоне ВЫКЛЮЧЕН Wi-Fi — раздаётся именно мобильная сеть.
echo  3. ПК подключён только к этой точке доступа.
echo.
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found. Install from https://python.org and check "Add to PATH".
  pause
  exit /b 1
)
python -m pip install -r requirements.txt --quiet --disable-pip-version-check

rem --- Мобильные лимиты: экономим трафик и щадим сеть ---
rem проверять не все конфиги (это сотни МБ), а случайную выборку
set CHECKER_MAX_RUN=10000
rem в подписку — только 500 самых быстрых
set CHECKER_MAX_RESULTS=500

rem Один прогон и выход. Для регулярной проверки добавьте аргументы:
rem   run_checker_mobile.bat --loop --interval 6   (каждые 6 часов)
python checker.py --tcp-concurrency 500 --core-concurrency 50 %*
pause
