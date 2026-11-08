#!/usr/bin/env bash
# Sub4ch Checker v2.1 — проверка через МОБИЛЬНЫЙ интернет прямо на телефоне.
# Работает в Termux на Android. Termux ставьте с F-Droid:
#   https://f-droid.org/packages/com.termux/
# (версия из Google Play устарела и не поддерживается).
#
# Быстрый старт в Termux:
#   pkg update -y && pkg install -y git
#   git clone https://github.com/nikus06123-del/sub4ch checker
#   cd checker
#   bash run_checker_mobile.sh
#
# Публикация в репозиторий: перед запуском выполните
#   export GITHUB_TOKEN=ваш_токен          (право Contents: Read and write)
# или впишите токен в config.ini ([github] token).
# Без токена проверка тоже работает — подписка останется в out/sub.txt,
# её можно открыть в клиенте на том же телефоне как локальный файл.

cd "$(dirname "$0")" || exit 1

# --- Зависимости: в Termux берём из репозитория Termux (быстро, без сборки) ---
if command -v pkg >/dev/null 2>&1; then
  pkg update -y >/dev/null 2>&1 || true
  pkg install -y python git python-requests python-pyyaml >/dev/null 2>&1 || true
  pip install --quiet pysocks 2>/dev/null || pip install --quiet -r requirements.txt 2>/dev/null || true
else
  # Обычный Linux (не Termux)
  python3 -m pip install -r requirements.txt --quiet --disable-pip-version-check
fi

# --- Android не должен усыплять телефон посреди проверки ---
command -v termux-wake-lock   >/dev/null 2>&1 && termux-wake-lock

# --- Мобильные лимиты: экономим трафик и батарею ---
export CHECKER_MAX_RUN=6000      # случайная выборка 6000 конфигов вместо всех
export CHECKER_MAX_RESULTS=500   # в подписку — 500 самых быстрых

# Один прогон и выход. Регулярно (каждые 6 часов):
#   bash run_checker_mobile.sh --loop --interval 6
python3 checker.py --tcp-concurrency 300 --core-concurrency 25 "$@"

command -v termux-wake-unlock >/dev/null 2>&1 && termux-wake-unlock
