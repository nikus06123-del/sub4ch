#!/usr/bin/env bash
# ============================================================================
#  Sub4ch Checker v2.2 — установка на VPS одной командой (Ubuntu 22.04+/Debian 12)
#
#  Полная замена GitHub Actions: проверка по cron каждые 2 часа прямо на VPS.
#  Оплата российскими картами (Timeweb, Beget, Selectel, REG.RU, Yandex Cloud...).
#  Подойдёт самый дешёвый тариф: 1 CPU / 1-2 ГБ RAM.
#
#  Использование (на чистом VPS от root):
#    1) git clone https://github.com/nikus06123-del/sub4ch /opt/sub4ch-checker
#       cd /opt/sub4ch-checker && bash install_vps.sh
#    2) Токен передайте переменной окружения или введите по запросу:
#       GITHUB_TOKEN=github_pat_.... bash install_vps.sh
#
#  Опции:
#    --web      поднять nginx и раздавать подписку прямо с VPS:
#               Throne будет читать http://ВАШ_IP/sub.txt без GitHub
#    --no-github  не публиковать на GitHub вообще (нужен --web)
# ============================================================================

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
WITH_WEB=0; WITH_GH=1
for a in "$@"; do
  case "$a" in
    --web) WITH_WEB=1 ;;
    --no-github) WITH_GH=0 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "Запустите от root: sudo bash install_vps.sh"; exit 1; }

echo "=== Sub4ch Checker: установка на VPS ==="

# --- 1. Системные пакеты ---
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv git cron >/dev/null
[ "$WITH_WEB" = 1 ] && apt-get install -y -qq nginx >/dev/null

# --- 2. Python-окружение ---
python3 -m venv "$DIR/venv"
"$DIR/venv/bin/pip" install -q -r "$DIR/requirements.txt"

# --- 3. config.ini из шаблона ---
if [ ! -f "$DIR/config.ini" ]; then
  cp "$DIR/config.ini.example" "$DIR/config.ini"
fi
# Лимиты под слабый VPS: меньше потоков и ОЗУ
sed -i 's/^tcp_concurrency = .*/tcp_concurrency = 500/'  "$DIR/config.ini"
sed -i 's/^core_concurrency = .*/core_concurrency = 30/' "$DIR/config.ini"
sed -i 's/^max_results = .*/max_results = 3000/'         "$DIR/config.ini"
sed -i 's/^mobile_limit = .*/mobile_limit = 200/'        "$DIR/config.ini"

# --- 4. Токен GitHub ---
if [ "$WITH_GH" = 1 ]; then
  TOKEN="${GITHUB_TOKEN:-}"
  if [ -z "$TOKEN" ]; then
    read -r -p "GitHub-токен (Contents: Read and write), Enter чтобы пропустить: " TOKEN || true
  fi
  if [ -n "$TOKEN" ]; then
    sed -i "s#^token = .*#token = $TOKEN#" "$DIR/config.ini"
    echo "Токен сохранён в config.ini"
  else
    echo "ВНИМАНИЕ: токен не задан — на GitHub публиковаться не будет"
    sed -i 's#^token = .*#token =#' "$DIR/config.ini"
  fi
else
  sed -i 's#^token = .*#token =#' "$DIR/config.ini"
fi

# --- 5. Папка подписки + nginx ---
if [ "$WITH_WEB" = 1 ]; then
  mkdir -p /var/www/sub4ch
  sed -i "s#^out_dir = .*#out_dir = /var/www/sub4ch#" "$DIR/config.ini"
  cat > /etc/nginx/sites-available/sub4ch <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/sub4ch;
    autoindex off;
    add_header Cache-Control "no-cache";
}
EOF
  rm -f /etc/nginx/sites-enabled/default
  ln -sf /etc/nginx/sites-available/sub4ch /etc/nginx/sites-enabled/sub4ch
  nginx -t 2>/dev/null && systemctl reload nginx && echo "nginx: подписка будет доступна на http://$(hostname -I | awk '{print $1}')/sub.txt"
fi

# --- 6. Cron: каждые 2 часа ---
# Пакетный режим v2.3 в щадящих лимитах под VPS 1-2 ГБ ОЗУ:
# 2 ядра × 100 конфигов = 200 проверок одновременно
CRON_LINE="0 */2 * * * cd $DIR && CHECKER_MAX_RUN=0 CHECKER_BATCH=1 CHECKER_BATCH_SIZE=100 CHECKER_BATCH_PARALLEL=2 CHECKER_TCP_TIMEOUT=3 CHECKER_CORE_TIMEOUT=5 $DIR/venv/bin/python checker.py --tcp-concurrency 1500 >> $DIR/checker.log 2>&1"
( crontab -l 2>/dev/null | grep -v sub4ch-checker ; echo "$CRON_LINE # sub4ch-checker" ) | crontab -
echo "Cron установлен: проверка каждые 2 часа (лог: $DIR/checker.log)"

# --- 7. Первый прогон сейчас ---
echo "Запускаю первый прогон (5-15 минут)..."
cd "$DIR"
CHECKER_MAX_RUN=0 CHECKER_BATCH=1 CHECKER_BATCH_SIZE=100 CHECKER_BATCH_PARALLEL=2 \
CHECKER_TCP_TIMEOUT=3 CHECKER_CORE_TIMEOUT=5 \
venv/bin/python checker.py --tcp-concurrency 1500 >> checker.log 2>&1 || true
tail -n 3 checker.log

echo
echo "=== Готово ==="
[ "$WITH_WEB" = 1 ] && echo "Throne (с VPS):  http://$(hostname -I | awk '{print $1}')/sub.txt  и  /sub_mobile.txt"
[ "$WITH_GH" = 1 ] && echo "Throne (GitHub): https://raw.githubusercontent.com/nikus06123-del/sub4ch/main/sub.txt"
echo "Лог: tail -f $DIR/checker.log"
