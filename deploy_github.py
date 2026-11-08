#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sub4ch Checker — развёртывание в GitHub (один клик).

Что делает: загружает программу (checker.py, sources.txt, workflow и т.д.)
в репозиторий из config.ini. После этого проверка конфигов выполняется
на серверах GitHub Actions КАЖДЫЕ 2 ЧАСА АВТОМАТИЧЕСКИ — без вашего
компьютера и без Throne.

Токен берётся из config.ini ([github] token) или из переменной окружения
GITHUB_TOKEN. Токену нужно право "Contents: Read and write"
(fine-grained) или scope repo (классический).

Запуск:
    python deploy_github.py

Файл config.ini НЕ загружается — он содержит ваш личный токен
и никогда не должен попадать в публичный репозиторий.
"""

import base64
import configparser
import json
import os
import sys

try:
    import requests
except ImportError:
    print("Не установлен пакет requests. Выполните: pip install -r requirements.txt")
    sys.exit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) sub4ch-checker/2.1"

# Файлы программы, которые публикуются в репозиторий.
# config.ini, out/, bin/ — НЕ публикуются (в config.ini живёт токен).
DEPLOY_FILES = [
    ".gitignore",
    "requirements.txt",
    "sources.txt",
    "checker.py",
    "deploy_github.py",
    "run_checker.bat",
    "run_checker.sh",
    "run_checker_mobile.bat",
    "run_checker_mobile.sh",
    "README.md",
    ".github/workflows/update.yml",
]

TOKEN_HELP = """
Как дать токену право записи:
  1. Откройте github.com -> аватар -> Settings -> Developer settings
     (внизу меню) -> Personal access tokens.
  2. Если токен fine-grained (начинается с github_pat_):
     нажмите на него -> Repository access -> Only select repositories ->
     выберите nikus06123-del/sub4ch -> Permissions -> Repository
     permissions -> "Contents" = "Read and write" -> Update/Save.
     Дополнительно можно "Actions" = "Read and write" (запуск прогона
     кнопкой, без ожидания расписания).
  3. Если удобнее классический токен: Generate new token (classic) ->
     отметьте scope "repo" -> вставьте его в config.ini.
  После изменения прав ПОМЕНЯТЬ ТОКЕН НЕ НУЖНО — тот же токен начнёт работать.
"""


def log(msg, tag="INFO"):
    print(f"[{tag}] {msg}", flush=True)


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    cp = configparser.ConfigParser()
    cfg_path = os.path.join(SCRIPT_DIR, "config.ini")
    if os.path.isfile(cfg_path):
        cp.read(cfg_path, encoding="utf-8-sig")
    token = (os.environ.get("GITHUB_TOKEN")
             or (cp.get("github", "token", fallback="") if cp.has_section("github") else "")
             or "").strip()
    repo = ((cp.get("github", "repo", fallback="") if cp.has_section("github") else "")
            or os.environ.get("GITHUB_REPOSITORY", "") or "nikus06123-del/sub4ch").strip()
    branch = (cp.get("github", "branch", fallback="main")
              if cp.has_section("github") else "main") or "main"

    if not token:
        log("Токен не найден. Впишите его в config.ini -> [github] token", "ERROR")
        print(TOKEN_HELP)
        sys.exit(1)

    api = f"https://api.github.com/repos/{repo}/contents/"
    hdr = {"Authorization": f"Bearer {token}",
           "Accept": "application/vnd.github+json",
           "User-Agent": UA, "X-GitHub-Api-Version": "2022-11-28"}

    # Проверка токена и репозитория
    r = requests.get(f"https://api.github.com/repos/{repo}", headers=hdr, timeout=30)
    if r.status_code == 404:
        log(f"Репозиторий {repo} не найден (или токен без доступа к нему)", "ERROR")
        sys.exit(1)
    if r.status_code != 200:
        log(f"GitHub вернул HTTP {r.status_code}: {r.text[:200]}", "ERROR")
        sys.exit(1)
    vis = "публичный" if not r.json().get("private") else "ПРИВАТНЫЙ"
    log(f"Репозиторий: {repo} ({vis}), ветка {branch}")
    if r.json().get("private"):
        log("ВНИМАНИЕ: приватный репозиторий — Throne не сможет читать подписку "
            "без авторизации. Сделайте его публичным: Settings -> Danger Zone -> "
            "Change visibility -> Public", "WARN")

    missing = [f for f in DEPLOY_FILES if not os.path.isfile(os.path.join(SCRIPT_DIR, f))]
    if missing:
        log("Не найдены файлы: " + ", ".join(missing), "ERROR")
        sys.exit(1)

    ok = 0
    for rel in DEPLOY_FILES:
        local = os.path.join(SCRIPT_DIR, rel)
        with open(local, "rb") as f:
            data = f.read()
        url = api + rel
        r = requests.get(url, headers=hdr, params={"ref": branch}, timeout=30)
        if r.status_code == 403 and "personal access token" in r.text:
            log(f"  ! {rel} — HTTP 403: у токена нет права записи (Contents)", "ERROR")
            print(TOKEN_HELP)
            log(f"Загружено {ok}/{len(DEPLOY_FILES)}. Исправьте права токена и запустите снова.",
                "ERROR")
            sys.exit(1)
        sha = r.json().get("sha") if r.status_code == 200 else None
        if r.status_code == 200:
            try:
                remote = base64.b64decode(r.json().get("content") or "")
                if remote == data:
                    log(f"  = {rel} — без изменений, пропускаю")
                    ok += 1
                    continue
            except Exception:
                pass
        payload = {"message": f"sub4ch checker: deploy {rel}",
                   "branch": branch,
                   "content": base64.b64encode(data).decode("ascii")}
        if sha:
            payload["sha"] = sha
        r = requests.put(url, headers=hdr, data=json.dumps(payload), timeout=60)
        if r.status_code in (200, 201):
            log(f"  + {rel} — загружен")
            ok += 1
        elif r.status_code == 403 and "personal access token" in r.text:
            log(f"  ! {rel} — HTTP 403: у токена нет права записи (Contents)", "ERROR")
            print(TOKEN_HELP)
            log(f"Загружено {ok}/{len(DEPLOY_FILES)}. Исправьте права токена и запустите снова.",
                "ERROR")
            sys.exit(1)
        else:
            log(f"  ! {rel} — HTTP {r.status_code}: {r.text[:200]}", "WARN")

    if ok < len(DEPLOY_FILES):
        log(f"Загружено {ok}/{len(DEPLOY_FILES)} — смотрите предупреждения выше", "WARN")
        sys.exit(1)

    log(f"Готово: программа опубликована в {repo}")
    print()
    print("=== ЧТО ДАЛЬШЕ ===")
    print("1. Откройте вкладку Actions в репозитории (github.com/" + repo + "/actions).")
    print("   Если Actions выключены — нажмите 'I understand my workflows, go ahead")
    print("   and enable them'.")
    print("2. Первый прогон:")
    print("   - либо кнопкой: Actions -> Update VPN subscription -> Run workflow;")
    print("   - либо сам запустится по расписанию (каждые 2 часа, UTC 0/2/4/...).")
    print("3. Через 20-60 минут в репозитории появятся sub.txt / sub_plain.txt / stats.json.")
    print()
    print("Ссылка для Throne (после первого прогона):")
    print(f"  https://raw.githubusercontent.com/{repo}/{branch}/sub.txt")
    print(f"  Зеркало: https://cdn.jsdelivr.net/gh/{repo}@{branch}/sub.txt")
    print()
    print("Проверка теперь идёт на серверах GitHub каждые 2 часа — ваш компьютер")
    print("не нужен. Локальный запуск (run_checker.bat) можно использовать, если")
    print("важно отбирать серверы, живые именно у вашего провайдера.")


if __name__ == "__main__":
    main()
