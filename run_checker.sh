#!/usr/bin/env bash
# Sub4ch Checker v2.1 — запуск в цикле (Linux / macOS)
cd "$(dirname "$0")"
python3 -m pip install -r requirements.txt --quiet --disable-pip-version-check
python3 checker.py --loop
