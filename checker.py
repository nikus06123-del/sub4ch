#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sub4ch Checker — агрегатор и живой фильтр бесплатных VPN-конфигов для Throne.

Как работает:
  1. Скачивает списки подписок из sources.txt (plain / base64 / Clash YAML,
     автоопределение) + динамический список источников (обновляется сообществом).
  2. Парсит vless / vmess / trojan / ss / hysteria2 / tuic, дедуплицирует,
     ограничивает число конфигов на один адрес (IP:порт).
  3. Ступень 1: асинхронный TCP-фильтр — отсекает адреса с закрытым портом
     (результат кешируется на адрес: соединение открываем один раз).
  4. Ступень 2: реальная проверка через ядра Xray (vless/vmess/trojan/ss) и
     sing-box (hysteria2/tuic) ПАЧКАМИ: один процесс ядра держит сразу ~200
     локальных прокси-портов, каждый порт направляется через свой сервер,
     через сервер делается HTTP-запрос на 204-URL. Живут только те, кто
     реально отвечает. Если ядро отклоняет пачку — автоматический откат
     на одиночную проверку. Без Throne и без VPN-клиентов — свои ядра.
  5. Живые конфиги сортируются по времени отклика и публикуются:
     - локально: out/sub.txt (base64) и out/sub_plain.txt
     - в GitHub-репозиторий через Contents API (sub.txt + sub_plain.txt + stats.json)

Запуск:
  python checker.py             один цикл
  python checker.py --loop      бесконечно, интервал из config.ini (по умолчанию 2 ч)
  GitHub Actions                автономный режим без ПК (см. .github/workflows/update.yml)

Подробности и настройка: README.md
"""

import argparse
import asyncio
import base64
import binascii
import configparser
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from itertools import islice

try:
    import yaml  # PyYAML — для источников в формате Clash/mihomo YAML
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

try:
    import requests
except ImportError:
    print("Не установлен пакет requests. Выполните: pip install -r requirements.txt")
    sys.exit(1)

IS_WIN = platform.system() == "Windows"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) sub4ch-checker/2.3"
VERSION = "2.3"

# Динамический список источников (обновляется сообществом; можно отключить в config.ini)
DYNAMIC_URL_DEFAULT = (
    "https://raw.githubusercontent.com/mehdirzfx/v2ray-sub/main/README.md")

SUPPORTED_SCHEMES = ("vless", "vmess", "trojan", "ss", "hysteria2", "tuic")
TCP_SCHEMES = {"vless", "vmess", "trojan", "ss"}
UDP_SCHEMES = {"hysteria2", "tuic"}
DEFAULT_TEST_URLS = "http://cp.cloudflare.com/generate_204,http://www.gstatic.com/generate_204"

URI_RE = re.compile(
    r"(?:vless|vmess|trojan|hysteria2|hysteria|hy2|tuic|ssr|ss)://[^\s<>\"'`\\]+", re.I)
URI_TRAIL = ".,;:!?)]}>\"'`"

BAD_HOSTS = {"localhost", "0.0.0.0", "::1", ""}

XRAY_ASSETS = {
    ("windows", "amd64"): "Xray-windows-64.zip",
    ("windows", "386"): "Xray-windows-32.zip",
    ("windows", "arm64"): "Xray-windows-arm64-v8a.zip",
    ("linux", "amd64"): "Xray-linux-64.zip",
    ("linux", "386"): "Xray-linux-32.zip",
    ("linux", "arm64"): "Xray-linux-arm64-v8a.zip",
    ("darwin", "amd64"): "Xray-macos-64.zip",
    ("darwin", "arm64"): "Xray-macos-arm64-v8a.zip",
}


# ----------------------------------------------------------------- утилиты --

def log(msg, tag="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    try:
        print(f"[{ts}] [{tag}] {msg}", flush=True)
    except Exception:
        print(f"[{ts}] [{tag}] {msg.encode('ascii', 'replace').decode()}", flush=True)


def truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes")


def int_try(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def b64_try_decode(s):
    """Пробует декодировать base64 (обычный и urlsafe, с паддингом или без)."""
    s2 = re.sub(r"\s+", "", s)
    if not s2 or len(s2) % 4 == 1:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/_=-]+", s2):
        return None
    pad = s2 + "=" * (-len(s2) % 4)
    try:
        out = base64.urlsafe_b64decode(pad.encode("ascii"))
        return out or None
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None


def is_ip_literal(h):
    if ":" in h:  # IPv6
        return True
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", h))


def split_hostport(s):
    s = (s or "").strip()
    if s.startswith("["):
        if "]" not in s:
            return "", None
        host = s[1:s.index("]")]
        rest = s[s.index("]") + 1:]
        return host, int_try(rest[1:]) if rest.startswith(":") else None
    if ":" in s:
        h, _, p = s.rpartition(":")
        return h, int_try(p)
    return s, None


def short_url(u):
    u = u.replace("https://raw.githubusercontent.com/", "")
    return u if len(u) <= 72 else u[:50] + "..." + u[-19:]


def setup_console():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def raise_nofile():
    if IS_WIN:
        return
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(65535, hard), hard))
    except Exception:
        pass


# ------------------------------------------------------------- парсинг URI --

def build_uri(p):
    """Канонический URI конфига (для вывода в подписку)."""
    s = p["scheme"]
    host = p["host"]
    port = p["port"]
    tag = urllib.parse.quote(p.get("tag") or "", safe="")

    if s == "vmess":
        net = "h2" if p.get("net") == "http" else p.get("net", "tcp")
        d = {"v": "2", "ps": p.get("tag") or "", "add": host, "port": str(port),
             "id": p.get("uuid", ""), "aid": str(int(p.get("aid") or 0)),
             "scy": p.get("scy") or "auto", "net": net,
             "type": p.get("headerType", "") or "", "host": p.get("hosth", "") or "",
             "path": p.get("path", "") or "",
             "tls": "tls" if p.get("security") == "tls" else "",
             "sni": p.get("sni", "") or "", "alpn": p.get("alpn", "") or "",
             "fp": p.get("fp", "") or ""}
        payload = json.dumps(d, ensure_ascii=False, separators=(",", ":"))
        return "vmess://" + base64.b64encode(payload.encode("utf-8")).decode("ascii")

    q = []

    def add(k, v):
        if v not in (None, "", False):
            q.append((k, str(v)))

    if s in ("vless", "trojan", "vmess"):
        if s == "vless":
            add("encryption", "none")
            add("security", p.get("security"))
            add("sni", p.get("sni"))
            add("fp", p.get("fp"))
            add("pbk", p.get("pbk"))
            add("sid", p.get("sid"))
            add("spx", p.get("spx"))
            add("flow", p.get("flow"))
        else:
            add("security", p.get("security"))
            add("sni", p.get("sni"))
            add("fp", p.get("fp"))
        add("alpn", p.get("alpn"))
        add("type", p.get("net") or "tcp")
        net = p.get("net") or "tcp"
        if net in ("ws", "httpupgrade", "xhttp"):
            add("path", p.get("path"))
            add("host", p.get("hosth"))
            if net == "xhttp":
                add("mode", p.get("mode"))
        elif net == "grpc":
            add("serviceName", p.get("serviceName"))
        elif net == "tcp" and p.get("headerType"):
            add("headerType", p["headerType"])
            add("path", p.get("path"))
            add("host", p.get("hosth"))
        if p.get("insecure"):
            add("allowInsecure", "1")
        user = urllib.parse.quote(p.get("uuid") or p.get("password") or "", safe="")
        return f"{s}://{user}@{host}:{port}?{urllib.parse.urlencode(q)}#{tag}"

    if s == "ss":
        userinfo = base64.urlsafe_b64encode(
            f"{p.get('method', '')}:{p.get('password', '')}".encode("utf-8")
        ).decode("ascii").rstrip("=")
        plug = ""
        if p.get("plugin"):
            plug = "?" + urllib.parse.urlencode({"plugin": p["plugin"]})
        return f"ss://{userinfo}@{host}:{port}{plug}#{tag}"

    if s == "hysteria2":
        add("sni", p.get("sni"))
        if p.get("insecure"):
            add("insecure", "1")
        add("obfs", p.get("obfs"))
        add("obfs-password", p.get("obfs_password"))
        auth = urllib.parse.quote(p.get("auth") or "", safe="")
        return f"hysteria2://{auth}@{host}:{port}?{urllib.parse.urlencode(q)}#{tag}"

    if s == "tuic":
        add("congestion_control", p.get("cc"))
        add("sni", p.get("sni"))
        add("alpn", p.get("alpn"))
        if p.get("insecure"):
            add("allow_insecure", "1")
        return (f"tuic://{urllib.parse.quote(p.get('uuid') or '', safe='')}:"
                f"{urllib.parse.quote(p.get('password') or '', safe='')}"
                f"@{host}:{port}?{urllib.parse.urlencode(q)}#{tag}")

    raise ValueError("unsupported scheme: " + s)


def normalize_item(p):
    host = (p.get("host") or "").strip().strip("[]").lower()
    port = int_try(p.get("port"))
    if not host or host in BAD_HOSTS or host.startswith("127.") or not port \
            or port < 1 or port > 65535:
        return None
    p["host"] = host
    p["port"] = port
    p["scheme"] = p["scheme"].lower()
    if not p.get("tag"):
        p["tag"] = f"{p['scheme']}-{host}:{port}"
    p["tag"] = str(p["tag"]).replace("\n", " ").strip()[:96]
    try:
        p["uri"] = build_uri(p)
    except Exception:
        return None
    p["key"] = p["uri"].split("#", 1)[0]
    p["endpoint"] = (p["scheme"], host, port)
    return p


def parse_vmess(uri):
    body = uri[len("vmess://"):]
    data = None
    for cand in (body, body.split("#", 1)[0], body.split("?", 1)[0]):
        dec = b64_try_decode(cand)
        if not dec:
            continue
        try:
            j = json.loads(dec.decode("utf-8", "ignore"))
            if isinstance(j, dict) and j.get("add"):
                data = j
                break
        except Exception:
            continue
    if data is None:
        # редко: vmess://uuid@host:port?...
        return parse_generic(uri, scheme_override="vmess")
    host = str(data.get("add", "")).strip()
    port = int_try(data.get("port"))
    if not host or not port:
        return None
    net = str(data.get("net", "tcp") or "tcp").lower()
    if net == "h2":
        net = "http"
    tls = str(data.get("tls", "")).lower() == "tls"
    p = {"scheme": "vmess", "host": host, "port": port,
         "uuid": str(data.get("id", "")).strip(),
         "aid": int_try(data.get("aid")) or int_try(data.get("alterId")) or 0,
         "scy": str(data.get("scy") or data.get("security") or "auto"),
         "net": net,
         "path": str(data.get("path", "") or ""),
         "hosth": str(data.get("host", "") or ""),
         "headerType": str(data.get("type", "") or ""),
         "sni": str(data.get("sni", "") or ""),
         "fp": str(data.get("fp", "") or ""),
         "alpn": str(data.get("alpn", "") or ""),
         "security": "tls" if tls else "none",
         "insecure": False,
         "tag": str(data.get("ps") or "").strip()}
    return normalize_item(p)


def parse_ss(uri):
    body = uri[len("ss://"):]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    q = {}
    if "?" in body:
        body, qs = body.split("?", 1)
        try:
            q = {k: (v[0] if v else "") for k, v in
                 urllib.parse.parse_qs(qs, keep_blank_values=True).items()}
        except ValueError:
            q = {}
    body = body.strip().strip("/")
    method = password = None
    host = port = None
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
            method = urllib.parse.unquote(method)
            password = urllib.parse.unquote(password)
        else:
            dec = b64_try_decode(userinfo)
            if not dec or b":" not in dec:
                return None
            method, password = dec.decode("utf-8", "ignore").split(":", 1)
        h, pt = split_hostport(hostport)
        host, port = h, pt
    else:
        dec = b64_try_decode(body)
        if not dec or b"@" not in dec:
            return None
        userinfo, hostport = dec.decode("utf-8", "ignore").rsplit("@", 1)
        if ":" not in userinfo:
            return None
        method, password = userinfo.split(":", 1)
        h, pt = split_hostport(hostport)
        host, port = h, pt
    if not host or not port or not method:
        return None
    p = {"scheme": "ss", "host": host, "port": port,
         "method": method.strip(), "password": password,
         "plugin": q.get("plugin", ""),
         "tag": urllib.parse.unquote(frag).strip()}
    return normalize_item(p)


def parse_generic(uri, scheme_override=None):
    try:
        sp = urllib.parse.urlsplit(uri)
    except ValueError:
        return None
    scheme = scheme_override or sp.scheme.lower()
    if scheme == "hy2":
        scheme = "hysteria2"
    if scheme not in ("vless", "trojan", "hysteria2", "tuic", "vmess"):
        return None
    try:
        port = sp.port
    except ValueError:
        return None
    host = sp.hostname or ""
    if not host or not port:
        return None
    try:
        q = {k: (v[0] if v else "") for k, v in
             urllib.parse.parse_qs(sp.query, keep_blank_values=True).items()}
    except ValueError:
        q = {}
    user = urllib.parse.unquote(sp.username or "")
    pw = urllib.parse.unquote(sp.password or "")
    tag = urllib.parse.unquote(sp.fragment or "").strip()
    p = {"scheme": scheme, "host": host, "port": port, "tag": tag}

    if scheme == "vless":
        if not user:
            return None
        sec = q.get("security", "").lower()
        if not sec:
            sec = "reality" if q.get("pbk") else (
                "tls" if (q.get("sni") or q.get("fp") or q.get("alpn")) else "none")
        p.update({"uuid": user, "flow": q.get("flow", ""),
                  "security": sec,
                  "sni": q.get("sni") or q.get("peer") or "",
                  "fp": q.get("fp", ""), "pbk": q.get("pbk", ""),
                  "sid": q.get("sid", ""), "spx": q.get("spx", ""),
                  "net": (q.get("type") or "tcp").lower(),
                  "path": q.get("path", ""), "hosth": q.get("host", ""),
                  "serviceName": q.get("serviceName", ""),
                  "headerType": q.get("headerType", ""),
                  "alpn": q.get("alpn", ""), "mode": q.get("mode", ""),
                  "insecure": truthy(q.get("allowInsecure")) or truthy(q.get("insecure"))})
    elif scheme == "trojan":
        if not user:
            return None
        p.update({"password": user,
                  "security": "none" if q.get("security", "").lower() == "none" else "tls",
                  "sni": q.get("sni") or q.get("peer") or "",
                  "fp": q.get("fp", ""),
                  "net": (q.get("type") or "tcp").lower(),
                  "path": q.get("path", ""), "hosth": q.get("host", ""),
                  "serviceName": q.get("serviceName", ""),
                  "headerType": q.get("headerType", ""),
                  "alpn": q.get("alpn", ""),
                  "insecure": truthy(q.get("allowInsecure")) or truthy(q.get("insecure"))})
    elif scheme == "hysteria2":
        auth = user if not pw else (user + ":" + pw)
        p.update({"auth": auth,
                  "sni": q.get("sni") or q.get("peer") or "",
                  "insecure": truthy(q.get("insecure")) or truthy(q.get("allowInsecure")),
                  "obfs": q.get("obfs", ""),
                  "obfs_password": q.get("obfs-password") or q.get("obfsPassword") or ""})
    elif scheme == "tuic":
        if not user:
            return None
        p.update({"uuid": user, "password": pw,
                  "cc": q.get("congestion_control") or "bbr",
                  "sni": q.get("sni") or q.get("peer") or "",
                  "alpn": q.get("alpn") or "h3",
                  "insecure": truthy(q.get("allow_insecure")) or truthy(q.get("insecure"))})
    else:  # vmess в SIP-форме
        if not user:
            return None
        p.update({"uuid": user,
                  "aid": int_try(q.get("alterId") or q.get("aid")) or 0,
                  "scy": q.get("encryption") or "auto",
                  "security": q.get("security", "").lower() or
                              ("tls" if (q.get("sni") or q.get("fp")) else "none"),
                  "sni": q.get("sni") or "", "fp": q.get("fp", ""),
                  "net": (q.get("type") or "tcp").lower(),
                  "path": q.get("path", ""), "hosth": q.get("host", ""),
                  "serviceName": q.get("serviceName", ""),
                  "headerType": q.get("headerType", ""),
                  "alpn": q.get("alpn", ""),
                  "insecure": truthy(q.get("allowInsecure"))})
    return normalize_item(p)


def parse_uri(uri):
    low = uri.strip().lower()
    if low.startswith("vmess://"):
        return parse_vmess(uri.strip())
    if low.startswith("ss://"):
        return parse_ss(uri.strip())
    return parse_generic(uri.strip())


# ------------------------------------------------- парсинг Clash YAML -------

def _cl_ws_headers(d):
    wo = d.get("ws-opts") or {}
    if not isinstance(wo, dict):
        return "", ""
    path = str(wo.get("path") or "")
    h = wo.get("headers") or {}
    hosth = ""
    if isinstance(h, dict):
        for k, v in h.items():
            if str(k).lower() == "host":
                hosth = str(v if isinstance(v, str) else
                            (v[0] if isinstance(v, list) and v else ""))
                break
    return path, hosth


def clash_to_p(d):
    """Clash-прокси (dict) -> внутренний конфиг. Неподдерживаемые типы -> None."""
    t = str(d.get("type") or "").strip().lower()
    host = str(d.get("server") or "").strip()
    port = int_try(d.get("port"))
    if not host or not port:
        return None
    name = str(d.get("name") or "").strip()
    ins = bool(d.get("skip-cert-verify"))
    net = str(d.get("network") or "tcp").strip().lower()
    sni = str(d.get("servername") or d.get("sni") or "").strip()
    fp = str(d.get("client-fingerprint") or "").strip()
    alpn = d.get("alpn")
    if isinstance(alpn, (list, tuple)):
        alpn = ",".join(str(a) for a in alpn)
    alpn = str(alpn or "")
    p = {"scheme": t, "host": host, "port": port, "tag": name, "insecure": ins}

    if t == "ss":
        p.update({"method": str(d.get("cipher") or ""),
                  "password": str(d.get("password") if d.get("password") is not None else "")})
        pl = str(d.get("plugin") or "").strip().lower()
        po = d.get("plugin-opts") or {}
        if isinstance(po, dict) and pl in ("obfs", "simple-obfs"):
            opts = "obfs=" + str(po.get("mode") or "http")
            if po.get("host"):
                opts += ";obfs-host=" + str(po["host"])
            p["plugin"] = "obfs-local;" + opts
        elif isinstance(po, dict) and pl == "v2ray-plugin":
            opts = "mode=" + str(po.get("mode") or "websocket")
            if po.get("path"):
                opts += ";path=" + str(po["path"])
            if po.get("host"):
                opts += ";host=" + str(po["host"])
            if po.get("tls"):
                opts += ";tls"
            p["plugin"] = "v2ray-plugin;" + opts
        return p

    if t in ("vmess", "vless"):
        path, hosth = _cl_ws_headers(d)
        grpcname = str((d.get("grpc-opts") or {}).get("grpc-service-name") or "")
        if d.get("http-opts"):  # vmess поверх tcp с http-обфускацией
            ho = d["http-opts"] or {}
            paths = ho.get("path") or [""]
            p_path = str(paths[0] if isinstance(paths, list) and paths else (paths or ""))
            p_hosth = ""
            hh = ho.get("headers") or {}
            if isinstance(hh, dict):
                for k, v in hh.items():
                    if str(k).lower() == "host" and isinstance(v, list) and v:
                        p_hosth = str(v[0])
            net, p_path, p_hosth, header_type = "tcp", p_path, p_hosth, "http"
        else:
            if net == "h2" or net == "http":
                ho = d.get("h2-opts") or {}
                hh = ho.get("host") if isinstance(ho, dict) else None
                if isinstance(hh, list) and hh:
                    hosth = str(hh[0])
                path = str((ho.get("path") if isinstance(ho, dict) else "") or path)
                net = "http"
            elif net == "ws":
                path, hosth = _cl_ws_headers(d)
            p_path, p_hosth, header_type = str(path or ""), str(hosth or ""), ""
        sec = "none"
        if t == "vmess":
            if d.get("tls"):
                sec = "tls"
        else:
            ro = d.get("reality-opts") or {}
            if isinstance(ro, dict) and ro.get("public-key"):
                sec = "reality"
                p["pbk"] = str(ro["public-key"])
                p["sid"] = str(ro.get("short-id") or "")
            elif d.get("tls"):
                sec = "tls"
        p.update({"uuid": str(d.get("uuid") or ""),
                  "aid": int_try(d.get("alterId")) or 0,
                  "scy": str(d.get("cipher") or "auto"),
                  "flow": str(d.get("flow") or ""),
                  "security": sec, "sni": sni, "fp": fp, "alpn": alpn,
                  "net": net or "tcp", "path": p_path, "hosth": p_hosth,
                  "serviceName": grpcname, "headerType": header_type})
        return p

    if t == "trojan":
        path, hosth = _cl_ws_headers(d)
        grpcname = str((d.get("grpc-opts") or {}).get("grpc-service-name") or "")
        if net in ("h2", "http"):
            net = "http"
        p.update({"password": str(d.get("password") or ""),
                  "security": "tls", "sni": sni, "fp": fp, "alpn": alpn,
                  "net": net or "tcp", "path": str(path or ""), "hosth": str(hosth or ""),
                  "serviceName": grpcname, "headerType": ""})
        return p

    if t in ("hysteria2", "hy2"):
        p["scheme"] = "hysteria2"
        p.update({"auth": str(d.get("password") or d.get("auth") or ""),
                  "sni": sni, "obfs": str(d.get("obfs") or ""),
                  "obfs_password": str(d.get("obfs-password") or ""),
                  "alpn": alpn})
        return p

    if t == "tuic":
        p.update({"uuid": str(d.get("uuid") or ""),
                  "password": str(d.get("password") or ""),
                  "cc": str(d.get("congestion-controller")
                            or d.get("congestion-control") or "bbr"),
                  "sni": sni, "alpn": alpn or "h3"})
        return p

    return None  # hysteria v1, socks5, http, snell, anytls, ssh и прочие


def parse_clash(text):
    """Целиком текст (Clash/mihomo YAML) -> список внутренних конфигов."""
    if not HAVE_YAML:
        return []
    if not re.search(r"(?m)^\s{0,4}proxies:\s*$", text):
        return []
    try:
        doc = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    out = []
    for d in (doc.get("proxies") or []):
        if isinstance(d, dict):
            p = clash_to_p(d)
            if p:
                out.append(p)
    return out


# --------------------------------------------------------- ядро: билдеры ----

def xray_stream(p):
    net = p.get("net") or "tcp"
    if net == "h2":
        net = "http"
    known = ("tcp", "ws", "grpc", "http", "httpupgrade", "xhttp", "kcp")
    if net not in known:
        return None
    ss = {"network": net}
    sec = p.get("security") or "none"
    if sec in ("tls", "reality"):
        tls = {"serverName": p.get("sni") or p.get("hosth") or p["host"],
               "allowInsecure": bool(p.get("insecure"))}
        if p.get("fp"):
            tls["fingerprint"] = p["fp"]
        alpn = p.get("alpn")
        if alpn:
            tls["alpn"] = [a for a in re.split(r"[;,]", alpn) if a]
        if sec == "tls":
            ss["security"] = "tls"
            ss["tlsSettings"] = tls
        else:
            if not p.get("pbk"):
                return None
            ss["security"] = "reality"
            ss["realitySettings"] = {
                "serverName": p.get("sni") or p["host"],
                "fingerprint": p.get("fp") or "chrome",
                "publicKey": p["pbk"],
                "shortId": p.get("sid", ""),
                "spiderX": p.get("spx") or "/"}
    if net == "tcp" and p.get("headerType") == "http":
        req = {"version": "1.1", "method": "GET",
               "headers": {"User-Agent": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]}}
        if p.get("path"):
            req["path"] = [p["path"]]
        if p.get("hosth"):
            req["headers"]["Host"] = [p["hosth"]]
        ss["tcpSettings"] = {"header": {"type": "http", "request": req}}
    elif net == "ws":
        w = {"path": p.get("path") or "/"}
        if p.get("hosth"):
            w["headers"] = {"Host": p["hosth"]}
        ss["wsSettings"] = w
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": p.get("serviceName") or p.get("path") or "",
                              "multiMode": p.get("mode") == "multi"}
    elif net == "httpupgrade":
        h = {"path": p.get("path") or "/"}
        if p.get("hosth"):
            h["host"] = p["hosth"]
        ss["httpupgradeSettings"] = h
    elif net == "http":
        ss["httpSettings"] = {"path": p.get("path") or "/",
                              "host": [p.get("hosth") or p["host"]]}
    elif net == "xhttp":
        xs = {"path": p.get("path") or "/", "mode": p.get("mode") or "auto"}
        if p.get("hosth"):
            xs["host"] = p["hosth"]
        ss["xhttpSettings"] = xs
    elif net == "kcp":
        k = {"mtu": 1350, "tti": 56, "uplinkCapacity": 12, "downlinkCapacity": 100,
             "congestion": False, "header": {"type": p.get("headerType") or "none"}}
        if p.get("seed"):
            k["seed"] = p["seed"]
        ss["kcpSettings"] = k
    return ss


def xray_outbound(p):
    s = p["scheme"]
    host, port = p["host"], p["port"]
    stream = xray_stream(p)
    if stream is None:
        return None
    if s == "vless":
        if not p.get("uuid"):
            return None
        user = {"id": p["uuid"], "encryption": "none", "level": 0}
        if p.get("flow"):
            user["flow"] = p["flow"]
        return {"protocol": "vless", "tag": "proxy",
                "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                "streamSettings": stream}
    if s == "vmess":
        if not p.get("uuid"):
            return None
        user = {"id": p["uuid"], "alterId": int(p.get("aid") or 0),
                "security": p.get("scy") or "auto", "level": 0}
        return {"protocol": "vmess", "tag": "proxy",
                "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                "streamSettings": stream}
    if s == "trojan":
        if not p.get("password"):
            return None
        return {"protocol": "trojan", "tag": "proxy",
                "settings": {"servers": [{"address": host, "port": port,
                                          "password": p["password"], "level": 0}]},
                "streamSettings": stream}
    if s == "ss":
        if not (p.get("method") and p.get("password") is not None):
            return None
        srv = {"address": host, "port": port, "method": p["method"], "password": p["password"]}
        pl = p.get("plugin") or ""
        if pl:
            name, _, opts = pl.partition(";")
            if name in ("obfs-local", "simple-obfs", "v2ray-plugin"):
                srv["plugin"] = name
                srv["pluginOpts"] = opts
        return {"protocol": "shadowsocks", "tag": "proxy",
                "settings": {"servers": [srv]}}
    return None


def sb_outbound(p):
    """Outbound для sing-box (hysteria2/tuic + fallback для TCP-протоколов)."""
    s = p["scheme"]
    host, port = p["host"], p["port"]
    o = {"type": "shadowsocks" if s == "ss" else s, "tag": "proxy",
         "server": host, "server_port": int(port)}
    if s in ("vless", "vmess", "trojan", "ss"):
        if s == "vless":
            if not p.get("uuid"):
                return None
            o["uuid"] = p["uuid"]
            if p.get("flow"):
                o["flow"] = p["flow"]
        elif s == "vmess":
            if not p.get("uuid"):
                return None
            o["uuid"] = p["uuid"]
            o["security"] = p.get("scy") or "auto"
            o["alter_id"] = int(p.get("aid") or 0)
        elif s == "trojan":
            if not p.get("password"):
                return None
            o["password"] = p["password"]
        elif s == "ss":
            if not (p.get("method") and p.get("password") is not None):
                return None
            o["method"] = p["method"]
            o["password"] = p["password"]
            pl = p.get("plugin") or ""
            if pl:
                name, _, opts = pl.partition(";")
                if name in ("obfs-local", "simple-obfs"):
                    o["plugin"] = "obfs-local"
                    o["plugin_opts"] = opts
                elif name == "v2ray-plugin":
                    o["plugin"] = "v2ray-plugin"
                    o["plugin_opts"] = opts
        net = p.get("net") or "tcp"
        if net == "h2":
            net = "http"
        if net not in ("tcp", "ws", "grpc", "http", "httpupgrade"):
            return None  # xhttp / kcp sing-box не умеет
        sec = p.get("security") or "none"
        if sec in ("tls", "reality") or s == "trojan":
            tls = {"enabled": True,
                   "server_name": p.get("sni") or p.get("hosth") or host,
                   "insecure": bool(p.get("insecure"))}
            if p.get("alpn"):
                tls["alpn"] = [a for a in re.split(r"[;,]", p["alpn"]) if a]
            if p.get("fp"):
                tls["utls"] = {"enabled": True, "fingerprint": p["fp"]}
            if sec == "reality":
                if not p.get("pbk"):
                    return None
                tls["reality"] = {"enabled": True, "public_key": p["pbk"],
                                  "short_id": p.get("sid", "")}
            o["tls"] = tls
        if net == "ws":
            t = {"type": "ws", "path": p.get("path") or "/"}
            if p.get("hosth"):
                t["headers"] = {"Host": p["hosth"]}
            o["transport"] = t
        elif net == "grpc":
            o["transport"] = {"type": "grpc",
                              "service_name": p.get("serviceName") or p.get("path") or ""}
        elif net == "http":
            o["transport"] = {"type": "http", "path": p.get("path") or "/",
                              "host": [p.get("hosth") or host]}
        elif net == "httpupgrade":
            o["transport"] = {"type": "httpupgrade", "path": p.get("path") or "/",
                              "host": p.get("hosth") or host}
        return o
    if s == "hysteria2":
        o["password"] = p.get("auth") or ""
        o["tls"] = {"enabled": True, "server_name": p.get("sni") or host,
                    "insecure": bool(p.get("insecure"))}
        if p.get("obfs") == "salamander" and p.get("obfs_password"):
            o["obfs"] = {"type": "salamander", "password": p["obfs_password"]}
        return o
    if s == "tuic":
        o["uuid"] = p.get("uuid") or ""
        o["password"] = p.get("password") or ""
        o["congestion_control"] = p.get("cc") or "bbr"
        alpn = [a for a in re.split(r"[;,]", p.get("alpn") or "h3") if a] or ["h3"]
        o["tls"] = {"enabled": True, "server_name": p.get("sni") or host,
                    "alpn": alpn, "insecure": bool(p.get("insecure"))}
        return o
    return None


def build_test_config(c, core, port):
    if core == "xray":
        out = xray_outbound(c)
        if out is None:
            return None
        return {"log": {"loglevel": "error"},
                "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http"}],
                "outbounds": [out]}
    out = sb_outbound(c)
    if out is None:
        return None
    rip = c.get("_rip")
    if rip:
        out["server"] = rip
    return {"log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
                          "listen_port": port}],
            "outbounds": [out]}


# ------------------------------------------------------------- загрузка -----

def proxies_for(settings):
    p = (settings.http_proxy or "").strip()
    return {"http": p, "https": p} if p else None


def load_sources(path):
    urls, seen = [], set()
    if not os.path.isfile(path):
        return urls
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"https://github\.com/([^/]+)/([^/]+)/blob/(.+)", line)
            if m:
                line = f"https://raw.githubusercontent.com/{m[1]}/{m[2]}/{m[3]}"
            else:
                m = re.match(r"https://github\.com/([^/]+)/([^/]+)/raw/(.+)", line)
                if m:
                    line = f"https://raw.githubusercontent.com/{m[1]}/{m[2]}/{m[3]}"
            line = line.replace("/refs/heads/", "/")
            if line not in seen:
                seen.add(line)
                urls.append(line)
    return urls


DYNAMIC_ALLOWED = (
    "raw.githubusercontent.com", "github.com", "gist.githubusercontent.com",
    "cdn.jsdelivr.net", "fastly.jsdelivr.net", "gcore.jsdelivr.net",
    "testingcf.jsdelivr.net", "gh-proxy.com", "ghproxy.net")
DYNAMIC_BAD = re.compile(
    r"(\.(png|jpe?g|gif|svg|ico|webp|pdf|zip|gz|rar|7z|mp4|apk|exe|deb|dmg)$"
    r"|t\.me/|telegram\.me|discord\.gg|youtube\.com|youtu\.be|twitter\.com"
    r"|x\.com/|reddit\.com|facebook\.com|instagram\.com"
    r"|/archive/|/releases/|/tree/|/commits/|/issues/|/pull/|/wiki/"
    r"|\.git$|gitlab\.com|gitcode|gitee\.com|node_modules"
    r"|/archives/|AdguardTeam|/hosts|v2ray-rules-dat|/rules/)", re.I)


def normalize_source_url(u):
    """Приводит ссылку-кандидата к raw-форме; возвращает None, если не подходит."""
    u = u.rstrip(URI_TRAIL).strip()
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/blob/(.+)", u)
    if m:
        u = f"https://raw.githubusercontent.com/{m[1]}/{m[2]}/{m[3]}"
    else:
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/raw/(.+)", u)
        if m:
            u = f"https://raw.githubusercontent.com/{m[1]}/{m[2]}/{m[3]}"
    u = u.replace("/refs/heads/", "/")
    u = re.sub(r"^http://", "https://", u)
    try:
        host = urllib.parse.urlsplit(u).netloc.lower()
    except ValueError:
        return None
    if host == "github.com" and "/blob/" not in u and "/raw/" not in u \
            and "/gist/" not in u:
        # страница репозитория, а не файл — не источник
        return None
    if host not in DYNAMIC_ALLOWED:
        return None
    if DYNAMIC_BAD.search(u):
        return None
    if len(u) < 20:
        return None
    return u


def load_dynamic_sources(url, static_urls, settings):
    """Тянет поддерживаемый сообществом список подписок и берёт из него
    до dynamic_max случайных адресов, которых ещё нет в sources.txt.
    Каждом цикле выборка разная — пул источников само-растёт."""
    if not url:
        return []
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=(10, 60),
                         proxies=proxies_for(settings))
        if r.status_code != 200:
            log(f"Динамический список источников: HTTP {r.status_code}", "SRC")
            return []
        text = r.text
    except Exception as e:
        log(f"Динамический список источников недоступен: {e}", "SRC")
        return []
    seen = set(static_urls)
    found = []
    for m in re.finditer(r"https?://[^\s<>\"'`\\)\]]+", text):
        u = normalize_source_url(m.group(0))
        if u and u not in seen:
            seen.add(u)
            found.append(u)
    random.shuffle(found)
    n = settings.dynamic_max
    if n and n > 0 and len(found) > n:
        found = found[:n]
    return found


def fetch_sources(urls, settings):
    prx = proxies_for(settings)
    headers = {"User-Agent": UA}
    texts = []
    fails = []

    def one(u):
        try:
            r = requests.get(u, headers=headers, timeout=(10, 60), proxies=prx)
            if r.status_code == 200 and r.text and len(r.text) > 16:
                return (u, r.text)
            return (u, None, f"HTTP {r.status_code}")
        except Exception as e:
            return (u, None, str(e)[:120])

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(one, u): u for u in urls}
        for f in as_completed(futs):
            res = f.result()
            if res[1] is None:
                fails.append(res[0])
                log(f"  [FAIL] {short_url(res[0])} — {res[2]}", "SRC")
            else:
                texts.append((res[0], res[1]))
                log(f"  [OK]   {short_url(res[0])} ({len(res[1]) // 1024} КБ)", "SRC")
    return texts, fails


def extract_uris(text):
    out = []

    def harvest(t):
        for m in URI_RE.findall(t):
            out.append(m.rstrip(URI_TRAIL))

    if "://" in text:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if "://" in line:
                harvest(line)
            else:
                dec = b64_try_decode(line)
                if dec and b"://" in dec:
                    harvest(dec.decode("utf-8", "ignore"))
    else:
        dec = b64_try_decode(text)
        if dec:
            text = dec.decode("utf-8", "ignore")
        harvest(text)
    return out


def collect_configs(texts, settings):
    include = set(settings.include_protocols)
    seen = set()
    ep_count = {}
    items = []
    raw = bad = unsupported = capped = clash_n = 0
    cap = settings.cap_per_endpoint

    def take(p):
        nonlocal bad, unsupported, capped
        if p is None:
            bad += 1
            return
        if p["scheme"] not in include:
            unsupported += 1
            return
        if p["key"] in seen:
            return
        seen.add(p["key"])
        ek = p["endpoint"]
        if cap and ep_count.get(ek, 0) >= cap:
            capped += 1
            return
        ep_count[ek] = ep_count.get(ek, 0) + 1
        items.append(p)

    for _url, text in texts:
        for u in extract_uris(text):
            raw += 1
            take(parse_uri(u))
        for cp in parse_clash(text):
            raw += 1
            clash_n += 1
            take(normalize_item(cp))
    hist = {}
    for c in items:
        hist[c["scheme"]] = hist.get(c["scheme"], 0) + 1
    return items, {"raw": raw, "bad": bad, "unsupported": unsupported,
                   "capped": capped, "clash": clash_n, "hist": hist}


# --------------------------------------------------------- TCP-предфильтр ---

async def tcp_prefilter(items, tcp_concurrency, tcp_timeout):
    """Ступень 1: асинхронный TCP-фильтр — отсекает адреса с закрытым портом.

    Оптимизации v2.3:
      - окно задач вместо жёстких чанков: новое соединение стартует сразу,
        как только освободилось место, без синхронных «ступенек»;
      - результат кешируется на пару (host, порт): на одном адресе часто
        сидит до 20 конфигов — соединение делаем один раз на всех.
    """
    if not items:
        return {}
    sem = asyncio.Semaphore(max(10, tcp_concurrency))
    loop = asyncio.get_running_loop()
    dns_workers = int_try(os.environ.get("CHECKER_DNS_WORKERS")) or 256
    executor = ThreadPoolExecutor(max_workers=dns_workers)
    loop.set_default_executor(executor)
    dns_cache = {}
    ep_fut = {}
    stat = {"alive": 0}

    def _resolve_sync(h):
        try:
            infos = socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)
            return infos[0][4][0]
        except Exception:
            return None

    async def resolve(h):
        if h in dns_cache:
            return dns_cache[h]
        try:
            ip = await asyncio.wait_for(loop.run_in_executor(None, _resolve_sync, h), 6)
        except Exception:
            ip = None
        dns_cache[h] = ip
        return ip

    async def connect_probe(c):
        h = c["host"]
        ip = h if is_ip_literal(h) else await resolve(h)
        if not ip:
            return False
        try:
            _r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, c["port"]), tcp_timeout)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    async def check(c):
        ep = (c["host"], c["port"])
        fut = ep_fut.get(ep)
        if fut is None:
            # первый конфиг адреса делает реальную проверку, остальные ждут
            fut = loop.create_future()
            ep_fut[ep] = fut
            async with sem:
                try:
                    ok = await connect_probe(c)
                except Exception:
                    ok = False
                if not fut.done():
                    fut.set_result(ok)
            if ok:
                stat["alive"] += 1
        try:
            c["_tcp"] = await fut
        except Exception:
            c["_tcp"] = False

    total = len(items)
    unique = len({(c["host"], c["port"]) for c in items})
    log(f"TCP-фильтр: {total} конфигов ({unique} уникальных адресов), "
        f"{tcp_concurrency} соединений одновременно", "TCP")

    pending = set()
    it = iter(items)

    def add_tasks(n):
        for c in islice(it, n):
            pending.add(asyncio.create_task(check(c)))

    WINDOW = 4000
    add_tasks(WINDOW)
    done_total = 0
    step = max(1, total // 12)
    next_report = step
    try:
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED)
            done_total += len(done)
            for t in done:
                if t.done() and not t.cancelled() and t.exception():
                    t.exception()  # забираем, чтобы не сыпалось при GC
            add_tasks(len(done))
            if done_total >= next_report or done_total >= total:
                log(f"  прогресс: {done_total}/{total} (живо {stat['alive']})", "TCP")
                next_report += step
    finally:
        # освобождаем потоки — они понадобятся проверке через ядра
        executor.shutdown(wait=False)
    return dns_cache


def resolve_hosts(items, workers=256):
    """Резолвит адреса (для sing-box: подставляем IP, SNI остаётся доменом)."""
    def res(c):
        if c.get("_rip"):
            return True
        h = c["host"]
        if is_ip_literal(h):
            c["_rip"] = h
            return True
        try:
            infos = socket.getaddrinfo(h, None)
            c["_rip"] = infos[0][4][0]
            return True
        except Exception:
            return False
    alive = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(res, c): c for c in items}
        for f in as_completed(futs):
            if f.result():
                alive.append(futs[f])
    return alive


# ------------------------------------------------------ тест через ядро -----

class ProxyNotReady(Exception):
    pass


# кеш проверки «терпит ли ядро vless без TLS» (ключ — путь к бинарику)
_VLESS_NONE_OK = {}

# кеш проверки «отвергает ли xray allowInsecure» (новые версии его удалили)
_XRAY_INSECURE_REJECT = {}


def xray_rejects_insecure(exe):
    """True, если этот бинарик xray уже не принимает allowInsecure=true.

    Свежие Xray удалили эту опцию: конфиг с ней отвергается ЦЕЛИКОМ при
    старте (exit 23). Такие конфиги направляем в sing-box, где insecure
    по-прежнему поддерживается. Проверяем одним запуском, кешируем."""
    if exe is None:
        return False
    cached = _XRAY_INSECURE_REJECT.get(exe)
    if cached is not None:
        return cached
    out = {"protocol": "trojan", "tag": "probe",
           "settings": {"servers": [{"address": "203.0.113.1", "port": 443,
                                     "password": "probe", "level": 0}]},
           "streamSettings": {"network": "tcp", "security": "tls",
                              "tlsSettings": {"serverName": "probe.local",
                                              "allowInsecure": True}}}
    conf = {"log": {"loglevel": "error"}, "outbounds": [out]}
    rejects = False
    try:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(conf, f)
        flags = subprocess.CREATE_NO_WINDOW if IS_WIN else 0
        proc = subprocess.Popen([exe, "run", "-c", path],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                creationflags=flags)
        time.sleep(0.4)
        rejects = proc.poll() is not None
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            pass
        try:
            os.remove(path)
        except OSError:
            pass
    except Exception:
        rejects = False
    _XRAY_INSECURE_REJECT[exe] = rejects
    if rejects:
        log("конфиги с allowInsecure=1 будут проверяться через sing-box "
            "(этот Xray эту опцию больше не принимает)", "DBG")
    return rejects


def probe_via_proxy(port, test_urls, timeout):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({
        "http": f"http://127.0.0.1:{port}",
        "https": f"http://127.0.0.1:{port}"}))
    opener.addheaders = [("User-Agent", UA), ("Accept", "*/*")]
    for url in test_urls:
        t0 = time.monotonic()
        try:
            r = opener.open(urllib.request.Request(url), timeout=max(1.0, timeout))
            status = getattr(r, "status", 200)
            try:
                r.read(64)
            except Exception:
                pass
            r.close()
            if status in (200, 204):
                return True, (time.monotonic() - t0) * 1000.0
        except urllib.error.HTTPError as e:
            # 5xx — это ответ САМОГО ЯДРА «не смог дозвониться до сервера»
            # (xray/sing-box так отвечают при неудачном dial), а не ответ
            # удалённого сайта: сервер мёртв. Проверяем следующий URL.
            if getattr(e, "code", 0) and e.code >= 500:
                continue
            # Ответ 2xx-4xx пришёл через туннель — сервер жив, просто код
            # не 204/200 (например, 403 от самого сайта)
            return True, (time.monotonic() - t0) * 1000.0
        except urllib.error.URLError as e:
            if isinstance(getattr(e, "reason", None), (ConnectionRefusedError, FileNotFoundError)):
                raise ProxyNotReady()
            continue
        except (socket.timeout, TimeoutError, OSError, ValueError):
            continue
    return False, None


class TestCtx:
    def __init__(self, exes, tmpdir, test_urls, core_timeout):
        self.exes = exes
        self.tmpdir = tmpdir
        self.test_urls = test_urls
        self.core_timeout = core_timeout
        self._lock = threading.Lock()
        self._used = set()
        self._id = 0
        self.rnd = random.Random(os.getpid() ^ int(time.time() * 1000))
        self.err_samples = []

    def take_port(self):
        with self._lock:
            for _ in range(60):
                p = self.rnd.randrange(30000, 55000)
                if p in self._used:
                    continue
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.bind(("127.0.0.1", p))
                    self._used.add(p)
                    return p
                except OSError:
                    continue
                finally:
                    s.close()
            return self.rnd.randrange(30000, 55000)

    def next_id(self):
        with self._lock:
            self._id += 1
            return self._id

    def add_err_sample(self, text):
        with self._lock:
            if len(self.err_samples) < 3 and text:
                self.err_samples.append(text[:400])

    def release_ports(self, ports):
        """Возвращает порты в пул после окончания теста (иначе набор
        «использованных» растёт весь цикл и однажды кончается)."""
        with self._lock:
            for p in ports:
                self._used.discard(p)

    def allows_vless_none(self):
        """Терпит ли ЭТОТ бинарик xray vless без TLS/reality.

        Свежие Xray отвергают такой outbound целиком (exit 23, лог — в
        stdout), и одна такая конфигурация убивала бы всю пачку. Зависит
        от версии ядра, поэтому проверяем одним запуском и кешируем."""
        exe = self.exes.get("xray")
        if exe is None:
            return True
        cached = _VLESS_NONE_OK.get(exe)
        if cached is not None:
            return cached
        out = {"protocol": "vless", "tag": "probe",
               "settings": {"vnext": [{"address": "203.0.113.1", "port": 443,
                                       "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                                                  "encryption": "none", "level": 0}]}]},
               "streamSettings": {"network": "tcp"}}
        conf = {"log": {"loglevel": "error"}, "outbounds": [out]}
        ok = True
        try:
            fd, path = tempfile.mkstemp(suffix=".json", dir=self.tmpdir)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(conf, f)
            flags = subprocess.CREATE_NO_WINDOW if IS_WIN else 0
            proc = subprocess.Popen([exe, "run", "-c", path],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                    creationflags=flags, cwd=self.tmpdir)
            time.sleep(0.4)
            ok = proc.poll() is None
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                pass
            try:
                os.remove(path)
            except OSError:
                pass
        except Exception:
            ok = True  # не смогли проверить — не выбрасываем конфиги зря
        _VLESS_NONE_OK[exe] = ok
        if not ok:
            log("vless без TLS будет пропущен в пачках (это ядро такие "
                "outbound-ы отвергает целиком)", "DBG")
        return ok


def core_test_one(c, core, ctx, keep_tmp=False):
    port = ctx.take_port()
    conf = build_test_config(c, core, port)
    if conf is None:
        return ("unsupported", c, None)
    idx = ctx.next_id()
    cfg_path = os.path.join(ctx.tmpdir, f"t{idx}.json")
    err_path = cfg_path + ".err"
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(conf, f, ensure_ascii=False)
    except Exception:
        return ("unsupported", c, None)
    exe = ctx.exes[core]
    flags = subprocess.CREATE_NO_WINDOW if IS_WIN else 0
    proc = None
    status, lat = "fail", None
    try:
        with open(err_path, "wb") as errf:
            proc = subprocess.Popen([exe, "run", "-c", cfg_path],
                                    stdout=subprocess.DEVNULL, stderr=errf,
                                    creationflags=flags, cwd=ctx.tmpdir)
            deadline = time.monotonic() + ctx.core_timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    ok, lat = probe_via_proxy(port, ctx.test_urls, remaining)
                    status = "ok" if ok else "fail"
                    break
                except ProxyNotReady:
                    if proc.poll() is not None or time.monotonic() >= deadline:
                        status = "fail"
                        break
                    time.sleep(0.25)
    except Exception:
        status = "fail"
    finally:
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if status == "fail":
            try:
                with open(err_path, "rb") as f:
                    err_text = f.read(2048).decode("utf-8", "ignore").strip()
                if err_text:
                    ctx.add_err_sample(f"{c['scheme']}://{c['host']}:{c['port']} -> {err_text}")
            except OSError:
                pass
        if not keep_tmp:
            for fp in (cfg_path, err_path):
                try:
                    os.remove(fp)
                except OSError:
                    pass
        ctx.release_ports([port])
    return (status, c, lat)


_PRIV4 = [ipaddress.ip_network(n) for n in
          ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_PRIV6 = [ipaddress.ip_network("fc00::/7")]


def is_private_ip(host):
    """Приватный/loopback адрес в понимании ядра Xray (семантика Go):
    10/8, 172.16/12, 192.168/16, 127/8, fc00::/7, ::1.
    Внимание: это НЕ python-овское is_private — TEST-NET-диапазоны
    (203.0.113.x и т.п.) для ядра ПУБЛИЧНЫЕ. Домен — тоже не исключение:
    ядро резолвит его и отвергает, если там публичный IP."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # домен
    nets = _PRIV4 if ip.version == 4 else _PRIV6
    return ip.is_loopback or any(ip in n for n in nets)


# ------------------------------------------------- пачечная проверка (v2.3) --

# Шифры shadowsocks, которые ядро принимает при старте (классический AEAD).
# Легаси-шифры (rc4, cfb, ctr...) и SS2022 с невалидным ключом новые ядра
# отвергают ЦЕЛИКОМ (exit 23 при старте) — одна такая конфигурация валит
# всю пачку, поэтому в пачки их не берём (в одиночном режиме они просто
# получат fail, как и в v2.2).
SS_BATCH_CIPHERS = {
    "aes-128-gcm", "aes-256-gcm",
    "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305",
}


def build_batch_config_xray(entries):
    """Один конфиг Xray сразу на всю пачку: каждому конфигу — свой входящий
    HTTP-порт и свой outbound, маршрутизация inbound -> outbound."""
    inbounds, outbounds, rules = [], [], []
    outbounds.append({"protocol": "freedom", "tag": "direct"})
    for j, (_i, _c, out, port) in enumerate(entries):
        out["tag"] = f"out{j}"
        outbounds.append(out)  # без этого пачка проверяла бы не тех серверов!
        inbounds.append({"listen": "127.0.0.1", "port": port,
                         "protocol": "http", "tag": f"in{j}"})
        # ВАЖНО: у правил маршрутизации Xray обязательно "type": "field" —
        # без него ядро молча игнорирует правило, и трафик уходит в
        # outbound по умолчанию (мимо проверяемого сервера!)
        rules.append({"type": "field",
                      "inboundTag": [f"in{j}"], "outboundTag": f"out{j}"})
    return {"log": {"loglevel": "error"}, "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}


def build_batch_config_sb(entries):
    """То же для sing-box (hysteria2/tuic): входящие mixed + правила маршрутов."""
    inbounds, outbounds, rules = [], [], []
    for j, (_i, _c, out, port) in enumerate(entries):
        out["tag"] = f"out{j}"
        outbounds.append(out)
        inbounds.append({"type": "mixed", "tag": f"in{j}",
                         "listen": "127.0.0.1", "listen_port": port})
        rules.append({"inbound": [f"in{j}"], "outbound": f"out{j}"})
    return {"log": {"level": "error"}, "inbounds": inbounds,
            "outbounds": outbounds, "route": {"rules": rules}}


def batch_probe(port, ctx, proc, deadline):
    """Опрос одного порта пачки, пока ядро живо и не вышел дедлайн."""
    while True:
        if proc.poll() is not None:
            return "dead", None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "fail", None
        try:
            ok, lat = probe_via_proxy(port, ctx.test_urls,
                                      min(remaining, ctx.core_timeout))
            return ("ok" if ok else "fail"), lat
        except ProxyNotReady:
            time.sleep(0.2)


def _batch_run_once(entries, core, ctx, keep_tmp):
    """Один запуск ядра на пачку entries=[(orig_i, c, out, port)].

    Возвращает {orig_i: (status, latency)} либо None, если ядро не приняло
    пачку (отклонила конфигурация / процесс умер) — вызывающий код
    раздробит пачку, чтобы изолировать «ядовитые» конфиги.
    """
    ports = [e[3] for e in entries]
    builder = build_batch_config_xray if core == "xray" else build_batch_config_sb
    conf = builder(entries)
    idx = ctx.next_id()
    cfg_path = os.path.join(ctx.tmpdir, f"b{idx}.json")
    err_path = cfg_path + ".err"
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(conf, f, ensure_ascii=False)
    except Exception:
        ctx.release_ports(ports)
        return None
    exe = ctx.exes[core]
    flags = subprocess.CREATE_NO_WINDOW if IS_WIN else 0
    proc = None
    errf = None
    try:
        errf = open(err_path, "wb")
        # логи ядро пишет в stdout («Failed to start» — именно там),
        # поэтому собираем оба потока в один файл
        proc = subprocess.Popen([exe, "run", "-c", cfg_path],
                                stdout=errf, stderr=errf,
                                creationflags=flags, cwd=ctx.tmpdir)
        errf.close()
        errf = None
        time.sleep(0.35)  # даём ядру стартовать
        if proc.poll() is not None:
            et = ""
            try:
                with open(err_path, "rb") as f:
                    et = f.read(8192).decode("utf-8", "ignore")
            except OSError:
                pass
            err_line = ""
            for line in et.splitlines():
                if "Failed to start" in line or "FATAL" in line:
                    err_line = line.strip()  # последняя настоящая причина
            if not err_line and et:
                err_line = et.splitlines()[-1].strip()
            ctx.add_err_sample(f"пачка {core} x{len(entries)} отклонена: "
                               f"{err_line[:220] or 'процесс умер сразу'}")
            return None
        deadline = time.monotonic() + ctx.core_timeout + 2.0
        dead = False
        res = {}
        with ThreadPoolExecutor(max_workers=len(entries)) as pp:
            futs = [pp.submit(batch_probe, e[3], ctx, proc, deadline)
                    for e in entries]
            for j, f in enumerate(futs):
                st, lat = f.result()
                if st == "dead":
                    dead = True
                res[entries[j][0]] = (("ok" if st == "ok" else "fail"), lat)
        if dead and proc.poll() is not None:
            return None  # ядро умерло посреди пачки — раздробим
        return res
    except Exception:
        return None
    finally:
        if errf is not None:
            try:
                errf.close()
            except Exception:
                pass
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        ctx.release_ports(ports)
        if not keep_tmp:
            for fp in (cfg_path, err_path):
                try:
                    os.remove(fp)
                except OSError:
                    pass


def batch_test_group(group, core, ctx, keep_tmp=False):
    """Проверка пачки конфигов ОДНИМ процессом ядра (v2.3).

    Вместо «один процесс на конфиг» строится общий конфиг: у каждого
    конфига свой локальный порт и свой outbound. Возвращаем список
    (status, latency) по каждому конфигу группы либо None, если проверить
    не удалось ни одного конфига (тогда вызывающий код идёт по-одиночке).

    Если ядро отвергает пачку целиком (одна кривая конфигурация валит
    весь запуск), пачка дробится пополам — «ядовитый» конфиг изолируется
    за ~log2(N) запусков и не топит соседей. Конфигурации, которые ядро
    не принимает в принципе, остаются unsupported: живыми они быть не могут.
    """
    results = [("unsupported", None)] * len(group)

    def run(items, depth):
        # items: [(orig_i, config)]
        entries = []
        for i, c in items:
            if core == "xray" and c.get("insecure") \
                    and xray_rejects_insecure(ctx.exes.get("xray")):
                # этот Xray отвергает allowInsecure (вся пачка умрёт);
                # конфиг ушёл в группу sing-box (или будет пропущен)
                continue
            if c.get("scheme") == "ss" \
                    and (c.get("method") or "").lower().replace("_", "-") \
                    not in SS_BATCH_CIPHERS:
                # легаси/нестандартный шифр — ядро отвергнет всю пачку
                continue
            if core == "xray" and c.get("scheme") == "vless" \
                    and (c.get("security") or "none") == "none" \
                    and not is_private_ip(c.get("host") or "") \
                    and not ctx.allows_vless_none():
                # это ядро отвергает vless без TLS/reality на публичный
                # адрес (exit 23) — такая конфигурация убила бы всю пачку.
                # На приватные адреса (127.x, 192.168.x) ядро соглашается.
                continue
            out = xray_outbound(c) if core == "xray" else sb_outbound(c)
            if out is None:
                continue
            entries.append((i, c, out, ctx.take_port()))
        if not entries:
            return
        res = _batch_run_once(entries, core, ctx, keep_tmp)
        if res is not None:
            for i, val in res.items():
                results[i] = val
            return
        if len(items) > 8 and depth < 8:
            mid = len(items) // 2
            run(items[:mid], depth + 1)
            run(items[mid:], depth + 1)

    run(list(enumerate(group)), 0)
    if all(st == "unsupported" for st, _ in results):
        return None  # ни один конфиг не проверен — работает одиночный режим
    return results


def _test_group_single(core, group, ctx, concurrency, keep_tmp, collect, results):
    """Старая схема: один процесс ядра на каждый конфиг (fallback)."""
    base = len(results)
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futs = []
        inline = False
        for c in group:
            if inline:
                st, cc, lt = core_test_one(c, core, ctx, keep_tmp)
                collect(st, cc, lt)
                continue
            try:
                futs.append(pool.submit(core_test_one, c, core, ctx, keep_tmp))
            except RuntimeError:
                # системы с жёстким лимитом потоков — деградируем
                inline = True
                log(f"  {core}: лимит потоков ОС, часть проверок идёт "
                    f"последовательно", "WARN")
                st, cc, lt = core_test_one(c, core, ctx, keep_tmp)
                collect(st, cc, lt)
        for i, fut in enumerate(as_completed(futs), 1):
            st, cc, lt = fut.result()
            collect(st, cc, lt)
            if i % 200 == 0 or i == len(futs):
                log(f"  {core}: {i}/{len(group)} (живых {len(results) - base})")


def test_group(core, group, ctx, settings, keep_tmp, collect, results):
    """Проверка группы конфигов выбранным режимом.

    Пакетный (v2.3): одно ядро обслуживает сразу batch_size конфигов —
    на порядок быстрее и в разы экономнее по ОЗУ. Если ядро отклоняет
    пачку, она автоматически проверяется по-одиночке; после 5 неудач
    пакетный режим отключается до конца цикла.
    """
    base = len(results)
    total = len(group)
    if not settings.batch_mode:
        log(f"  {core}: одиночная проверка, {settings.core_concurrency} потоков")
        _test_group_single(core, group, ctx, settings.core_concurrency,
                           keep_tmp, collect, results)
        return

    bs = max(10, settings.batch_size)
    batches = [group[i:i + bs] for i in range(0, total, bs)]
    log(f"  {core}: пачками по {bs} конфигов, "
        f"{settings.batch_parallel} ядер одновременно")
    state = {"fail": 0, "done": 0, "off": False}
    lock = threading.Lock()

    def one_batch(batch):
        try:
            res = None
            with lock:
                off = state["off"]
            if not off:
                res = batch_test_group(batch, core, ctx, keep_tmp)
            if res is None:
                with lock:
                    state["fail"] += 1
                    if state["fail"] >= 5:
                        state["off"] = True
                log(f"  {core}: пачка не прошла через ядро — проверяю по-одиночке "
                    f"({state['fail']}-й сбой)", "WARN")
                with ThreadPoolExecutor(max_workers=min(24, max(1, len(batch)))) as fp:
                    futs = [fp.submit(core_test_one, c, core, ctx, keep_tmp)
                            for c in batch]
                    for f in as_completed(futs):
                        st, cc, lt = f.result()
                        collect(st, cc, lt)
            else:
                for (st, lt), c in zip(res, batch):
                    collect(st, c, lt)
            with lock:
                state["done"] += 1
                d = state["done"]
            if d % 5 == 0 or d == len(batches):
                log(f"  {core}: пачек {d}/{len(batches)} "
                    f"(живых {len(results) - base})")
        except Exception as e:
            log(f"  {core}: сбой пачки: {e}", "WARN")

    with ThreadPoolExecutor(max_workers=max(1, settings.batch_parallel)) as bp:
        futs = [bp.submit(one_batch, b) for b in batches]
        for f in as_completed(futs):
            f.result()


def download_file(url, proxy, retries=3):
    prx = {"http": proxy, "https": proxy} if proxy else None
    last = None
    for i in range(retries):
        try:
            with requests.get(url, stream=True, timeout=(10, 180), proxies=prx,
                              headers={"User-Agent": UA}) as r:
                r.raise_for_status()
                fd, path = tempfile.mkstemp(suffix=os.path.splitext(url)[1][:8] or ".bin")
                with os.fdopen(fd, "wb") as f:
                    for chunk in r.iter_content(1 << 16):
                        f.write(chunk)
                return path
        except Exception as e:
            last = e
            time.sleep(1.5 * (i + 1))
    raise RuntimeError(f"скачивание не удалось: {last}")


def extract_from_archive(archive_path, names, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    names = {n.lower() for n in names}
    found = False
    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as z:
            for m in z.infolist():
                if os.path.basename(m.filename).lower() in names:
                    with z.open(m) as src, open(dest, "wb") as d:
                        shutil.copyfileobj(src, d)
                    found = True
                    break
    else:
        with tarfile.open(archive_path, "r:*") as t:
            for m in t.getmembers():
                if m.isfile() and os.path.basename(m.name).lower() in names:
                    fsrc = t.extractfile(m)
                    with open(dest, "wb") as d:
                        shutil.copyfileobj(fsrc, d)
                    found = True
                    break
    if not found:
        raise RuntimeError("бинарник не найден в архиве")
    if not IS_WIN:
        os.chmod(dest, 0o755)


def detect_platform():
    s = platform.system().lower()
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        a = "amd64"
    elif m in ("aarch64", "arm64"):
        a = "arm64"
    elif m in ("i386", "i686"):
        a = "386"
    else:
        a = m
    return s, a


def singbox_latest_tag(proxy):
    try:
        r = requests.get("https://github.com/SagerNet/sing-box/releases/latest",
                         allow_redirects=True, timeout=30,
                         proxies=({"http": proxy, "https": proxy} if proxy else None),
                         headers={"User-Agent": UA})
        tag = r.url.rstrip("/").split("/")[-1]
        if tag.startswith("v") and re.match(r"^v\d+\.\d+", tag):
            return tag
    except Exception:
        pass
    r = requests.get("https://api.github.com/repos/SagerNet/sing-box/releases/latest",
                     timeout=30, headers={"User-Agent": UA},
                     proxies=({"http": proxy, "https": proxy} if proxy else None))
    return r.json()["tag_name"]


def _core_runs(path):
    """Проверка, что ядро реально запускается.

    Windows-антивирусы любят молча удалять или портить xray.exe/sing-box.exe —
    файл есть, а работать нельзя. Без этой проверки программа качала ядро
    заново каждый цикл.
    """
    try:
        r = subprocess.run([path, "version"], capture_output=True, timeout=25)
        return r.returncode == 0
    except Exception:
        return False


def ensure_cores(settings):
    exes = {}
    cdir = settings.cores_dir
    os.makedirs(cdir, exist_ok=True)
    s, a = detect_platform()
    prx = (settings.http_proxy or "").strip() or None
    AV_HINT = ("Ядро скачано, но не запускается — почти наверняка его удалил или "
               "испортил АНТИВИРУС. Добавьте папку программы в исключения антивируса "
               "(Безопасность Windows -> Защита от вирусов -> Исключения), иначе "
               "ядро будет перекачиваться каждый цикл.")
    xname = "xray.exe" if IS_WIN else "xray"
    xpath = os.path.join(cdir, "xray", xname)
    if os.path.isfile(xpath) and not _core_runs(xpath):
        log(f"Xray: {AV_HINT}", "WARN")
        try:
            os.remove(xpath)
        except OSError:
            pass
    if not os.path.isfile(xpath):
        asset = XRAY_ASSETS.get((s, a))
        if not asset:
            log(f"Нет сборки Xray для {s}/{a}", "WARN")
        else:
            try:
                log(f"Скачиваю ядро Xray ({asset})...")
                tmp = download_file("https://github.com/XTLS/Xray-core/releases/latest/download/" + asset, prx)
                extract_from_archive(tmp, {xname}, xpath)
                os.remove(tmp)
            except Exception as e:
                log(f"Xray недоступен: {e}", "WARN")
    if os.path.isfile(xpath):
        exes["xray"] = xpath
    bname = "sing-box.exe" if IS_WIN else "sing-box"
    bpath = os.path.join(cdir, "sing-box", bname)
    if os.path.isfile(bpath) and not _core_runs(bpath):
        log(f"sing-box: {AV_HINT}", "WARN")
        try:
            os.remove(bpath)
        except OSError:
            pass
    if not os.path.isfile(bpath):
        try:
            log("Скачиваю ядро sing-box...")
            tag = singbox_latest_tag(prx)
            asset = f"sing-box-{tag[1:]}-{s}-{a}." + ("zip" if s == "windows" else "tar.gz")
            tmp = download_file(f"https://github.com/SagerNet/sing-box/releases/download/{tag}/{asset}", prx)
            extract_from_archive(tmp, {bname}, bpath)
            os.remove(tmp)
        except Exception as e:
            log(f"sing-box недоступен: {e}", "WARN")
    if os.path.isfile(bpath):
        exes["singbox"] = bpath
    if exes:
        log("Ядра готовы: " + ", ".join(sorted(exes)))
    return exes


# ------------------------------------------------------------- GitHub -------

def github_push(settings, files, count):
    token = settings.github_token
    if not token:
        log("GitHub-токен не задан (config.ini [github] token или env GITHUB_TOKEN) "
            "— публикация пропущена", "WARN")
        return False
    repo, branch = settings.repo, settings.branch
    api = f"https://api.github.com/repos/{repo}/contents/"
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github+json",
               "User-Agent": UA, "X-GitHub-Api-Version": "2022-11-28"}
    prx = proxies_for(settings)

    def perm_hint_error():
        return RuntimeError(
            "HTTP 403 — у токена нет права записи в репозиторий. Для fine-grained "
            "токена откройте: GitHub -> Settings -> Developer settings -> "
            "Personal access tokens -> Fine-grained tokens -> ваш токен -> "
            "Repository access: Only select repositories -> nikus06123-del/sub4ch; "
            "Permissions -> Repository permissions -> Contents: Read and write "
            "(сохраните). Либо создайте классический токен со scope repo.")

    def put_file(path, data):
        url = api + path
        for attempt in range(3):
            sha = None
            r = requests.get(url, headers=headers, params={"ref": branch},
                             proxies=prx, timeout=30)
            if r.status_code == 200:
                sha = r.json().get("sha")
            elif r.status_code == 403 and "personal access token" in r.text:
                raise perm_hint_error()
            elif r.status_code != 404:
                raise RuntimeError(f"GET {path}: HTTP {r.status_code} {r.text[:200]}")
            payload = {"message": f"update {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC: "
                                  f"{count} live configs",
                       "branch": branch,
                       "content": base64.b64encode(data).decode("ascii")}
            if sha:
                payload["sha"] = sha
            r = requests.put(url, headers=headers, data=json.dumps(payload),
                             proxies=prx, timeout=60)
            if r.status_code in (200, 201):
                log(f"Загружено в GitHub: {repo}/{path} (ветка {branch})", "OK")
                return
            if r.status_code == 403 and "personal access token" in r.text:
                raise perm_hint_error()
            if r.status_code in (409, 429, 500, 502, 503, 504) and attempt < 2:
                time.sleep(3 * (attempt + 1))  # конфликт sha/лимиты — перечитаем и повторим
                continue
            raise RuntimeError(f"PUT {path}: HTTP {r.status_code} {r.text[:200]}")

    for path, data in files.items():
        put_file(path, data)
    return True


# ------------------------------------------------------------- цикл ---------

def run_cycle(settings, args, cycle_no):
    t0 = time.monotonic()
    log(f"=== Цикл #{cycle_no} ===")

    urls = load_sources(settings.sources_path)
    if not urls:
        log(f"В {settings.sources_path} нет ни одного источника", "ERROR")
        return
    log(f"Источников в списке: {len(urls)}")

    # Динамические источники: случайная выборка из поддерживаемого сообществом списка
    dyn = load_dynamic_sources(settings.dynamic_url, urls, settings)
    if dyn:
        log(f"Динамические источники: +{len(dyn)} (случайная выборка из общего пула)")
        urls = urls + dyn

    texts, fails = fetch_sources(urls, settings)
    if not texts:
        log("Ни один источник не скачался — прерываю цикл", "ERROR")
        return

    items, stats = collect_configs(texts, settings)
    items_total = len(items)
    hist_str = ", ".join(f"{k}: {v}" for k, v in sorted(stats["hist"].items()))
    log(f"Извлечено URI: {stats['raw']} (из них из Clash YAML: {stats['clash']}) | "
        f"нераспознано: {stats['bad']} | чужие протоколы: {stats['unsupported']} | "
        f"лимит на адрес: {stats['capped']}")
    log(f"Уникальных конфигов к проверке: {len(items)} ({hist_str})")
    if not items:
        log("Нет конфигов для проверки", "WARN")
        return

    if args.limit and args.limit > 0:
        random.Random(42).shuffle(items)
        items = items[:args.limit]
        log(f"Отладочный лимит: проверяю первые {len(items)}", "DEBUG")
    elif settings.max_run and len(items) > settings.max_run:
        total_before = len(items)
        items = random.sample(items, settings.max_run)
        log(f"Лимит на прогон: случайно выбрано {settings.max_run} "
            f"из {total_before} конфигов")

    tcp_items = [c for c in items if c["scheme"] in TCP_SCHEMES]
    udp_items = [c for c in items if c["scheme"] in UDP_SCHEMES]

    if settings.do_core:
        asyncio.run(tcp_prefilter(tcp_items, settings.tcp_concurrency, settings.tcp_timeout))
        tcp_alive = [c for c in tcp_items if c.get("_tcp")]
    else:
        for c in tcp_items:
            c["_tcp"] = True
        tcp_alive = tcp_items
    log(f"TCP-фильтр: {len(tcp_items)} -> {len(tcp_alive)} живых адресов")

    udp_resolved = resolve_hosts(udp_items) if udp_items else []
    if udp_items:
        log(f"Резолв UDP-серверов (hysteria2/tuic): {len(udp_items)} -> {len(udp_resolved)}")

    results = []
    tested = 0
    if settings.do_core:
        exes = ensure_cores(settings)
        if not exes:
            log("Ядра недоступны — оставляю результат только TCP-фильтра", "WARN")
            results = tcp_alive[:]
        else:
            def core_for(c):
                if c["scheme"] in UDP_SCHEMES:
                    return "singbox" if "singbox" in exes else None
                # свежие Xray не принимают allowInsecure — такие конфиги
                # проверяем через sing-box, где insecure ещё поддерживается
                if c.get("insecure") and "singbox" in exes \
                        and xray_rejects_insecure(exes.get("xray")):
                    return "singbox"
                if "xray" in exes:
                    return "xray"
                return "singbox" if "singbox" in exes else None

            groups = {"xray": [], "singbox": []}
            for c in tcp_alive + udp_resolved:
                k = core_for(c)
                if k:
                    groups[k].append(c)
            tested = sum(len(g) for g in groups.values())
            tmpdir = tempfile.mkdtemp(prefix="sub4ch_")
            try:
                okc = 0

                def collect(st, cc, lt):
                    nonlocal okc
                    if st == "ok":
                        okc += 1
                        cc["_lat"] = lt
                        results.append(cc)

                for core, group in groups.items():
                    if not group:
                        continue
                    if core == "singbox":
                        group = resolve_hosts(group)
                        if not group:
                            continue
                    ctx = TestCtx(exes, tmpdir, settings.test_urls, settings.core_timeout)
                    log(f"Проверка через {core}: {len(group)} конфигов")
                    test_group(core, group, ctx, settings, args.keep_tmp,
                               collect, results)
                    for smp in ctx.err_samples:
                        log(f"  пример ошибки: {smp}", "DBG")
            finally:
                if not args.keep_tmp:
                    shutil.rmtree(tmpdir, ignore_errors=True)
    else:
        results = tcp_alive[:]
        tested = 0

    for c in results:
        c.setdefault("_lat", None)
    results.sort(key=lambda c: c["_lat"] if c.get("_lat") is not None else 9e9)
    if settings.max_results and len(results) > settings.max_results:
        results = results[:settings.max_results]
    uris = [c["uri"] for c in results]

    lh = {}
    for c in results:
        lh[c["scheme"]] = lh.get(c["scheme"], 0) + 1
    log(f"ИТОГ: живых конфигов {len(uris)} (" +
        ", ".join(f"{k}: {v}" for k, v in sorted(lh.items())) + ")")

    outdir = settings.out_dir
    os.makedirs(outdir, exist_ok=True)
    plain = ("\n".join(uris) + ("\n" if uris else "")).encode("utf-8")
    b64 = base64.b64encode(plain).decode("ascii").encode("ascii")
    with open(os.path.join(outdir, "sub.txt"), "wb") as f:
        f.write(b64)
    with open(os.path.join(outdir, "sub_plain.txt"), "wb") as f:
        f.write(plain)

    # Мобильная подписка: топ-N самых быстрых (список уже отсортирован по отклику).
    # Мало серверов в файле = клиент на телефоне качает его быстрее и не тормозит.
    mobile_b64 = mobile_plain = None
    if settings.mobile_limit and uris:
        m_uris = [c["uri"] for c in results[:settings.mobile_limit]]
        mobile_plain = ("\n".join(m_uris) + "\n").encode("utf-8")
        mobile_b64 = base64.b64encode(mobile_plain).decode("ascii").encode("ascii")
        with open(os.path.join(outdir, os.path.basename(settings.path_mobile_b64)), "wb") as f:
            f.write(mobile_b64)
        with open(os.path.join(outdir, os.path.basename(settings.path_mobile_plain)), "wb") as f:
            f.write(mobile_plain)
        log(f"Мобильная подписка: {len(m_uris)} самых быстрых серверов")

    pushed = False
    elapsed = time.monotonic() - t0
    if uris:
        if not args.no_push:
            stats_doc = {
                "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "version": VERSION,
                "sources_total": len(urls),
                "sources_ok": len(texts),
                "raw_uris": stats["raw"],
                "unique_configs": items_total,
                "tcp_alive": len(tcp_alive),
                "tested": tested,
                "test_mode": ("batch" if settings.batch_mode else "single"),
                "live": len(uris),
                "by_protocol": lh,
                "mobile_limit": settings.mobile_limit,
                "mobile_live": (min(len(uris), settings.mobile_limit)
                                if settings.mobile_limit else None),
                "elapsed_sec": round(elapsed)}
            files = {settings.path_b64: b64, settings.path_plain: plain}
            if mobile_b64 is not None:
                files[settings.path_mobile_b64] = mobile_b64
                files[settings.path_mobile_plain] = mobile_plain
            if settings.path_stats:
                files[settings.path_stats] = json.dumps(
                    stats_doc, ensure_ascii=False, indent=2).encode("utf-8")
            try:
                pushed = github_push(settings, files, len(uris))
                if pushed:
                    log(f"Подписка для Throne: "
                        f"https://raw.githubusercontent.com/{settings.repo}/{settings.branch}/{settings.path_b64}")
                    log(f"Зеркало (если raw недоступен): "
                        f"https://cdn.jsdelivr.net/gh/{settings.repo}@{settings.branch}/{settings.path_b64}")
                    if mobile_b64 is not None:
                        log(f"Мобильная подписка (топ-{settings.mobile_limit}): "
                            f"https://raw.githubusercontent.com/{settings.repo}/{settings.branch}/{settings.path_mobile_b64}")
            except Exception as e:
                log(f"Ошибка публикации на GitHub: {e}", "ERROR")
    else:
        log("Живых конфигов не найдено — публикация пропущена (старая подписка сохранена)", "WARN")

    log(f"Цикл завершён за {elapsed:.0f} c. Файлы: {outdir}/sub.txt, {outdir}/sub_plain.txt")
    try:
        with open(os.path.join(outdir, "report.txt"), "a", encoding="utf-8") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} | src {len(texts)}/{len(urls)}"
                    f" | raw {stats['raw']} | uniq {len(items)} | tcp {len(tcp_alive)}"
                    f" | live {len(uris)} | push {'ok' if pushed else '-'}"
                    f" | {elapsed:.0f}s\n")
    except OSError:
        pass


# ------------------------------------------------------------- настройки ----

class Settings:
    def __init__(self, config_path, args):
        cp = configparser.ConfigParser(inline_comment_prefixes=(";", "#"),
                                       comment_prefixes=(";", "#"))
        if config_path and os.path.isfile(config_path):
            cp.read(config_path, encoding="utf-8-sig")

        def g(sec, key, fb):
            if cp.has_section(sec):
                return cp.get(sec, key, fallback=fb)
            return fb

        self.github_token = (os.environ.get("GITHUB_TOKEN") or g("github", "token", "") or "").strip()
        # Репозиторий: config.ini -> окружение Actions (GITHUB_REPOSITORY) -> значение по умолчанию
        self.repo = ((g("github", "repo", "") or "").strip()
                     or (os.environ.get("GITHUB_REPOSITORY") or "").strip()
                     or "nikus06123-del/sub4ch")
        self.branch = (g("github", "branch", "main") or "").strip()
        self.path_b64 = (g("github", "path_base64", "sub.txt") or "").strip()
        self.path_plain = (g("github", "path_plain", "sub_plain.txt") or "").strip()
        self.path_stats = (g("github", "path_stats", "stats.json") or "").strip()
        # отдельная «мобильная» подписка (топ самых быстрых серверов)
        self.path_mobile_b64 = (g("github", "path_mobile_base64", "sub_mobile.txt") or "").strip()
        self.path_mobile_plain = (g("github", "path_mobile_plain", "sub_mobile_plain.txt") or "").strip()

        # Динамические источники ([sources])
        self.dynamic_url = (g("sources", "dynamic_url", DYNAMIC_URL_DEFAULT) or "").strip()
        self.dynamic_max = int(g("sources", "dynamic_max", "60") or 0)

        # Лимит конфигов на прогон (env CHECKER_MAX_RUN приоритетнее — для Actions)
        self.max_run = int(os.environ.get("CHECKER_MAX_RUN")
                           or g("checker", "max_configs_per_run", "0") or 0)

        self.interval_hours = float(g("checker", "interval_hours", "2") or 2)
        self.cap_per_endpoint = int(g("checker", "max_configs_per_endpoint", "20") or 0)
        # лимит итоговой подписки (env CHECKER_MAX_RESULTS приоритетнее — для Actions)
        self.max_results = int(os.environ.get("CHECKER_MAX_RESULTS")
                               or g("checker", "max_results", "0") or 0)
        # отдельная мобильная подписка: топ-N самых быстрых серверов в файл
        # sub_mobile.txt (env CHECKER_MOBILE_LIMIT приоритетнее; 0 = не публиковать)
        self.mobile_limit = int(os.environ.get("CHECKER_MOBILE_LIMIT")
                                or g("checker", "mobile_limit", "0") or 0)
        self.out_dir = args.out_dir or (g("checker", "out_dir", "out") or "out")
        if not os.path.isabs(self.out_dir):
            self.out_dir = os.path.join(SCRIPT_DIR, self.out_dir)
        self.cores_dir = args.cores_dir or os.path.join(SCRIPT_DIR, "bin")

        self.tcp_concurrency = args.tcp_concurrency or int(g("testing", "tcp_concurrency", "1000") or 1000)
        # таймауты можно перекрыть env CHECKER_TCP_TIMEOUT / CHECKER_CORE_TIMEOUT
        self.tcp_timeout = float(os.environ.get("CHECKER_TCP_TIMEOUT")
                                 or g("testing", "tcp_timeout", "4") or 4)
        self.core_concurrency = args.core_concurrency or int(g("testing", "core_concurrency", "100") or 100)
        self.core_timeout = float(os.environ.get("CHECKER_CORE_TIMEOUT")
                                  or g("testing", "core_timeout", "10") or 10)
        # Пакетный режим (v2.3): одно ядро проверяет сразу пачку конфигов через
        # отдельные локальные порты — ступень 2 ускоряется на порядок.
        # CHECKER_BATCH=0 возвращает старую схему «один процесс на конфиг».
        self.batch_mode = truthy(os.environ.get("CHECKER_BATCH")
                                 or g("testing", "batch", "1"))
        self.batch_size = int(os.environ.get("CHECKER_BATCH_SIZE")
                              or g("testing", "batch_size", "200") or 200)
        self.batch_parallel = int(os.environ.get("CHECKER_BATCH_PARALLEL")
                                  or g("testing", "batch_parallel", "6") or 6)
        tu = (g("testing", "test_urls", DEFAULT_TEST_URLS) or DEFAULT_TEST_URLS)
        self.test_urls = [u.strip() for u in tu.split(",") if u.strip()]
        self.http_proxy = (os.environ.get("CHECKER_PROXY") or g("testing", "http_proxy", "") or "").strip()

        inc = (g("protocols", "include", "vless,vmess,trojan,ss,hysteria2,tuic") or "")
        self.include_protocols = [x.strip().lower() for x in inc.split(",") if x.strip()]

        self.sources_path = args.sources or os.path.join(SCRIPT_DIR, "sources.txt")
        self.do_core = not args.no_core
        if args.interval is not None:
            self.interval_hours = args.interval


def parse_args():
    ap = argparse.ArgumentParser(
        description="Sub4ch Checker — проверка бесплатных VPN-подписок для Throne",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--config", default=os.path.join(SCRIPT_DIR, "config.ini"),
                    help="путь к config.ini")
    ap.add_argument("--sources", default=None, help="путь к списку источников")
    ap.add_argument("--out-dir", default=None, help="папка для локальных файлов подписки")
    ap.add_argument("--cores-dir", default=None, help="папка для ядер xray/sing-box")
    ap.add_argument("--loop", action="store_true", help="работать бесконечно с интервалом")
    ap.add_argument("--interval", type=float, default=None,
                    help="интервал цикла в часах (перекрывает config.ini)")
    ap.add_argument("--no-push", action="store_true", help="не публиковать на GitHub")
    ap.add_argument("--no-core", action="store_true",
                    help="только TCP-фильтр, без проверки через ядро (быстро, но грязно)")
    ap.add_argument("--limit", type=int, default=0,
                    help="проверить не более N конфигов (для отладки)")
    ap.add_argument("--tcp-concurrency", type=int, default=None)
    ap.add_argument("--core-concurrency", type=int, default=None)
    ap.add_argument("--cores-only", action="store_true",
                    help="только скачать ядра и выйти")
    ap.add_argument("--keep-tmp", action="store_true",
                    help="не удалять временные конфиги ядра (для отладки)")
    return ap.parse_args()


def main():
    setup_console()
    raise_nofile()
    args = parse_args()
    print(f"=== Sub4ch Checker v{VERSION} — агрегатор живых VPN-конфигов для Throne ===")
    if args.cores_only:
        settings = Settings(args.config, args)
        exes = ensure_cores(settings)
        log(f"Готово: {exes}")
        return
    cycle = 0
    while True:
        cycle += 1
        try:
            settings = Settings(args.config, args)
            run_cycle(settings, args, cycle)
        except KeyboardInterrupt:
            log("Остановлено пользователем")
            return
        except Exception:
            import traceback
            traceback.print_exc()
        if not args.loop:
            break
        log(f"Следующий цикл через {settings.interval_hours:g} ч "
            f"(Ctrl+C — выход)")
        try:
            end = time.monotonic() + settings.interval_hours * 3600
            while time.monotonic() < end:
                time.sleep(min(30, max(0.5, end - time.monotonic())))
        except KeyboardInterrupt:
            log("Остановлено пользователем")
            return


if __name__ == "__main__":
    main()
