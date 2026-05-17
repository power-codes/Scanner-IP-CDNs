#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Powercodes - IP & Domain Scanner
ping + TCP + CDN Detection
"""

# --- تبلیغات ---
TELEGRAM_CHANNEL = "https://t.me/powercodes"
TELEGRAM_HANDLE  = "@powercodes"
YOUTUBE_CHANNEL  = "https://youtube.com/@powercodes"
GITHUB_REPO      = "https://github.com/power_codes"
TOOL_NAME        = "Scanner IP CDN"
TOOL_VERSION     = "1.0"
# ----------------

import concurrent.futures
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import subprocess
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, jsonify, render_template_string,
    request, Response, stream_with_context
)

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

IS_WINDOWS = platform.system().lower() == "windows"

# ══════════════════════════════════════════════════════════════════
#  Ping ══════════════════════════════════════════════════════════════════

def check_ping(host: str, timeout_ms: int = 1500) -> tuple:
    """پینگ واقعی با subprocess — دقیقاً منطق قدیمی"""
    if IS_WINDOWS:
        command = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms / 1000))), host]

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=(timeout_ms / 1000) + 2,
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        ok = proc.returncode == 0

        latency = None
        match_int   = re.search(r"time[=<]\s*(\d+)\s*ms", output, flags=re.IGNORECASE)
        match_float = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)", output, flags=re.IGNORECASE)
        if match_int:
            latency = float(match_int.group(1))
        elif match_float:
            latency = float(match_float.group(1))

        return ok, latency
    except Exception:
        return False, None


def check_tcp(target: str, port: int = 443, timeout: float = 2.0) -> tuple:
    try:
        start = time.perf_counter()
        with socket.create_connection((target, port), timeout=timeout):
            elapsed = (time.perf_counter() - start) * 1000
        return True, round(elapsed, 1)
    except Exception:
        return False, None


# ══════════════════════════════════════════════════════════════════
#  DNS + پاکسازی هدف‌ها
# ══════════════════════════════════════════════════════════════════
MAX_SUBNET_IPS = 1024
MAX_TOTAL_IPS  = 50_000

_dns_cache: dict = {}
_dns_lock = threading.Lock()

def resolve_domain(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    with _dns_lock:
        if target in _dns_cache:
            return _dns_cache[target]
    try:
        resolved = socket.gethostbyname(target)
        with _dns_lock:
            _dns_cache[target] = resolved
        return resolved
    except Exception:
        return target


def expand_subnet(cidr: str) -> list:
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        hosts = list(net.hosts()) or list(net)
        return [str(ip) for ip in hosts[:MAX_SUBNET_IPS]]
    except ValueError:
        return []


_cidr_re   = re.compile(r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2})\b')
_ip_re     = re.compile(r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b')
_domain_re = re.compile(r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b')

def clean_targets(raw_text: str) -> list:
    targets: set = set()
    for line in raw_text.splitlines():
        if len(targets) >= MAX_TOTAL_IPS:
            break
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cidr_found = False
        for match in _cidr_re.finditer(line):
            cidr_found = True
            for ip in expand_subnet(match.group(1)):
                targets.add(ip)
                if len(targets) >= MAX_TOTAL_IPS:
                    break
        remaining = _cidr_re.sub("", line) if cidr_found else line
        for match in _ip_re.finditer(remaining):
            ip = match.group(1)
            try:
                ipaddress.ip_address(ip)
                targets.add(ip)
            except ValueError:
                pass
        remaining2 = _ip_re.sub("", _cidr_re.sub("", line))
        for match in _domain_re.finditer(remaining2):
            dom = match.group(1).lower()
            if len(dom) > 3 and "." in dom:
                targets.add(dom)
    return sorted(targets)[:MAX_TOTAL_IPS]


# ══════════════════════════════════════════════════════════════════
#  CDN Detection
# ══════════════════════════════════════════════════════════════════
CDN_RANGES = [
    ("Cloudflare", [
        "1.0.0.0/24","1.1.1.0/24","103.21.244.0/22","103.22.200.0/22",
        "103.31.4.0/22","104.16.0.0/13","104.24.0.0/14","108.162.192.0/18",
        "131.0.72.0/22","141.101.64.0/18","162.158.0.0/15","172.64.0.0/13",
        "173.245.48.0/20","188.114.96.0/20","190.93.240.0/20",
        "197.234.240.0/22","198.41.128.0/17",
    ]),
    ("Google", [
        "8.8.4.0/24","8.8.8.0/24",
        "64.233.160.0/19","66.102.0.0/20","66.249.64.0/19","74.125.0.0/16",
        "104.132.0.0/14","108.177.0.0/17","142.250.0.0/15",
        "172.217.0.0/16","172.253.0.0/16","173.194.0.0/16",
        "209.85.128.0/17","216.58.192.0/19","216.239.32.0/19",
    ]),
    ("Fastly", [
        "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24",
        "104.156.80.0/20","146.75.0.0/16","151.101.0.0/16",
        "157.52.64.0/18","167.82.0.0/17","199.27.72.0/21","199.232.0.0/16",
    ]),
    ("Akamai", [
        "2.16.0.0/13","23.0.0.0/12","23.32.0.0/11","23.64.0.0/14",
        "23.72.0.0/13","23.192.0.0/11","63.0.0.0/8","69.192.0.0/16",
        "72.246.0.0/15","88.221.0.0/16","95.100.0.0/15","104.64.0.0/10",
        "184.24.0.0/13","184.50.0.0/15","184.84.0.0/14",
    ]),
    ("Netlify", [
        "3.33.128.0/17","13.32.0.0/15","13.35.0.0/16","18.64.0.0/14",
        "44.226.105.0/24","50.7.4.0/24","50.7.85.0/24","50.7.87.0/24",
        "44.235.184.0/24","52.84.0.0/15","35.157.26.0/24","63.176.8.0/24"
        "54.182.0.0/16","99.83.128.0/17","162.159.128.0/20",
    ]),
    ("Vercel", [
        "64.29.17.0/24","64.29.18.0/24","64.29.19.0/24",
        "66.33.60.0/24","66.33.61.0/24","76.76.21.0/24","76.223.126.0/24",
    ]),
    ("CloudFront", [
        "52.46.0.0/18","52.84.0.0/15","54.182.0.0/16",
        "99.84.0.0/16","130.176.0.0/17",
    ]),
    ("BunnyCDN", ["89.187.160.0/19","147.75.0.0/16"]),
    ("Gcore",    ["92.223.0.0/16","95.85.0.0/16","185.158.0.0/16"]),
    ("AbrArvan",    ["185.220.226.0/24","185.143.232.0/22"]),
    
]

_compiled_ranges = []
for _cdn_name, _ranges in CDN_RANGES:
    for _r in _ranges:
        try:
            _compiled_ranges.append((ipaddress.ip_network(_r, strict=False), _cdn_name))
        except ValueError:
            pass

def detect_cdn(ip_str: str) -> str:
    try:
        addr = ipaddress.ip_address(ip_str)
        for net, name in _compiled_ranges:
            if addr in net:
                return name
    except ValueError:
        pass
    return "Unknown"


# ══════════════════════════════════════════════════════════════════
#  هسته اسکن
# ══════════════════════════════════════════════════════════════════
def scan_single(target: str, port: int, ping_timeout_ms: int, tcp_timeout: float) -> dict:
    cdn         = "Unknown"
    resolved_ip = None

    try:
        ipaddress.ip_address(target)
        resolved_ip = target
        cdn = detect_cdn(target)
    except ValueError:
        r = resolve_domain(target)
        if r != target:
            resolved_ip = r
            cdn = detect_cdn(resolved_ip)

    # پینگ واقعی با subprocess — به IP resolve شده می‌زنیم
    ping_host = resolved_ip if resolved_ip else target
    ping_ok, ping_ms = check_ping(ping_host, timeout_ms=ping_timeout_ms)

    # TCP به target اصلی (دامنه یا IP)
    tcp_ok, tcp_ms = check_tcp(target, port=port, timeout=tcp_timeout)

    if ping_ok and tcp_ok:
        status = "both"
    elif tcp_ok:
        status = "tcp_only"
    elif ping_ok:
        status = "ping_only"
    else:
        status = "dead"

    return {
        "target":      target,
        "resolved_ip": resolved_ip or "",
        "cdn":         cdn,
        "ping_ok":     ping_ok,
        "ping_ms":     round(ping_ms, 1) if ping_ms is not None else None,
        "tcp_ok":      tcp_ok,
        "tcp_ms":      tcp_ms,
        "status":      status,
        "time":        datetime.now().strftime("%H:%M:%S"),
    }


# ══════════════════════════════════════════════════════════════════
#  State مشترک
# ══════════════════════════════════════════════════════════════════
scan_state = {
    "running": False,
    "results": [],
    "total":   0,
    "scanned": 0,
    "lock":    threading.Lock(),
}

# ══════════════════════════════════════════════════════════════════
#  HTML Template
# ══════════════════════════════════════════════════════════════════
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="fa" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scanner IP CDN</title>
<style>
:root {
  --bg:#0a0a0f;--bg2:#111118;--bg3:#18181f;
  --surface:rgba(255,255,255,0.04);--border:rgba(255,255,255,0.08);--border-hi:rgba(255,215,0,0.2);
  --gold:#ffd700;--gold2:#f5c842;--gold-dim:rgba(255,215,0,0.12);--gold-glow:rgba(255,215,0,0.25);
  --teal:#00d4aa;--teal2:#00b894;--teal-dim:rgba(0,212,170,0.12);--teal-glow:rgba(0,212,170,0.25);
  --white:#f0f0f0;--muted:#6b7280;--text:#d1d5db;
  --red:#f87171;--red-dim:rgba(248,113,113,0.12);
  --green:#34d399;--green-dim:rgba(52,211,153,0.12);
  --amber:#fbbf24;--amber-dim:rgba(251,191,36,0.12);
  --radius:14px;--radius-sm:8px;--radius-lg:20px;
}
[data-theme="light"] {
  --bg:#f5f5f0;--bg2:#ffffff;--bg3:#efefea;
  --surface:rgba(0,0,0,0.04);--border:rgba(0,0,0,0.1);--border-hi:rgba(180,140,0,0.3);
  --gold:#b8860b;--gold2:#a07800;--gold-dim:rgba(184,134,11,0.1);--gold-glow:rgba(184,134,11,0.2);
  --teal:#00897b;--teal2:#00796b;--teal-dim:rgba(0,137,123,0.1);--teal-glow:rgba(0,137,123,0.2);
  --white:#111827;--muted:#9ca3af;--text:#374151;
  --red:#dc2626;--red-dim:rgba(220,38,38,0.1);
  --green:#059669;--green-dim:rgba(5,150,105,0.1);
  --amber:#d97706;--amber-dim:rgba(217,119,6,0.1);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;transition:background .3s,color .3s}
.app{max-width:1400px;margin:0 auto;padding:20px 16px;display:flex;flex-direction:column;gap:16px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-lg);transition:background .3s,border-color .3s}
.header{padding:14px 20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;border-bottom:1px solid var(--border)}
.brand{display:flex;align-items:center;gap:12px}
.brand-icon{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,var(--gold-dim),var(--teal-dim));border:1px solid var(--border-hi);display:flex;align-items:center;justify-content:center;font-size:18px}
.brand-name{font-size:1.05rem;font-weight:700;color:var(--white);letter-spacing:-.01em}
.brand-ver{font-size:.62rem;color:var(--muted);letter-spacing:.15em;text-transform:uppercase;margin-top:1px}
.header-right{display:flex;align-items:center;gap:10px}
.theme-btn{width:36px;height:36px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:16px;transition:all .2s}
.theme-btn:hover{border-color:var(--gold);color:var(--gold)}
.promo-links{display:flex;gap:6px}
.promo-link{display:flex;align-items:center;gap:5px;padding:5px 10px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface);color:var(--muted);text-decoration:none;font-size:.68rem;font-weight:500;letter-spacing:.05em;transition:all .2s}
.promo-link:hover{border-color:var(--teal);color:var(--teal)}
.promo-link svg{width:13px;height:13px;flex-shrink:0}
.main-grid{display:grid;grid-template-columns:300px 1fr;gap:16px;align-items:start}
@media(max-width:900px){.main-grid{grid-template-columns:1fr}}
.sidebar{display:flex;flex-direction:column;gap:14px}
.panel{padding:18px}
.panel-title{font-size:.65rem;font-weight:600;letter-spacing:.18em;text-transform:uppercase;color:var(--muted);margin-bottom:14px;display:flex;align-items:center;gap:7px}
.panel-title-dot{width:6px;height:6px;border-radius:50%;background:var(--gold)}
.field{margin-bottom:12px}
.field-label{display:flex;justify-content:space-between;align-items:center;font-size:.62rem;color:var(--muted);letter-spacing:.12em;text-transform:uppercase;margin-bottom:5px}
.field-value{color:var(--teal);font-weight:600}
textarea.inp,input.inp{width:100%;padding:9px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--white);font-family:'Cascadia Code','Consolas',monospace;font-size:.75rem;line-height:1.6;resize:vertical;transition:border-color .2s,box-shadow .2s}
textarea.inp:focus,input.inp:focus{outline:none;border-color:var(--teal);box-shadow:0 0 0 3px var(--teal-dim)}
input[type=range].slider{-webkit-appearance:none;width:100%;height:5px;border-radius:3px;background:var(--border);outline:none;margin:6px 0}
input[type=range].slider::-webkit-slider-thumb{-webkit-appearance:none;width:15px;height:15px;border-radius:50%;background:var(--teal);cursor:pointer;box-shadow:0 0 8px var(--teal-glow)}
.toggle-row{display:flex;align-items:center;justify-content:space-between;padding:9px 12px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface);margin-bottom:8px}
.toggle-label{font-size:.8rem;color:var(--text)}
.toggle-wrap{position:relative;width:40px;height:22px;flex-shrink:0}
.toggle-input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%;z-index:2;margin:0}
.toggle-track{position:absolute;inset:0;border-radius:999px;background:var(--border);border:1px solid var(--border);transition:background .25s,border-color .25s}
.toggle-thumb{position:absolute;top:3px;left:3px;width:14px;height:14px;border-radius:50%;background:#fff;transition:transform .25s}
.toggle-input:checked~.toggle-track{background:var(--teal);border-color:var(--teal)}
.toggle-input:checked~.toggle-thumb{transform:translateX(18px)}
select.inp{width:100%;padding:8px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--white);font-size:.78rem;cursor:pointer;transition:border-color .2s}
select.inp:focus{outline:none;border-color:var(--teal)}
.btn-row{display:flex;gap:8px;margin-top:14px}
.btn{flex:1;padding:11px 16px;border-radius:var(--radius-sm);border:none;cursor:pointer;font-size:.82rem;font-weight:700;display:flex;align-items:center;justify-content:center;gap:7px;transition:all .25s}
.btn-scan{background:linear-gradient(135deg,var(--gold),var(--gold2));color:#0a0a0f;box-shadow:0 4px 14px var(--gold-glow)}
.btn-scan:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 6px 20px var(--gold-glow)}
.btn-scan:disabled{background:var(--surface);color:var(--muted);box-shadow:none;cursor:not-allowed;border:1px solid var(--border)}
.btn-stop{background:var(--red-dim);color:var(--red);border:1px solid rgba(248,113,113,.25)}
.btn-stop:hover:not(:disabled){background:rgba(248,113,113,.2)}
.btn-export{padding:7px 14px;border-radius:var(--radius-sm);border:1px solid rgba(0,212,170,.25);background:var(--teal-dim);color:var(--teal);font-size:.72rem;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:6px;transition:all .2s}
.btn-export:hover{background:rgba(0,212,170,.2)}
.spin{animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.hidden{display:none!important}
.metrics{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:14px}
.metric{padding:10px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface);text-align:center}
.metric.gold{border-color:rgba(255,215,0,.2);background:var(--gold-dim)}
.metric.teal{border-color:rgba(0,212,170,.2);background:var(--teal-dim)}
.metric.red{border-color:rgba(248,113,113,.2);background:var(--red-dim)}
.metric.green{border-color:rgba(52,211,153,.2);background:var(--green-dim)}
.metric-num{font-family:'Cascadia Code','Consolas',monospace;font-size:1.5rem;font-weight:700;line-height:1;margin-bottom:4px}
.metric.gold .metric-num{color:var(--gold)}
.metric.teal .metric-num{color:var(--teal)}
.metric.red .metric-num{color:var(--red)}
.metric.green .metric-num{color:var(--green)}
.metric-lbl{font-size:.55rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.progress-wrap{height:4px;border-radius:2px;background:var(--border);overflow:hidden;margin-top:12px}
.progress-bar{height:100%;border-radius:2px;background:linear-gradient(90deg,var(--teal),var(--gold));transition:width .4s ease;width:0%}
.results-panel{display:flex;flex-direction:column;overflow:hidden;max-height:820px}
.results-header{padding:14px 18px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:8px}
.results-title{font-size:.65rem;font-weight:600;letter-spacing:.18em;text-transform:uppercase;color:var(--muted);display:flex;align-items:center;gap:7px}
.status-chip{font-size:.65rem;font-weight:600;padding:3px 10px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--muted);transition:all .3s}
.status-chip.scanning{background:var(--teal-dim);color:var(--teal);border-color:rgba(0,212,170,.3)}
.status-chip.done{background:var(--green-dim);color:var(--green);border-color:rgba(52,211,153,.3)}
.status-chip.stopped{background:var(--amber-dim);color:var(--amber);border-color:rgba(251,191,36,.3)}
.status-chip.error{background:var(--red-dim);color:var(--red);border-color:rgba(248,113,113,.3)}
.table-wrap{flex:1;overflow:auto;scrollbar-width:thin;scrollbar-color:var(--border) transparent}
.table-wrap::-webkit-scrollbar{width:5px;height:5px}
.table-wrap::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
table{width:100%;border-collapse:collapse}
thead th{padding:9px 16px;text-align:left;font-size:.58rem;letter-spacing:.18em;text-transform:uppercase;color:var(--muted);background:var(--surface);position:sticky;top:0;z-index:1;border-bottom:1px solid var(--border);white-space:nowrap}
tbody tr{border-bottom:1px solid var(--border);transition:background .15s}
tbody tr:hover{background:var(--surface)}
tbody tr.row-both{border-left:3px solid var(--teal)}
tbody tr.row-tcp{border-left:3px solid var(--gold)}
tbody tr.row-ping{border-left:3px solid var(--amber)}
tbody tr.row-dead{border-left:3px solid transparent;opacity:.5}
tbody td{padding:9px 16px;font-family:'Cascadia Code','Consolas',monospace;font-size:.72rem;white-space:nowrap}
.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:5px;font-size:.62rem;font-weight:600;letter-spacing:.05em}
.badge-ok{background:var(--green-dim);color:var(--green)}
.badge-fail{background:var(--red-dim);color:var(--red)}
.badge-ms{background:var(--teal-dim);color:var(--teal)}
.cdn-cloudflare{background:rgba(249,115,22,.12);color:#fb923c}
.cdn-google{background:rgba(59,130,246,.12);color:#60a5fa}
.cdn-fastly{background:rgba(239,68,68,.12);color:#f87171}
.cdn-akamai{background:rgba(16,185,129,.12);color:#34d399}
.cdn-netlify{background:rgba(99,102,241,.12);color:#a5b4fc}
.cdn-vercel{background:rgba(255,255,255,.08);color:#e2e8f0}
.cdn-cloudfront{background:rgba(255,165,0,.12);color:#ffa500}
.cdn-bunnycdn{background:rgba(255,105,180,.12);color:#ff69b4}
.cdn-gcore{background:rgba(0,191,255,.12);color:#00bfff}
.cdn-unknown{background:var(--surface);color:var(--muted)}
.empty-state{padding:60px 20px;text-align:center;color:var(--muted)}
.empty-state-icon{font-size:2.5rem;margin-bottom:12px;opacity:.4}
.empty-state-text{font-size:.82rem}

/* فیلتر خروجی */
.export-filter{padding:12px 18px;border-top:1px solid var(--border);display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:var(--surface)}
.export-filter-label{font-size:.6rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);white-space:nowrap}
.filter-chips{display:flex;gap:6px;flex-wrap:wrap}
.filter-chip{padding:4px 10px;border-radius:999px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:.65rem;font-weight:600;cursor:pointer;transition:all .2s;letter-spacing:.04em}
.filter-chip.active-both{background:var(--teal-dim);color:var(--teal);border-color:rgba(0,212,170,.4)}
.filter-chip.active-tcp{background:var(--gold-dim);color:var(--gold);border-color:rgba(255,215,0,.4)}
.filter-chip.active-ping{background:var(--amber-dim);color:var(--amber);border-color:rgba(251,191,36,.4)}
.filter-chip.active-cdn{background:rgba(249,115,22,.12);color:#fb923c;border-color:rgba(249,115,22,.3)}
.filter-chip.active-all{background:var(--green-dim);color:var(--green);border-color:rgba(52,211,153,.4)}

.tabs{display:flex;gap:2px;background:var(--bg3);border-radius:var(--radius-sm);padding:3px;margin-bottom:14px}
.tab-btn{flex:1;padding:7px 6px;border-radius:6px;border:none;background:transparent;color:var(--muted);font-size:.68rem;font-weight:600;cursor:pointer;letter-spacing:.05em;transition:all .2s;white-space:nowrap}
.tab-btn.active{background:var(--bg2);color:var(--gold);border:1px solid var(--border-hi);box-shadow:0 1px 4px rgba(0,0,0,.3)}
.tab-panel{display:none}
.tab-panel.active{display:block}
.tpl-grid{display:flex;flex-direction:column;gap:7px}
.tpl-card{padding:10px 12px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface);cursor:pointer;transition:all .2s;display:flex;align-items:flex-start;gap:10px}
.tpl-card:hover{border-color:var(--gold);background:var(--gold-dim)}
.tpl-card.empty-tpl{border-style:dashed;opacity:.6;cursor:default;pointer-events:none}
.tpl-icon{font-size:1.3rem;flex-shrink:0;margin-top:1px}
.tpl-name{font-size:.78rem;font-weight:700;color:var(--white);margin-bottom:2px}
.tpl-desc{font-size:.62rem;color:var(--muted);line-height:1.4}
.tpl-count{margin-left:auto;flex-shrink:0;font-size:.6rem;font-weight:600;padding:2px 7px;border-radius:4px;background:var(--teal-dim);color:var(--teal);white-space:nowrap;align-self:center}
.drop-zone{border:2px dashed var(--border);border-radius:var(--radius-sm);padding:24px 16px;text-align:center;cursor:pointer;transition:all .2s;position:relative}
.drop-zone:hover,.drop-zone.dragover{border-color:var(--teal);background:var(--teal-dim)}
.drop-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.drop-icon{font-size:1.8rem;margin-bottom:8px;opacity:.6}
.drop-text{font-size:.72rem;color:var(--muted);line-height:1.5}
.drop-text strong{color:var(--teal)}
.subnet-info{display:inline-flex;align-items:center;gap:5px;font-size:.6rem;color:var(--gold);background:var(--gold-dim);border:1px solid rgba(255,215,0,.2);border-radius:4px;padding:2px 7px;margin-top:4px}
.toast-wrap{position:fixed;bottom:20px;right:20px;display:flex;flex-direction:column;gap:8px;z-index:9999}
.toast{padding:10px 16px;border-radius:var(--radius-sm);background:var(--bg3);border:1px solid var(--border-hi);color:var(--text);font-size:.78rem;box-shadow:0 8px 24px rgba(0,0,0,.3);animation:slideIn .3s ease;max-width:300px}
@keyframes slideIn{from{transform:translateX(120%);opacity:0}to{transform:translateX(0);opacity:1}}
</style>
</head>
<body>
<div class="app">

  <div class="card header">
    <div class="brand">
      <div class="brand-icon">📡</div>
      <div>
        <div class="brand-name">PowerCodes</div>
        <div class="brand-ver">v2.0 · IP + Domain CDN</div>
      </div>
    </div>
    <div class="header-right">
      <div class="promo-links">
        <a href="{{ tg }}" target="_blank" class="promo-link">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12s5.37 12 12 12 12-5.37 12-12S18.63 0 12 0zm5.562 8.247l-2.01 9.478c-.15.668-.54.832-1.094.518l-3-2.21-1.447 1.393c-.16.16-.295.295-.604.295l.215-3.053 5.56-5.023c.242-.215-.052-.334-.373-.12L7.28 14.64 4.316 13.7c-.658-.206-.67-.658.138-.975l10.874-4.193c.548-.198 1.027.134.834.972z"/></svg>
          Telegram
        </a>
        <a href="{{ yt }}" target="_blank" class="promo-link">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M23.5 6.2a3.01 3.01 0 0 0-2.12-2.13C19.55 3.6 12 3.6 12 3.6s-7.55 0-9.38.47A3.01 3.01 0 0 0 .5 6.2C0 8.04 0 12 0 12s0 3.96.5 5.8a3.01 3.01 0 0 0 2.12 2.13C4.45 20.4 12 20.4 12 20.4s7.55 0 9.38-.47a3.01 3.01 0 0 0 2.12-2.13C24 15.96 24 12 24 12s0-3.96-.5-5.8zM9.6 15.6V8.4l6.28 3.6-6.28 3.6z"/></svg>
          YouTube
        </a>
        <a href="{{ gh }}" target="_blank" class="promo-link">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.2 11.39.6.11.82-.26.82-.58v-2.03c-3.34.72-4.04-1.61-4.04-1.61-.54-1.37-1.32-1.74-1.32-1.74-1.08-.74.08-.72.08-.72 1.19.08 1.82 1.22 1.82 1.22 1.06 1.82 2.78 1.29 3.46.99.1-.77.41-1.29.75-1.59-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.12-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 3-.4c1.02 0 2.04.14 3 .4 2.28-1.55 3.29-1.23 3.29-1.23.66 1.66.24 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.81 5.63-5.48 5.92.43.37.81 1.1.81 2.22v3.29c0 .32.22.69.83.58C20.56 21.8 24 17.3 24 12c0-6.63-5.37-12-12-12z"/></svg>
          GitHub
        </a>
      </div>
      <button class="theme-btn" id="themeBtn" title="Change Theme">🌙</button>
    </div>
  </div>

  <div class="main-grid">
    <div class="sidebar">
      <div class="card panel">
        <div class="panel-title"><span class="panel-title-dot"></span>Scan Targets</div>
        <div class="tabs">
          <button class="tab-btn active" onclick="switchTab('manual')">Manual</button>
          <button class="tab-btn" onclick="switchTab('template')">Template</button>
          <button class="tab-btn" onclick="switchTab('file')">File</button>
        </div>

        <div class="tab-panel active" id="tab-manual">
          <div class="field">
            <label class="field-label">IP / Subnet / Domain<span class="field-value" id="targetCount">0</span></label>
            <textarea class="inp" id="targetsInput" rows="8"
              placeholder="one per line:&#10;1.2.3.4&#10;192.168.1.0/24&#10;example.com"></textarea>
            <div style="font-size:.6rem;color:var(--muted);margin-top:4px;">CIDR subnets expand · duplicates removed</div>
            <div id="subnetInfo" class="subnet-info hidden">📡 <span id="subnetCount">0</span> IPs from subnets</div>
          </div>
        </div>

        <div class="tab-panel" id="tab-template">
          <div class="tpl-grid" id="tplGrid"></div>
          <div style="margin-top:10px;font-size:.62rem;color:var(--muted);">Place <code style="color:var(--teal)">targets.txt</code> next to the script</div>
        </div>

        <div class="tab-panel" id="tab-file">
          <div class="drop-zone" id="dropZone">
            <input type="file" id="fileInput" accept=".txt,.csv,.list">
            <div class="drop-icon">📂</div>
            <div class="drop-text">Drop TXT file here<br>or <strong>click to select</strong></div>
          </div>
          <div id="fileInfo" style="margin-top:8px;font-size:.65rem;color:var(--muted);display:none;"></div>
        </div>

        <div style="margin-top:14px;">
          <div class="field">
            <label class="field-label">TCP Port<span class="field-value" id="portVal">443</span></label>
            <input class="inp" type="number" id="portInput" value="443" min="1" max="65535">
          </div>
          <div class="field">
            <label class="field-label">Ping Timeout (ms)<span class="field-value" id="pingTOVal">1500</span></label>
            <input type="range" class="slider" id="pingTO" min="500" max="5000" step="250" value="1500">
          </div>
          <div class="field">
            <label class="field-label">TCP Timeout (s)<span class="field-value" id="tcpTOVal">2</span></label>
            <input type="range" class="slider" id="tcpTO" min="0.5" max="10" step="0.5" value="2">
          </div>
          <div class="field">
            <label class="field-label">Threads<span class="field-value" id="workersVal">50</span></label>
            <input type="range" class="slider" id="workersSlider" min="5" max="200" step="5" value="50">
          </div>
          <div class="toggle-row">
            <span class="toggle-label">Auto Sort</span>
            <label class="toggle-wrap">
              <input type="checkbox" class="toggle-input" id="autoSortToggle" checked>
              <span class="toggle-track"></span><span class="toggle-thumb"></span>
            </label>
          </div>
          <div class="field" style="margin-top:8px;">
            <label class="field-label">Sort By</label>
            <select class="inp" id="sortBy">
              <option value="status">Status (both first)</option>
              <option value="ping">Ping (lowest first)</option>
              <option value="tcp">TCP (lowest first)</option>
              <option value="cdn_cf">Cloudflare first</option>
              <option value="cdn_g">Google first</option>
              <option value="cdn_nl">Netlify first</option>
              <option value="cdn_vc">Vercel first</option>
              <option value="cdn_fy">Fastly first</option>
              <option value="cdn_ak">Akamai first</option>
              <option value="cdn_cf2">CloudFront first</option>
            </select>
          </div>
        </div>

        <div class="btn-row">
          <button class="btn btn-scan" id="scanBtn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5,3 19,12 5,21"/></svg>
            <span>Start Scan</span>
          </button>
          <button class="btn btn-stop hidden" id="stopBtn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="5" width="14" height="14" rx="2"/></svg>
            <span>Stop</span>
          </button>
        </div>

        <div class="metrics">
          <div class="metric teal"><div class="metric-num" id="mBoth">0</div><div class="metric-lbl">Ping + TCP</div></div>
          <div class="metric gold"><div class="metric-num" id="mTcp">0</div><div class="metric-lbl">TCP Only</div></div>
          <div class="metric green"><div class="metric-num" id="mScanned">0</div><div class="metric-lbl">Scanned</div></div>
          <div class="metric red"><div class="metric-num" id="mDead">0</div><div class="metric-lbl">Dead</div></div>
        </div>
        <div class="progress-wrap"><div class="progress-bar" id="progressBar"></div></div>
      </div>
    </div>

    <div class="card results-panel">
      <div class="results-header">
        <div class="results-title"><span class="panel-title-dot"></span>Scan Results</div>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="status-chip" id="statusChip">Ready</span>
          <button class="btn-export" id="exportBtn">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Export
          </button>
        </div>
      </div>

      <!-- فیلتر خروجی -->
      <div class="export-filter">
        <span class="export-filter-label">Filter Export:</span>
        <div class="filter-chips">
          <button class="filter-chip active-all" data-filter="all" onclick="setExportFilter(this,'all')">All</button>
          <button class="filter-chip" data-filter="both" onclick="setExportFilter(this,'both')">Ping + TCP</button>
          <button class="filter-chip" data-filter="tcp_only" onclick="setExportFilter(this,'tcp_only')">TCP Only</button>
          <button class="filter-chip" data-filter="ping_only" onclick="setExportFilter(this,'ping_only')">Ping Only</button>
          <button class="filter-chip" data-filter="Cloudflare" onclick="setExportFilter(this,'Cloudflare')">Cloudflare</button>
          <button class="filter-chip" data-filter="Vercel" onclick="setExportFilter(this,'Vercel')">Vercel</button>
          <button class="filter-chip" data-filter="Netlify" onclick="setExportFilter(this,'Netlify')">Netlify</button>
          <button class="filter-chip" data-filter="Fastly" onclick="setExportFilter(this,'Fastly')">Fastly</button>
          <button class="filter-chip" data-filter="Google" onclick="setExportFilter(this,'Google')">Google</button>
          <button class="filter-chip" data-filter="Akamai" onclick="setExportFilter(this,'Akamai')">Akamai</button>
        </div>
      </div>

      <div class="table-wrap">
        <table>
          <thead><tr><th>#</th><th>Target</th><th>Resolved IP</th><th>CDN</th><th>Ping</th><th>TCP</th><th>Status</th><th>Time</th></tr></thead>
          <tbody id="tableBody">
            <tr><td colspan="8"><div class="empty-state"><div class="empty-state-icon">📡</div><div class="empty-state-text">Enter IPs, subnets or domains and start scan</div></div></td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<div class="toast-wrap" id="toastWrap"></div>

<script>
let results = [], scanning = false, reader = null;
let exportFilter = 'all';
const $ = id => document.getElementById(id);

function toast(msg, type='info') {
  const el = document.createElement('div');
  el.className = 'toast';
  el.style.borderColor = type==='ok' ? 'var(--teal)' : type==='err' ? 'var(--red)' : 'var(--gold)';
  el.textContent = msg;
  $('toastWrap').appendChild(el);
  setTimeout(() => el.remove(), 3800);
}

let dark = true;
$('themeBtn').addEventListener('click', () => {
  dark = !dark;
  document.documentElement.setAttribute('data-theme', dark ? '' : 'light');
  $('themeBtn').textContent = dark ? '🌙' : '☀️';
});

$('pingTO').addEventListener('input', e => $('pingTOVal').textContent = e.target.value);
$('tcpTO').addEventListener('input',  e => $('tcpTOVal').textContent  = e.target.value);
$('workersSlider').addEventListener('input', e => $('workersVal').textContent = e.target.value);
$('portInput').addEventListener('input', e => $('portVal').textContent = e.target.value);


function setExportFilter(btn, filter) {
  document.querySelectorAll('.filter-chip').forEach(c => {
    c.className = 'filter-chip';
  });
  const cls = filter==='all'?'active-all':filter==='both'?'active-both':filter==='tcp_only'?'active-tcp':filter==='ping_only'?'active-ping':'active-cdn';
  btn.classList.add(cls);
  exportFilter = filter;
}

function applyFilter(arr) {
  if (exportFilter === 'all') return arr;
  if (['both','tcp_only','ping_only','dead'].includes(exportFilter))
    return arr.filter(r => r.status === exportFilter);
  return arr.filter(r => r.cdn === exportFilter);
}

function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach((btn, i) => {
    btn.classList.toggle('active', ['manual','template','file'][i] === name);
  });
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  $('tab-' + name).classList.add('active');
  if (name === 'template') loadTemplates();
}

async function loadTemplates() {
  const grid = $('tplGrid');
  grid.innerHTML = '<div style="color:var(--muted);font-size:.75rem;padding:8px;">Loading...</div>';
  try {
    const resp = await fetch('/templates');
    const data = await resp.json();
    if (!data.templates || data.templates.length === 0) {
      grid.innerHTML = `<div class="tpl-card empty-tpl"><div class="tpl-icon">📭</div><div><div class="tpl-name">No templates found</div><div class="tpl-desc">Place targets.txt next to the script</div></div></div>`;
      return;
    }
    grid.innerHTML = data.templates.map(tpl => `
      <div class="tpl-card" onclick="loadTemplate('${tpl.file}')">
        <div class="tpl-icon">${tpl.icon}</div>
        <div style="flex:1"><div class="tpl-name">${tpl.name}</div><div class="tpl-desc">${tpl.desc}</div></div>
        <div class="tpl-count">${tpl.count} targets</div>
      </div>`).join('');
  } catch(e) {
    grid.innerHTML = `<div class="tpl-card empty-tpl"><div class="tpl-icon">Warning</div><div><div class="tpl-name">Load error</div></div></div>`;
  }
}

async function loadTemplate(filename) {
  try {
    const resp = await fetch('/template/' + encodeURIComponent(filename));
    const data = await resp.json();
    if (data.content) { $('targetsInput').value = data.content; switchTab('manual'); debounceClean(); toast(`Template "${filename}" loaded`, 'ok'); }
  } catch(e) { toast('Error loading template', 'err'); }
}

const dropZone = $('dropZone'), fileInput = $('fileInput');
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => { e.preventDefault(); dropZone.classList.remove('dragover'); const f = e.dataTransfer.files[0]; if(f) handleFile(f); });
fileInput.addEventListener('change', e => { if(e.target.files[0]) handleFile(e.target.files[0]); });

function handleFile(file) {
  if (!file.name.match(/\.(txt|csv|list)$/i)) { toast('Only TXT/CSV/List files', 'err'); return; }
  const rf = new FileReader();
  rf.onload = e => {
    const content = e.target.result;
    $('targetsInput').value = content;
    const lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
    $('fileInfo').style.display = 'block';
    $('fileInfo').innerHTML = `File: <strong>${file.name}</strong> — ${lines.length} lines`;
    switchTab('manual'); debounceClean(); toast(`"${file.name}" loaded`, 'ok');
  };
  rf.readAsText(file, 'UTF-8');
}

$('targetsInput').addEventListener('input', debounceClean);
let cleanTimer;
function debounceClean() { clearTimeout(cleanTimer); cleanTimer = setTimeout(updateCount, 400); }

function updateCount() {
  const raw = $('targetsInput').value;
  const { ips, domains, subnetTotal } = parseTargetsClient(raw);
  const total = ips.size + domains.size + subnetTotal;
  $('targetCount').textContent = total;
  if (subnetTotal > 0) { $('subnetInfo').classList.remove('hidden'); $('subnetCount').textContent = subnetTotal; }
  else $('subnetInfo').classList.add('hidden');
}

function parseTargetsClient(raw) {
  const cidrRe = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\b/g;
  const ipRe   = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const domRe  = /\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b/g;
  const ips = new Set(), domains = new Set(); let subnetTotal = 0, m;
  for (const line of raw.split('\n')) {
    const l = line.trim(); if (!l || l.startsWith('#')) continue;
    let cidrFound = false;
    while ((m = cidrRe.exec(l)) !== null) { cidrFound = true; const prefix = parseInt(m[1].split('/')[1]); subnetTotal += Math.max(1, Math.pow(2,32-prefix)-2); }
    cidrRe.lastIndex = 0;
    const stripped = l.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}\b/g,'');
    while ((m = ipRe.exec(cidrFound ? stripped : l)) !== null) ips.add(m[1]); ipRe.lastIndex = 0;
    const forDom = l.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?\b/g,'');
    while ((m = domRe.exec(forDom)) !== null) { const d = m[1].toLowerCase(); if(d.length>3) domains.add(d); } domRe.lastIndex = 0;
  }
  return { ips, domains, subnetTotal: Math.min(subnetTotal, 99999) };
}

const CDN_PRIORITY = { 'Cloudflare':'cdn_cf','Google':'cdn_g','Netlify':'cdn_nl','Vercel':'cdn_vc','Fastly':'cdn_fy','Akamai':'cdn_ak','CloudFront':'cdn_cf2' };

function sortResults(arr) {
  const mode = $('sortBy').value;
  return [...arr].sort((a,b) => {
    if (mode==='status') { const s=r=>r.status==='both'?0:r.status==='tcp_only'?1:r.status==='ping_only'?2:3; return s(a)-s(b)||(a.ping_ms||9999)-(b.ping_ms||9999); }
    if (mode==='ping') { if(!a.ping_ok&&b.ping_ok) return 1; if(a.ping_ok&&!b.ping_ok) return -1; return (a.ping_ms||9999)-(b.ping_ms||9999); }
    if (mode==='tcp')  { if(!a.tcp_ok&&b.tcp_ok) return 1; if(a.tcp_ok&&!b.tcp_ok) return -1; return (a.tcp_ms||9999)-(b.tcp_ms||9999); }
    if (mode.startsWith('cdn_')) { const t=Object.keys(CDN_PRIORITY).find(k=>CDN_PRIORITY[k]===mode); if(a.cdn===t&&b.cdn!==t) return -1; if(b.cdn===t&&a.cdn!==t) return 1; return (a.ping_ms||9999)-(b.ping_ms||9999); }
    return 0;
  });
}

$('sortBy').addEventListener('change', renderTable);
$('autoSortToggle').addEventListener('change', renderTable);

function renderTable() {
  const rows = $('autoSortToggle').checked ? sortResults(results) : results;
  const tbody = $('tableBody');
  if (rows.length===0) { tbody.innerHTML=`<tr><td colspan="8"><div class="empty-state"><div class="empty-state-icon">📡</div><div class="empty-state-text">Enter IPs, subnets or domains and start scan</div></div></td></tr>`; return; }
  tbody.innerHTML = rows.map((r,i) => {
    const rowClass = r.status==='both'?'row-both':r.status==='tcp_only'?'row-tcp':r.status==='ping_only'?'row-ping':'row-dead';
    const cdnKey = (r.cdn||'unknown').toLowerCase().replace(/\s/g,'');
    const cdnBadge = `<span class="badge cdn-${cdnKey}">${r.cdn||'Unknown'}</span>`;
    const pingBadge = r.ping_ok ? `<span class="badge badge-ms">${r.ping_ms != null ? r.ping_ms+'ms' : 'OK'}</span>` : `<span class="badge badge-fail">--</span>`;
    const tcpBadge  = r.tcp_ok  ? `<span class="badge badge-ms">${r.tcp_ms  != null ? r.tcp_ms+'ms'  : 'OK'}</span>` : `<span class="badge badge-fail">--</span>`;
    const statusMap = {both:'[OK] Both',tcp_only:'[TCP]',ping_only:'[Ping]',dead:'[Dead]'};
    const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(r.target);
    const resolvedCell = (!isIP&&r.resolved_ip) ? `<span style="font-family:monospace;font-size:.68rem;color:var(--teal)">${r.resolved_ip}</span>` : `<span style="color:var(--muted);font-size:.65rem">-</span>`;
    return `<tr class="${rowClass}"><td style="color:var(--muted)">${i+1}</td><td style="color:var(--white);font-weight:600;font-family:monospace">${r.target}</td><td>${resolvedCell}</td><td>${cdnBadge}</td><td>${pingBadge}</td><td>${tcpBadge}</td><td>${statusMap[r.status]||r.status}</td><td style="color:var(--muted)">${r.time}</td></tr>`;
  }).join('');
}

function updateMetrics(total) {
  $('mBoth').textContent    = results.filter(r=>r.status==='both').length;
  $('mTcp').textContent     = results.filter(r=>r.status==='tcp_only').length;
  $('mScanned').textContent = results.length;
  $('mDead').textContent    = results.filter(r=>r.status==='dead').length;
  $('progressBar').style.width = total>0 ? `${Math.round(results.length/total*100)}%` : '0%';
}

$('scanBtn').addEventListener('click', startScan);
$('stopBtn').addEventListener('click', stopScan);

async function startScan() {
  const raw = $('targetsInput').value.trim();
  if (!raw) { toast('Enter at least one target', 'err'); return; }
  results = []; scanning = true;
  $('scanBtn').classList.add('hidden');
  $('stopBtn').classList.remove('hidden');
  $('statusChip').textContent = 'Scanning...';
  $('statusChip').className = 'status-chip scanning';
  renderTable();

  try {
    const response = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targets:  raw,
        port:     $('portInput').value,
        ping_to:  $('pingTO').value,
        tcp_to:   $('tcpTO').value,
        workers:  $('workersSlider').value,
      })
    });
    reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.startsWith('data:')) continue;
        try {
          const data = JSON.parse(line.slice(5).trim());
          if (data.type==='result') { results.push(data); updateMetrics(data.total); renderTable(); }
          else if (data.type==='done')  finishScan('done');
          else if (data.type==='error') { toast(data.msg,'err'); finishScan('error'); }
        } catch {}
      }
    }
    if (scanning) finishScan('done');
  } catch(e) {
    if (scanning) { toast('Connection error','err'); finishScan('error'); }
  }
}

async function stopScan() {
  scanning = false;
  if (reader) { try { reader.cancel(); } catch {} }
  await fetch('/stop', { method:'POST' });
  finishScan('stopped');
}

function finishScan(state) {
  scanning = false;
  $('scanBtn').classList.remove('hidden');
  $('stopBtn').classList.add('hidden');
  const map = { done:['Done','done'], stopped:['Stopped','stopped'], error:['Error','error'] };
  const [txt,cls] = map[state]||['Ready',''];
  $('statusChip').textContent = txt;
  $('statusChip').className = 'status-chip '+cls;
  updateMetrics(results.length);
  renderTable();
  if (state==='done') toast(`Scan complete - ${results.length} targets checked`,'ok');
}

$('exportBtn').addEventListener('click', async () => {
  if (results.length===0) { toast('No results to export','err'); return; }
  const filtered = applyFilter(results);
  if (filtered.length===0) { toast('No results match current filter','err'); return; }
  const resp = await fetch('/export', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ results: filtered, filter: exportFilter })
  });
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = '@powercodes_' + new Date().toISOString().slice(0,19).replace(/:/g,'-') + '.txt';
  a.click();
  URL.revokeObjectURL(url);
  toast(`Exported ${filtered.length} results`,'ok');
});

updateCount();
</script>
</body>
</html>
"""

# ══════════════════════════════════════════════════════════════════
#  Flask App
# ══════════════════════════════════════════════════════════════════
app = Flask(__name__)


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE, tg=TELEGRAM_CHANNEL, yt=YOUTUBE_CHANNEL, gh=GITHUB_REPO)


@app.route("/scan", methods=["POST"])
def scan():
    data         = request.get_json(force=True)
    raw_targets  = data.get("targets", "")
    port         = int(data.get("port", 443))
    ping_timeout = int(float(data.get("ping_to", 1500)))
    tcp_timeout  = float(data.get("tcp_to", 2.0))
    workers      = int(data.get("workers", 50))

    targets = clean_targets(raw_targets)

    if not targets:
        def empty_gen():
            yield 'data: {"type":"error","msg":"No valid targets found"}\n\n'
        return Response(stream_with_context(empty_gen()), mimetype="text/event-stream")

    with scan_state["lock"]:
        scan_state["running"] = True
        scan_state["results"] = []
        scan_state["total"]   = len(targets)
        scan_state["scanned"] = 0

    def generate():
        total = len(targets)
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, total)) as executor:
            futures = {
                executor.submit(scan_single, t, port, ping_timeout, tcp_timeout): t
                for t in targets
            }
            for future in concurrent.futures.as_completed(futures):
                with scan_state["lock"]:
                    if not scan_state["running"]:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                try:
                    result = future.result()
                    result["total"] = total
                    result["type"]  = "result"
                    with scan_state["lock"]:
                        scan_state["results"].append(result)
                        scan_state["scanned"] += 1
                    yield f"data: {json.dumps(result, ensure_ascii=False)}\n\n"
                except Exception:
                    pass
        yield 'data: {"type":"done"}\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@app.route("/stop", methods=["POST"])
def stop():
    with scan_state["lock"]:
        scan_state["running"] = False
    return jsonify({"ok": True})


@app.route("/templates")
def templates():
    tpl_files = list(Path(".").glob("targets*.txt"))
    result = []
    for f in tpl_files:
        try:
            lines = [l.strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
            result.append({"file": f.name, "name": f.stem, "desc": f"File {f.name}", "icon": "File", "count": len(lines)})
        except Exception:
            pass
    return jsonify({"templates": result})


@app.route("/template/<filename>")
def template_file(filename):
    try:
        content = Path(filename).read_text(encoding="utf-8")
        return jsonify({"content": content})
    except Exception:
        return jsonify({"content": ""}), 404


@app.route("/export", methods=["POST"])
def export():
    data    = request.get_json()
    results = data.get("results", [])
    filter_ = data.get("filter", "all")
    now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    both      = [r for r in results if r["status"] == "both"]
    tcp_only  = [r for r in results if r["status"] == "tcp_only"]
    ping_only = [r for r in results if r["status"] == "ping_only"]


    lines = [
        "#",
        f"# {TOOL_NAME} v{TOOL_VERSION}",
        f"# Scan output - {now}",
        f"# Filter: {filter_}",
        "#",
        f"# Telegram : {TELEGRAM_CHANNEL}",
        f"# YouTube  : {YOUTUBE_CHANNEL}",
        f"# GitHub   : {GITHUB_REPO}",
        "#",
        f"# Total: {len(results)} | Ping+TCP: {len(both)} | TCP: {len(tcp_only)} | Ping: {len(ping_only)}",
        "#",
        "",
    ]

    if both:
        lines.append("# -- Ping + TCP -------------------------")
        for r in sorted(both, key=lambda x: x.get("ping_ms") or 9999):
            ms = f"{r['ping_ms']}ms" if r.get("ping_ms") is not None else ""
            cdn = r.get("cdn","")
            lines.append(r['target'])
        lines.append("")

    if tcp_only:
        lines.append("# -- TCP Only ---------------------------")
        for r in sorted(tcp_only, key=lambda x: x.get("tcp_ms") or 9999):
            cdn = r.get("cdn","")
            lines.append(r['target'])
        lines.append("")

    if ping_only:
        lines.append("# -- Ping Only --------------------------")
        for r in sorted(ping_only, key=lambda x: x.get("ping_ms") or 9999):
            lines.append(r['target'])
        lines.append("")

    return Response(
        "\n".join(lines),
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=@powercodes_scan.txt"}
    )


# ══════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    port_http = 5000
    url = f"http://127.0.0.1:{port_http}"
    print(f"""
+----------------------------------------------+
  {TOOL_NAME} v{TOOL_VERSION}
  {url}
+----------------------------------------------+
  Telegram : {TELEGRAM_HANDLE}
  GitHub   : {GITHUB_REPO}
""")
    threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    app.run(host="0.0.0.0", port=port_http, debug=False, threaded=True)
