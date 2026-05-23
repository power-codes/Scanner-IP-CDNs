#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PowerCodes — IP & Domain Scanner  v3.0
@powercodes | github.com/power-codes
مشکی / طلایی — ساده، تمیز، بدون باگ
"""

import concurrent.futures
import ipaddress
import os
import platform
import re
import socket
import subprocess
import threading
import time
from datetime import datetime

os.environ.setdefault("KIVY_NO_ENV_CONFIG", "1")
os.environ.setdefault("KIVY_WINDOW", "sdl2")

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.graphics import Color, Rectangle, RoundedRectangle, Line
from kivy.metrics import dp
from kivy.properties import BooleanProperty, NumericProperty
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.modalview import ModalView
from kivy.uix.progressbar import ProgressBar
from kivy.uix.recycleboxlayout import RecycleBoxLayout
from kivy.uix.recycleview import RecycleView
from kivy.uix.recycleview.views import RecycleDataViewBehavior
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.widget import Widget

IS_WINDOWS = platform.system().lower() == "windows"
IS_ANDROID = "ANDROID_ARGUMENT" in os.environ or os.path.exists("/data/app")

# ───────────────────────────────────────────────────
#  رنگ‌ها
# ───────────────────────────────────────────────────
BG      = (.06, .06, .07, 1)
CARD    = (.10, .10, .12, 1)
ROW_ODD = (.08, .08, .10, 1)
ROW_EVN = (.11, .11, .13, 1)
BORDER  = (.20, .20, .25, 1)
GOLD    = (1.00, .82, .00, 1)
GOLD_DIM= (1.00, .82, .00, .20)
GREEN   = (.22, .85, .50, 1)
GREEN_D = (.22, .85, .50, .18)
RED     = (.90, .30, .30, 1)
RED_D   = (.90, .30, .30, .18)
AMBER   = (.98, .70, .10, 1)
MUTED   = (.42, .44, .50, 1)
WHITE   = (.95, .95, .97, 1)
TEXT    = (.75, .77, .82, 1)
R       = dp(8)

# ───────────────────────────────────────────────────
#  CDN
# ───────────────────────────────────────────────────
CDN_RANGES = [
    ("Cloudflare", [
        "1.0.0.0/24","1.1.1.0/24","103.21.244.0/22","103.22.200.0/22",
        "103.31.4.0/22","104.16.0.0/13","104.24.0.0/14","108.162.192.0/18",
        "131.0.72.0/22","141.101.64.0/18","162.158.0.0/15","172.64.0.0/13",
        "173.245.48.0/20","188.114.96.0/20","190.93.240.0/20",
        "197.234.240.0/22","198.41.128.0/17"]),
    ("Google", [
        "8.8.4.0/24","8.8.8.0/24","64.233.160.0/19","66.102.0.0/20",
        "66.249.64.0/19","74.125.0.0/16","104.132.0.0/14","108.177.0.0/17",
        "142.250.0.0/15","172.217.0.0/16","172.253.0.0/16","173.194.0.0/16",
        "209.85.128.0/17","216.58.192.0/19","216.239.32.0/19"]),
    ("Fastly", [
        "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24",
        "104.156.80.0/20","146.75.0.0/16","151.101.0.0/16","157.52.64.0/18",
        "167.82.0.0/17","199.27.72.0/21","199.232.0.0/16"]),
    ("Akamai", [
        "2.16.0.0/13","23.0.0.0/12","23.32.0.0/11","23.64.0.0/14",
        "23.72.0.0/13","23.192.0.0/11","63.0.0.0/8","69.192.0.0/16",
        "72.246.0.0/15","88.221.0.0/16","95.100.0.0/15","104.64.0.0/10",
        "184.24.0.0/13","184.50.0.0/15","184.84.0.0/14"]),
    ("Netlify", [
        "44.226.105.0/24","50.7.4.0/24","50.7.85.0/24",
        "54.182.0.0/16","99.83.128.0/17","162.159.128.0/20"]),
    ("Vercel", [
        "64.29.17.0/24","64.29.18.0/24","64.29.19.0/24",
        "66.33.60.0/24","66.33.61.0/24","76.76.21.0/24","76.223.126.0/24"]),
    ("CloudFront", [
        "52.46.0.0/18","52.84.0.0/15","54.182.0.0/16",
        "99.84.0.0/16","130.176.0.0/17"]),
    ("BunnyCDN", ["89.187.160.0/19","147.75.0.0/16"]),
    ("Gcore",    ["92.223.0.0/16","95.85.0.0/16","185.158.0.0/16"]),
    ("AbrArvan", ["185.220.226.0/24","185.143.232.0/22"]),
]

_nets = []
for _n, _rs in CDN_RANGES:
    for _r in _rs:
        try: _nets.append((ipaddress.ip_network(_r, strict=False), _n))
        except ValueError: pass

ALL_CDN = [n for n, _ in CDN_RANGES] + ["Unknown"]

CDN_COLOR = {
    "Cloudflare": (1.00, .45, .13, 1),
    "Google":     (.25, .52, .96, 1),
    "Fastly":     (.90, .30, .30, 1),
    "Akamai":     (.22, .85, .50, 1),
    "Netlify":    (.40, .40, .95, 1),
    "Vercel":     (.88, .88, .90, 1),
    "CloudFront": (1.00, .65, .00, 1),
    "BunnyCDN":   (1.00, .40, .70, 1),
    "Gcore":      (.00, .75, 1.00, 1),
    "AbrArvan":   (.40, .80, 1.00, 1),
    "Unknown":    MUTED,
}

# ───────────────────────────────────────────────────
#  CORE
# ───────────────────────────────────────────────────
def check_ping(host, timeout_ms=1500):
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout_ms / 1000 + 2,
                               startupinfo=si,
                               creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            return False, None
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms / 1000))), host]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout_ms / 1000 + 2)
        except Exception:
            return False, None
    out = (p.stdout or "") + (p.stderr or "")
    ok = p.returncode == 0
    ms = None
    m = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", out, re.I)
    if m:
        ms = float(m.group(1))
    return ok, ms


def check_tcp(target, port=443, timeout=2.0):
    try:
        t0 = time.perf_counter()
        with socket.create_connection((target, port), timeout=timeout):
            return True, round((time.perf_counter() - t0) * 1000, 1)
    except Exception:
        return False, None


_dns_cache, _dns_lock = {}, threading.Lock()


def resolve_domain(t):
    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    with _dns_lock:
        if t in _dns_cache:
            return _dns_cache[t]
    try:
        r = socket.gethostbyname(t)
        with _dns_lock:
            _dns_cache[t] = r
        return r
    except Exception:
        return t


def expand_subnet(cidr):
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        h = list(net.hosts()) or list(net)
        return [str(x) for x in h[:1024]]
    except ValueError:
        return []


_re_cidr = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2})\b')
_re_ip = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b')
_re_dom = re.compile(
    r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b')


def clean_targets(raw):
    targets = set()
    for line in raw.splitlines():
        if len(targets) >= 50000:
            break
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cf = False
        for m in _re_cidr.finditer(line):
            cf = True
            for ip in expand_subnet(m.group(1)):
                targets.add(ip)
                if len(targets) >= 50000:
                    break
        rem = _re_cidr.sub("", line) if cf else line
        for m in _re_ip.finditer(rem):
            try:
                ipaddress.ip_address(m.group(1))
                targets.add(m.group(1))
            except ValueError:
                pass
        rem2 = _re_ip.sub("", _re_cidr.sub("", line))
        for m in _re_dom.finditer(rem2):
            d = m.group(1).lower()
            if len(d) > 3:
                targets.add(d)
    return sorted(targets)[:50000]


def detect_cdn(ip):
    try:
        a = ipaddress.ip_address(ip)
        for net, name in _nets:
            if a in net:
                return name
    except ValueError:
        pass
    return "Unknown"


def scan_single(target, port, ping_ms_to, tcp_sec_to):
    cdn = "Unknown"
    resolved = None
    try:
        ipaddress.ip_address(target)
        resolved = target
        cdn = detect_cdn(target)
    except ValueError:
        r = resolve_domain(target)
        if r != target:
            resolved = r
            cdn = detect_cdn(r)
    ph = resolved or target
    p_ok, p_ms = check_ping(ph, timeout_ms=ping_ms_to)
    t_ok, t_ms = check_tcp(target, port=port, timeout=tcp_sec_to)
    status = ("both" if p_ok and t_ok else
              "tcp_only" if t_ok else
              "ping_only" if p_ok else "dead")
    return {
        "target": target,
        "resolved": resolved or "",
        "cdn": cdn,
        "ping_ok": p_ok,
        "ping_ms": round(p_ms, 1) if p_ms is not None else None,
        "tcp_ok": t_ok,
        "tcp_ms": t_ms,
        "status": status,
        "time": datetime.now().strftime("%H:%M:%S"),
    }


# ───────────────────────────────────────────────────
#  UI HELPERS
# ───────────────────────────────────────────────────

def mk_label(text="", color=None, size=dp(11), bold=False, halign="left", **kw):
    l = Label(text=text, color=color or TEXT,
              font_size=size, bold=bold,
              halign=halign, valign="middle", **kw)
    l.bind(size=lambda w, *_: setattr(w, "text_size", w.size))
    return l


class Card(BoxLayout):
    """کارت تیره با خط حاشیه"""
    def __init__(self, **kw):
        kw.setdefault("padding", dp(10))
        kw.setdefault("spacing", dp(6))
        super().__init__(**kw)
        self.bind(pos=self._draw, size=self._draw)

    def _draw(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*CARD)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[R])
            Color(*BORDER)
            Line(rounded_rectangle=[self.x, self.y, self.width, self.height, R], width=dp(.7))


class LineInput(TextInput):
    """ورودی تک‌خطی"""
    def __init__(self, **kw):
        kw.setdefault("multiline", False)
        kw.setdefault("background_color", (0, 0, 0, 0))
        kw.setdefault("foreground_color", WHITE)
        kw.setdefault("cursor_color", GOLD)
        kw.setdefault("hint_text_color", MUTED)
        kw.setdefault("font_size", dp(12))
        kw.setdefault("padding", [dp(10), dp(7)])
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height", dp(36))
        super().__init__(**kw)
        self.bind(pos=self._draw, size=self._draw)

    def _draw(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(.12, .12, .15, 1)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(6)])
            Color(*BORDER)
            Line(rounded_rectangle=[self.x, self.y, self.width, self.height, dp(6)], width=dp(.6))


class AreaInput(TextInput):
    """ورودی چندخطی هدف‌ها"""
    def __init__(self, **kw):
        kw.setdefault("multiline", True)
        kw.setdefault("background_color", (0, 0, 0, 0))
        kw.setdefault("foreground_color", WHITE)
        kw.setdefault("cursor_color", GOLD)
        kw.setdefault("hint_text_color", MUTED)
        kw.setdefault("font_size", dp(11))
        kw.setdefault("padding", [dp(10), dp(8)])
        super().__init__(**kw)
        self.bind(pos=self._draw, size=self._draw)

    def _draw(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(.08, .08, .10, 1)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(6)])
            Color(*BORDER)
            Line(rounded_rectangle=[self.x, self.y, self.width, self.height, dp(6)], width=dp(.6))


class GoldBtn(ButtonBehavior, BoxLayout):
    """دکمه طلایی اصلی"""
    def __init__(self, text="", accent=None, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height", dp(40))
        super().__init__(**kw)
        self._ac = accent or GOLD
        self._lbl = mk_label(text, color=(.06, .06, .07, 1), size=dp(13), bold=True, halign="center")
        self.add_widget(self._lbl)
        self.bind(pos=self._draw, size=self._draw)

    @property
    def text(self): return self._lbl.text
    @text.setter
    def text(self, v): self._lbl.text = v

    def _draw(self, pressed=False, *_):
        a = self._ac
        self.canvas.before.clear()
        with self.canvas.before:
            alpha = .85 if pressed else 1.0
            Color(a[0], a[1], a[2], alpha)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(7)])

    def on_press(self): self._draw(True)
    def on_release(self): self._draw(False)


class OutlineBtn(ButtonBehavior, BoxLayout):
    """دکمه توخالی با خط حاشیه"""
    def __init__(self, text="", accent=None, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height", dp(38))
        super().__init__(**kw)
        self._ac = accent or BORDER
        self._lbl = mk_label(text, color=accent or TEXT, size=dp(12), bold=False, halign="center")
        self.add_widget(self._lbl)
        self.bind(pos=self._draw, size=self._draw)

    @property
    def text(self): return self._lbl.text
    @text.setter
    def text(self, v): self._lbl.text = v

    def _draw(self, pressed=False, *_):
        a = self._ac
        self.canvas.before.clear()
        with self.canvas.before:
            Color(a[0], a[1], a[2], .15 if pressed else .08)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(7)])
            Color(*a[:3], 1)
            Line(rounded_rectangle=[self.x, self.y, self.width, self.height, dp(7)], width=dp(.8))

    def on_press(self): self._draw(True)
    def on_release(self): self._draw(False)


class StatBox(BoxLayout):
    """جعبه آماری کوچک"""
    def __init__(self, label, color, **kw):
        kw.setdefault("orientation", "vertical")
        kw.setdefault("spacing", dp(1))
        kw.setdefault("padding", [dp(8), dp(6)])
        super().__init__(**kw)
        self._c = color
        self._num = Label(text="0", font_size=dp(20), bold=True, color=color,
                          size_hint_y=None, height=dp(26))
        self._lbl = mk_label(label, color=MUTED, size=dp(9), halign="center")
        self.add_widget(self._num)
        self.add_widget(self._lbl)
        self.bind(pos=self._draw, size=self._draw)

    def _draw(self, *_):
        c = self._c
        self.canvas.before.clear()
        with self.canvas.before:
            Color(c[0], c[1], c[2], .10)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(6)])
            Color(c[0], c[1], c[2], .25)
            Line(rounded_rectangle=[self.x, self.y, self.width, self.height, dp(6)], width=dp(.6))

    def set(self, v): self._num.text = str(v)


class Divider(Widget):
    def __init__(self, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height", dp(1))
        super().__init__(**kw)
        self.bind(pos=self._draw, size=self._draw)

    def _draw(self, *_):
        self.canvas.clear()
        with self.canvas:
            Color(*BORDER)
            Rectangle(pos=self.pos, size=self.size)


# ───────────────────────────────────────────────────
#  RESULT ROW
# ───────────────────────────────────────────────────
STATUS_COLOR = {"both": GREEN, "tcp_only": GOLD, "ping_only": AMBER, "dead": RED}
STATUS_LABEL = {"both": "OK", "tcp_only": "TCP", "ping_only": "PING", "dead": "DEAD"}


class ResultRow(RecycleDataViewBehavior, BoxLayout):
    index = NumericProperty(0)

    def __init__(self, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height", dp(34))
        kw.setdefault("spacing", dp(4))
        kw.setdefault("padding", [dp(8), dp(2)])
        super().__init__(**kw)
        self._even = False
        self.bind(pos=self._bg, size=self._bg)

        def col(fx, color=None, fs=dp(10), align="left"):
            l = Label(size_hint_x=fx, font_size=fs,
                      color=color or TEXT, halign=align, valign="middle")
            l.bind(size=lambda w, *_: setattr(w, "text_size", w.size))
            return l

        self.c_num    = col(.5,  MUTED, dp(9), "center")
        self.c_target = col(3.0, WHITE, dp(10))
        self.c_cdn    = col(1.2, MUTED, dp(9))
        self.c_ping   = col(1.0, TEXT,  dp(10), "center")
        self.c_tcp    = col(1.0, TEXT,  dp(10), "center")
        self.c_status = col(.8,  TEXT,  dp(10), "center")

        for w in [self.c_num, self.c_target, self.c_cdn,
                  self.c_ping, self.c_tcp, self.c_status]:
            self.add_widget(w)

    def _bg(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*ROW_EVN) if self._even else Color(*ROW_ODD)
            Rectangle(pos=self.pos, size=self.size)

    def refresh_view_attrs(self, rv, index, data):
        self.index = index
        self._even = index % 2 == 1
        self._bg()

        sc = STATUS_COLOR.get(data.get("status", "dead"), MUTED)
        self.c_num.text    = str(index + 1)
        self.c_target.text = data.get("target", "")
        self.c_cdn.text    = data.get("cdn", "")
        self.c_cdn.color   = CDN_COLOR.get(data.get("cdn", "Unknown"), MUTED)

        p_ok = data.get("ping_ok", False)
        t_ok = data.get("tcp_ok",  False)
        p_ms = data.get("ping_ms")
        t_ms = data.get("tcp_ms")

        self.c_ping.text  = (f"{p_ms}ms" if p_ms is not None else "✓") if p_ok else "—"
        self.c_ping.color = GREEN if p_ok else RED
        self.c_tcp.text   = (f"{t_ms}ms" if t_ms is not None else "✓") if t_ok else "—"
        self.c_tcp.color  = GREEN if t_ok else RED

        self.c_status.text  = STATUS_LABEL.get(data.get("status", "dead"), "?")
        self.c_status.color = sc

        return super().refresh_view_attrs(rv, index, data)


class ResultList(RecycleView):
    def __init__(self, **kw):
        super().__init__(**kw)
        lay = RecycleBoxLayout(
            default_size=(None, dp(34)),
            default_size_hint=(1, None),
            size_hint_y=None,
            orientation="vertical",
            spacing=dp(1),
        )
        lay.bind(minimum_height=lay.setter("height"))
        self.add_widget(lay)
        self.viewclass = "ResultRow"
        self.data = []


# ───────────────────────────────────────────────────
#  EXPORT MODAL
# ───────────────────────────────────────────────────
class ExportModal(ModalView):
    def __init__(self, results, **kw):
        kw.setdefault("size_hint", (.88, .78))
        kw.setdefault("background_color", (0, 0, 0, .80))
        super().__init__(**kw)
        self._results = results

        root = BoxLayout(orientation="vertical", padding=dp(14), spacing=dp(10))
        with root.canvas.before:
            Color(*CARD)
            self._bg_rect = RoundedRectangle(radius=[R])
        root.bind(pos=lambda *_: setattr(self._bg_rect, "pos", root.pos),
                  size=lambda *_: setattr(self._bg_rect, "size", root.size))

        # ─ header
        hdr = BoxLayout(size_hint_y=None, height=dp(32), spacing=dp(8))
        hdr.add_widget(mk_label("خروجی نتایج", color=GOLD, size=dp(14), bold=True))
        close_btn = OutlineBtn("✕", accent=MUTED, size_hint_x=None, width=dp(36))
        close_btn.bind(on_release=self.dismiss)
        hdr.add_widget(close_btn)
        root.add_widget(hdr)
        root.add_widget(Divider())

        # ─ filter row
        frow = BoxLayout(size_hint_y=None, height=dp(34), spacing=dp(8))
        frow.add_widget(mk_label("فیلتر:", color=MUTED, size=dp(11),
                                  size_hint_x=None, width=dp(40)))
        self._filters = {}
        statuses = [("همه", "all"), ("موفق", "both"), ("TCP", "tcp_only"),
                    ("Ping", "ping_only"), ("ناموفق", "dead")]
        self._cur_filter = "all"
        self._filter_btns = {}
        for label, key in statuses:
            accent = (GREEN if key == "both" else RED if key == "dead" else
                      GOLD if key == "tcp_only" else AMBER if key == "ping_only" else TEXT)
            b = OutlineBtn(label, accent=accent,
                           size_hint_x=None, width=dp(54), height=dp(30))
            b._filter_key = key
            b.bind(on_release=self._on_filter)
            self._filter_btns[key] = b
            frow.add_widget(b)
        root.add_widget(frow)

        # ─ text area
        self._ta = TextInput(
            readonly=True,
            multiline=True,
            background_color=(0, 0, 0, 0),
            foreground_color=TEXT,
            font_size=dp(10),
            padding=[dp(8), dp(6)],
        )
        with self._ta.canvas.before:
            Color(.08, .08, .10, 1)
            self._ta_rect = RoundedRectangle(radius=[dp(6)])
        self._ta.bind(pos=lambda *_: setattr(self._ta_rect, "pos", self._ta.pos),
                      size=lambda *_: setattr(self._ta_rect, "size", self._ta.size))
        root.add_widget(self._ta)

        # ─ bottom buttons
        brow = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(8))
        copy_btn = GoldBtn("کپی در کلیپ‌بورد")
        copy_btn.bind(on_release=self._copy)
        brow.add_widget(copy_btn)
        root.add_widget(brow)

        self.add_widget(root)
        self._render("all")

    def _on_filter(self, btn):
        self._render(btn._filter_key)

    def _render(self, fkey):
        self._cur_filter = fkey
        if fkey == "all":
            rows = self._results
        else:
            rows = [r for r in self._results if r["status"] == fkey]
        lines = []
        for r in rows:
            pm = f"{r['ping_ms']}ms" if r.get("ping_ms") is not None else ("✓" if r["ping_ok"] else "—")
            tm = f"{r['tcp_ms']}ms" if r.get("tcp_ms") is not None else ("✓" if r["tcp_ok"] else "—")
            lines.append(
                f"{r['target']:<35} CDN:{r['cdn']:<12} Ping:{pm:<8} TCP:{tm:<8} [{r['status'].upper()}]  {r['time']}")
        self._ta.text = "\n".join(lines) if lines else "(نتیجه‌ای موجود نیست)"

    def _copy(self, *_):
        Clipboard.copy(self._ta.text)


# ───────────────────────────────────────────────────
#  MAIN APP
# ───────────────────────────────────────────────────
class ScannerApp(App):
    title = "PowerCodes Scanner v3"

    def build(self):
        Window.clearcolor = BG
        self._results  = []
        self._scanning = False
        self._stop_evt = threading.Event()
        self._lock     = threading.Lock()
        self._total    = 0
        self._done     = 0

        root = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(8))

        # ── HEADER ─────────────────────────────────
        hdr = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(10))
        t = mk_label("PowerCodes", color=GOLD, size=dp(18), bold=True,
                      size_hint_x=None, width=dp(130))
        sub = mk_label("IP & Domain Scanner", color=MUTED, size=dp(10))
        ver = mk_label("v3.0", color=MUTED, size=dp(9), halign="right",
                        size_hint_x=None, width=dp(36))
        hdr.add_widget(t)
        hdr.add_widget(sub)
        hdr.add_widget(ver)
        root.add_widget(hdr)
        root.add_widget(Divider())

        # ── CONFIG ROW ─────────────────────────────
        cfg = Card(orientation="horizontal", spacing=dp(10),
                   size_hint_y=None, height=dp(68))

        def field(label, hint, default, w):
            col = BoxLayout(orientation="vertical", spacing=dp(3),
                            size_hint_x=None, width=dp(w))
            col.add_widget(mk_label(label, color=MUTED, size=dp(9),
                                     size_hint_y=None, height=dp(14)))
            inp = LineInput(hint_text=hint, text=str(default))
            col.add_widget(inp)
            return col, inp

        f1, self.inp_port    = field("پورت TCP",   "443",  443,  58)
        f2, self.inp_threads = field("ترد",         "50",   50,   48)
        f3, self.inp_ping_to = field("Ping (ms)",   "1500", 1500, 64)
        f4, self.inp_tcp_to  = field("TCP (s)",     "2",    2,    48)
        for f in [f1, f2, f3, f4]:
            cfg.add_widget(f)

        # CDN filter toggle
        cdn_wrap = BoxLayout(orientation="vertical", spacing=dp(2))
        cdn_wrap.add_widget(mk_label("CDN فیلتر", color=MUTED, size=dp(9),
                                      size_hint_y=None, height=dp(14)))
        self._cdn_filter_all = True
        self._cdn_checks = {}
        cdn_scroll_wrap = ScrollView(do_scroll_y=False)
        cdn_row = BoxLayout(spacing=dp(4), size_hint_x=None)
        cdn_row.bind(minimum_width=cdn_row.setter("width"))
        for name in ALL_CDN:
            c = CDN_COLOR.get(name, MUTED)
            btn = OutlineBtn(name, accent=c,
                             size_hint_x=None, width=dp(max(len(name) * 7, 54)),
                             height=dp(26))
            btn._cdn_name  = name
            btn._active    = True
            btn._accent    = c
            btn.bind(on_release=self._toggle_cdn)
            self._cdn_checks[name] = btn
            cdn_row.add_widget(btn)
        cdn_scroll_wrap.add_widget(cdn_row)
        cdn_wrap.add_widget(cdn_scroll_wrap)
        cfg.add_widget(cdn_wrap)
        root.add_widget(cfg)

        # ── TARGET INPUT ───────────────────────────
        ti_wrap = BoxLayout(orientation="vertical", spacing=dp(4),
                            size_hint_y=None, height=dp(120))
        ti_hdr = BoxLayout(size_hint_y=None, height=dp(18), spacing=dp(6))
        ti_hdr.add_widget(mk_label("هدف‌ها  (IP / دامنه / CIDR — هر خط یا فاصله)",
                                    color=MUTED, size=dp(9)))
        self._target_count_lbl = mk_label("0 هدف", color=GOLD, size=dp(9),
                                           halign="right", size_hint_x=None, width=dp(60))
        ti_hdr.add_widget(self._target_count_lbl)
        ti_wrap.add_widget(ti_hdr)
        self.inp_targets = AreaInput(
            hint_text="8.8.8.8\n1.1.1.1\ngoogle.com\n192.168.1.0/24",
        )
        self.inp_targets.bind(text=self._on_target_text)
        ti_wrap.add_widget(self.inp_targets)
        root.add_widget(ti_wrap)

        # ── SCAN BUTTONS ───────────────────────────
        btn_row = BoxLayout(size_hint_y=None, height=dp(42), spacing=dp(8))
        self.btn_scan  = GoldBtn("▶  شروع اسکن")
        self.btn_stop  = GoldBtn("■  توقف", accent=RED)
        self.btn_stop.opacity = .3
        self.btn_clear = OutlineBtn("پاک کردن", accent=MUTED)
        self.btn_export= OutlineBtn("خروجی", accent=GOLD)

        self.btn_scan.bind(on_release=self._start_scan)
        self.btn_stop.bind(on_release=self._stop_scan)
        self.btn_clear.bind(on_release=self._clear)
        self.btn_export.bind(on_release=self._open_export)

        btn_row.add_widget(self.btn_scan)
        btn_row.add_widget(self.btn_stop)
        btn_row.add_widget(self.btn_clear)
        btn_row.add_widget(self.btn_export)
        root.add_widget(btn_row)

        # ── PROGRESS ───────────────────────────────
        prog_row = BoxLayout(orientation="vertical", spacing=dp(2),
                              size_hint_y=None, height=dp(26))
        self._prog_lbl = mk_label("آماده", color=MUTED, size=dp(9),
                                   size_hint_y=None, height=dp(12))
        self._prog = ProgressBar(max=100, value=0, size_hint_y=None, height=dp(6))
        prog_row.add_widget(self._prog_lbl)
        prog_row.add_widget(self._prog)
        root.add_widget(prog_row)

        # ── STATS ──────────────────────────────────
        stat_row = BoxLayout(size_hint_y=None, height=dp(56), spacing=dp(6))
        self.s_total  = StatBox("کل",     WHITE)
        self.s_ok     = StatBox("موفق",   GREEN)
        self.s_tcp    = StatBox("TCP",    GOLD)
        self.s_ping   = StatBox("Ping",   AMBER)
        self.s_dead   = StatBox("ناموفق", RED)
        for s in [self.s_total, self.s_ok, self.s_tcp, self.s_ping, self.s_dead]:
            stat_row.add_widget(s)
        root.add_widget(stat_row)

        # ── TABLE HEADER ───────────────────────────
        root.add_widget(Divider())
        th = BoxLayout(size_hint_y=None, height=dp(22),
                       padding=[dp(8), dp(0)], spacing=dp(4))
        def th_lbl(t, fx, align="left"):
            l = mk_label(t, color=GOLD, size=dp(9), bold=True,
                          halign=align, size_hint_x=fx)
            return l
        th.add_widget(th_lbl("#",      .5, "center"))
        th.add_widget(th_lbl("هدف",   3.0))
        th.add_widget(th_lbl("CDN",   1.2))
        th.add_widget(th_lbl("Ping",  1.0, "center"))
        th.add_widget(th_lbl("TCP",   1.0, "center"))
        th.add_widget(th_lbl("وضع",  .8, "center"))
        root.add_widget(th)
        root.add_widget(Divider())

        # ── RESULT LIST ────────────────────────────
        self._rv = ResultList()
        root.add_widget(self._rv)

        # ── FOOTER ─────────────────────────────────
        root.add_widget(Divider())
        ft = BoxLayout(size_hint_y=None, height=dp(18))
        ft.add_widget(mk_label("@powercodes", color=MUTED, size=dp(8)))
        ft.add_widget(mk_label("github.com/power-codes", color=MUTED, size=dp(8), halign="right"))
        root.add_widget(ft)

        return root

    # ── CDN toggle ─────────────────────────────────
    def _toggle_cdn(self, btn):
        btn._active = not btn._active
        if btn._active:
            btn._ac = btn._accent
            btn._lbl.color = btn._accent
        else:
            btn._ac = MUTED
            btn._lbl.color = MUTED
        btn._draw()
        self._apply_cdn_filter()

    def _apply_cdn_filter(self):
        active = {n for n, b in self._cdn_checks.items() if b._active}
        filtered = [r for r in self._results if r["cdn"] in active]
        self._rv.data = filtered

    # ── target count ───────────────────────────────
    def _on_target_text(self, *_):
        t = clean_targets(self.inp_targets.text)
        self._target_count_lbl.text = f"{len(t)} هدف"

    # ── clear ──────────────────────────────────────
    def _clear(self, *_):
        if self._scanning:
            return
        self._results = []
        self._rv.data = []
        self._reset_stats()
        self._prog.value = 0
        self._prog_lbl.text = "آماده"

    def _reset_stats(self):
        for s in [self.s_total, self.s_ok, self.s_tcp, self.s_ping, self.s_dead]:
            s.set(0)

    # ── stop ───────────────────────────────────────
    def _stop_scan(self, *_):
        self._stop_evt.set()

    # ── start ──────────────────────────────────────
    def _start_scan(self, *_):
        if self._scanning:
            return
        targets = clean_targets(self.inp_targets.text)
        if not targets:
            self._prog_lbl.text = "هیچ هدفی وارد نشده"
            return

        try:
            port    = int(self.inp_port.text    or 443)
            threads = int(self.inp_threads.text or 50)
            ping_to = int(self.inp_ping_to.text or 1500)
            tcp_to  = float(self.inp_tcp_to.text or 2)
        except ValueError:
            self._prog_lbl.text = "مقادیر تنظیمات اشتباه است"
            return

        threads = max(1, min(threads, 500))
        self._results  = []
        self._rv.data  = []
        self._reset_stats()
        self._total    = len(targets)
        self._done     = 0
        self._scanning = True
        self._stop_evt.clear()

        self.btn_scan.opacity  = .4
        self.btn_stop.opacity  = 1.0
        self._prog.max = self._total
        self._prog.value = 0
        self._prog_lbl.text = f"اسکن {self._total} هدف..."

        threading.Thread(
            target=self._scan_worker,
            args=(targets, port, threads, ping_to, tcp_to),
            daemon=True,
        ).start()

    def _scan_worker(self, targets, port, threads, ping_to, tcp_to):
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(scan_single, t, port, ping_to, tcp_to): t
                    for t in targets}
            for fut in concurrent.futures.as_completed(futs):
                if self._stop_evt.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    res = fut.result()
                except Exception:
                    res = {"target": futs[fut], "resolved": "", "cdn": "Unknown",
                           "ping_ok": False, "ping_ms": None,
                           "tcp_ok": False, "tcp_ms": None,
                           "status": "dead", "time": datetime.now().strftime("%H:%M:%S")}
                with self._lock:
                    self._results.append(res)
                    self._done += 1
                Clock.schedule_once(lambda dt: self._tick(), 0)

        Clock.schedule_once(lambda dt: self._finish(), 0)

    def _tick(self):
        with self._lock:
            results = list(self._results)
            done = self._done

        active_cdn = {n for n, b in self._cdn_checks.items() if b._active}
        filtered = [r for r in results if r["cdn"] in active_cdn]
        self._rv.data = filtered

        s_ok = sum(1 for r in results if r["status"] == "both")
        s_tc = sum(1 for r in results if r["status"] == "tcp_only")
        s_pg = sum(1 for r in results if r["status"] == "ping_only")
        s_dd = sum(1 for r in results if r["status"] == "dead")

        self.s_total.set(done)
        self.s_ok.set(s_ok)
        self.s_tcp.set(s_tc)
        self.s_ping.set(s_pg)
        self.s_dead.set(s_dd)

        pct = (done / self._total * 100) if self._total else 0
        self._prog.value = done
        self._prog_lbl.text = f"{done} / {self._total}  ({pct:.0f}%)"

    def _finish(self):
        self._scanning = False
        self.btn_scan.opacity = 1.0
        self.btn_stop.opacity = .3
        stopped = "متوقف شد" if self._stop_evt.is_set() else "تمام شد"
        self._prog_lbl.text = f"اسکن {stopped} — {self._done} بررسی شد"

    # ── export ─────────────────────────────────────
    def _open_export(self, *_):
        if not self._results:
            return
        ExportModal(list(self._results)).open()


if __name__ == "__main__":
    ScannerApp().run()
