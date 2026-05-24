#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PowerCodes Scanner v2.0  —  IP / CDN / Ping / TCP"""

APP_VERSION     = "2.0"
TELEGRAM_HANDLE = "@powercodes"
GITHUB          = "github.com/power-codes"

import concurrent.futures, ipaddress, os, platform
import re, socket, subprocess, threading, time
from datetime import datetime

os.environ.setdefault("KIVY_NO_ENV_CONFIG", "1")
os.environ.setdefault("KIVY_WINDOW",        "sdl2")

from kivy.app                    import App
from kivy.clock                  import Clock
from kivy.core.clipboard         import Clipboard
from kivy.core.window            import Window
from kivy.graphics               import Color, Rectangle, RoundedRectangle, Line
from kivy.metrics                import dp
from kivy.properties             import BooleanProperty, ListProperty, NumericProperty
from kivy.uix.behaviors          import ButtonBehavior
from kivy.uix.boxlayout          import BoxLayout
from kivy.uix.gridlayout         import GridLayout
from kivy.uix.label              import Label
from kivy.uix.modalview          import ModalView
from kivy.uix.progressbar        import ProgressBar
from kivy.uix.recycleboxlayout   import RecycleBoxLayout
from kivy.uix.recycleview        import RecycleView
from kivy.uix.recycleview.views  import RecycleDataViewBehavior
from kivy.uix.scrollview         import ScrollView
from kivy.uix.textinput          import TextInput
from kivy.uix.widget             import Widget

IS_WIN     = platform.system().lower() == "windows"
IS_ANDROID = "ANDROID_ARGUMENT" in os.environ or os.path.exists("/data/app")

# ─────────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────────
BG0    = (.06, .06, .08, 1)   # main background
BG1    = (.10, .10, .13, 1)   # panel / card
BG2    = (.13, .13, .17, 1)   # input field bg
ROW_E  = (.08, .08, .10, 1)   # even row
ROW_O  = (.11, .11, .14, 1)   # odd row
BORDER = (.24, .24, .30, 1)

GOLD   = (1.00, .84, .00, 1)
GOLD_D = (1.00, .84, .00, .18)
GREEN  = (.18, .80, .48, 1)
GREEN_D= (.18, .80, .48, .15)
RED    = (.93, .33, .33, 1)
RED_D  = (.93, .33, .33, .15)
AMBER  = (.97, .71, .08, 1)
MUTED  = (.44, .46, .52, 1)
WHITE  = (.95, .95, .97, 1)
TEXT   = (.76, .78, .82, 1)

CDN_COL = {
    "Cloudflare": (1.00, .45, .13, 1),
    "Google":     (.26, .52, .96, 1),
    "Fastly":     (.93, .33, .33, 1),
    "Akamai":     (.18, .80, .48, 1),
    "Netlify":    (.40, .40, .95, 1),
    "Vercel":     (.85, .85, .87, 1),
    "CloudFront": (1.00, .64, .00, 1),
    "BunnyCDN":   (1.00, .38, .68, 1),
    "Gcore":      (.00, .74, 1.00, 1),
    "AbrArvan":   (.38, .78, 1.00, 1),
    "Unknown":    MUTED,
}

R = dp(8)   # corner radius

# ─────────────────────────────────────────────────
#  SCAN LOGIC
# ─────────────────────────────────────────────────
def check_ping(host, ms=1500):
    if IS_WIN:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        try:
            p = subprocess.run(
                ["ping","-n","1","-w",str(ms),host],
                capture_output=True, text=True,
                timeout=ms/1000+2,
                startupinfo=si,
                creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception: return False, None
    else:
        try:
            p = subprocess.run(
                ["ping","-c","1","-W",str(max(1,int(ms/1000))),host],
                capture_output=True, text=True, timeout=ms/1000+2)
        except Exception: return False, None
    out = (p.stdout or "")+(p.stderr or "")
    ok  = p.returncode == 0
    m   = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", out, re.I)
    return ok, (float(m.group(1)) if m else None)

def check_tcp(host, port=443, sec=2.0):
    try:
        t = time.perf_counter()
        with socket.create_connection((host, port), timeout=sec):
            return True, round((time.perf_counter()-t)*1000, 1)
    except Exception: return False, None

_dc, _dl = {}, threading.Lock()
def resolve(t):
    try: ipaddress.ip_address(t); return t
    except ValueError: pass
    with _dl:
        if t in _dc: return _dc[t]
    try:
        r = socket.gethostbyname(t)
        with _dl: _dc[t] = r
        return r
    except Exception: return t

def expand(cidr):
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        h = list(net.hosts()) or list(net)
        return [str(x) for x in h[:1024]]
    except ValueError: return []

_rcidr = re.compile(r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2})\b')
_rip   = re.compile(r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b')
_rdom  = re.compile(r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b')

def parse_targets(raw):
    seen = set()
    for line in raw.splitlines():
        if len(seen) >= 50000: break
        line = line.strip()
        if not line or line.startswith("#"): continue
        cf = False
        for m in _rcidr.finditer(line):
            cf = True
            for ip in expand(m.group(1)):
                seen.add(ip)
                if len(seen) >= 50000: break
        rem = _rcidr.sub("", line) if cf else line
        for m in _rip.finditer(rem):
            try: ipaddress.ip_address(m.group(1)); seen.add(m.group(1))
            except ValueError: pass
        rem2 = _rip.sub("", _rcidr.sub("", line))
        for m in _rdom.finditer(rem2):
            d = m.group(1).lower()
            if len(d) > 3: seen.add(d)
    return sorted(seen)[:50000]

CDN_RANGES = [
    ("Cloudflare", ["1.0.0.0/24","1.1.1.0/24","103.21.244.0/22","103.22.200.0/22",
                    "103.31.4.0/22","104.16.0.0/13","104.24.0.0/14","108.162.192.0/18",
                    "131.0.72.0/22","141.101.64.0/18","162.158.0.0/15","172.64.0.0/13",
                    "173.245.48.0/20","188.114.96.0/20","190.93.240.0/20",
                    "197.234.240.0/22","198.41.128.0/17"]),
    ("Google",     ["8.8.4.0/24","8.8.8.0/24","64.233.160.0/19","66.102.0.0/20",
                    "66.249.64.0/19","74.125.0.0/16","104.132.0.0/14","108.177.0.0/17",
                    "142.250.0.0/15","172.217.0.0/16","172.253.0.0/16","173.194.0.0/16",
                    "209.85.128.0/17","216.58.192.0/19","216.239.32.0/19"]),
    ("Fastly",     ["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24",
                    "104.156.80.0/20","146.75.0.0/16","151.101.0.0/16","157.52.64.0/18",
                    "167.82.0.0/17","199.27.72.0/21","199.232.0.0/16"]),
    ("Akamai",     ["2.16.0.0/13","23.0.0.0/12","23.32.0.0/11","23.64.0.0/14",
                    "23.72.0.0/13","23.192.0.0/11","63.0.0.0/8","69.192.0.0/16",
                    "72.246.0.0/15","88.221.0.0/16","95.100.0.0/15","104.64.0.0/10",
                    "184.24.0.0/13","184.50.0.0/15","184.84.0.0/14"]),
    ("Netlify",    ["44.226.105.0/24","50.7.4.0/24","50.7.85.0/24",
                    "54.182.0.0/16","99.83.128.0/17","162.159.128.0/20"]),
    ("Vercel",     ["64.29.17.0/24","64.29.18.0/24","64.29.19.0/24","66.33.60.0/24",
                    "66.33.61.0/24","76.76.21.0/24","76.223.126.0/24"]),
    ("CloudFront", ["52.46.0.0/18","52.84.0.0/15","54.182.0.0/16",
                    "99.84.0.0/16","130.176.0.0/17"]),
    ("BunnyCDN",   ["89.187.160.0/19","147.75.0.0/16"]),
    ("Gcore",      ["92.223.0.0/16","95.85.0.0/16","185.158.0.0/16"]),
    ("AbrArvan",   ["185.220.226.0/24","185.143.232.0/22"]),
]
ALL_CDN = [n for n, _ in CDN_RANGES] + ["Unknown"]
_nets = []
for _n, _rs in CDN_RANGES:
    for _r in _rs:
        try: _nets.append((ipaddress.ip_network(_r, strict=False), _n))
        except ValueError: pass

def detect_cdn(ip):
    try:
        a = ipaddress.ip_address(ip)
        for net, name in _nets:
            if a in net: return name
    except ValueError: pass
    return "Unknown"

def scan_one(target, port, ping_ms, tcp_sec):
    cdn = "Unknown"; resolved = None
    try:
        ipaddress.ip_address(target)
        resolved = target; cdn = detect_cdn(target)
    except ValueError:
        r = resolve(target)
        if r != target: resolved = r; cdn = detect_cdn(r)
    p_ok, p_ms = check_ping(resolved or target, ms=ping_ms)
    t_ok, t_ms = check_tcp(target, port=port, sec=tcp_sec)
    st = ("both" if p_ok and t_ok else
          "tcp"  if t_ok else
          "ping" if p_ok else "dead")
    return {"target": target, "cdn": cdn,
            "p_ok": p_ok, "p_ms": (round(p_ms,1) if p_ms else None),
            "t_ok": t_ok, "t_ms": t_ms, "st": st}

# ─────────────────────────────────────────────────
#  UI HELPERS
# ─────────────────────────────────────────────────

def L(text="", color=None, size=None, bold=False, halign="left", **kw):
    """Create a properly wrapped Label"""
    l = Label(
        text=text, markup=False,
        color=color or TEXT,
        font_size=size or dp(11),
        bold=bold,
        halign=halign,
        valign="middle",
        **kw
    )
    l.bind(size=lambda w, *_: setattr(w, "text_size", w.size))
    return l


def divider():
    w = Widget(size_hint_y=None, height=dp(1))
    with w.canvas:
        Color(*BORDER)
        w._rect = Rectangle(pos=w.pos, size=w.size)
    w.bind(pos=lambda s,v: setattr(s._rect,"pos",v),
           size=lambda s,v: setattr(s._rect,"size",v))
    return w


class Card(BoxLayout):
    """Dark card with rounded border"""
    def __init__(self, **kw):
        kw.setdefault("orientation", "vertical")
        kw.setdefault("padding",     dp(12))
        kw.setdefault("spacing",     dp(8))
        super().__init__(**kw)
        self.bind(pos=self._d, size=self._d)

    def _d(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*BG1)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[R])
            Color(*BORDER)
            Line(rounded_rectangle=[self.x,self.y,self.width,self.height,R],
                 width=dp(.7))


class FieldInput(TextInput):
    """Compact single-line input"""
    def __init__(self, **kw):
        kw.setdefault("multiline",        False)
        kw.setdefault("background_color", (0,0,0,0))
        kw.setdefault("foreground_color", WHITE)
        kw.setdefault("cursor_color",     GOLD)
        kw.setdefault("hint_text_color",  list(MUTED))
        kw.setdefault("font_size",        dp(11))
        kw.setdefault("padding",          [dp(9), dp(6)])
        kw.setdefault("size_hint_y",      None)
        kw.setdefault("height",           dp(32))
        super().__init__(**kw)
        self.bind(pos=self._d, size=self._d)

    def _d(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*BG2)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(6)])
            Color(*BORDER)
            Line(rounded_rectangle=[self.x,self.y,self.width,self.height,dp(6)],
                 width=dp(.6))


class BigInput(TextInput):
    """Multi-line targets area"""
    def __init__(self, **kw):
        kw.setdefault("multiline",        True)
        kw.setdefault("background_color", (0,0,0,0))
        kw.setdefault("foreground_color", WHITE)
        kw.setdefault("cursor_color",     GOLD)
        kw.setdefault("hint_text_color",  list(MUTED))
        kw.setdefault("font_size",        dp(11))
        kw.setdefault("padding",          [dp(10), dp(8)])
        super().__init__(**kw)
        self.bind(pos=self._d, size=self._d)

    def _d(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*BG2)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(6)])
            Color(*BORDER)
            Line(rounded_rectangle=[self.x,self.y,self.width,self.height,dp(6)],
                 width=dp(.6))


class PillBtn(ButtonBehavior, BoxLayout):
    """Button: colored border + subtle bg fill"""
    def __init__(self, text="", accent=None, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height",      dp(36))
        kw.setdefault("padding",     [dp(10), dp(5)])
        super().__init__(**kw)
        self._ac   = accent or GOLD
        self._norm = list(self._ac[:3]) + [.14]
        self._over = list(self._ac[:3]) + [.28]
        self._cur  = self._norm
        self._lbl  = L(text, color=self._ac, size=dp(12),
                       bold=True, halign="center")
        self.add_widget(self._lbl)
        self.bind(pos=self._d, size=self._d)

    @property
    def text(self): return self._lbl.text
    @text.setter
    def text(self, v): self._lbl.text = v

    def _d(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*self._cur)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[R])
            Color(*self._ac)
            Line(rounded_rectangle=[self.x,self.y,self.width,self.height,R],
                 width=dp(.9))

    def on_press(self):   self._cur = self._over; self._d()
    def on_release(self): self._cur = self._norm; self._d()


class CheckItem(ButtonBehavior, BoxLayout):
    active    = BooleanProperty(True)
    chk_color = ListProperty(list(GOLD))

    def __init__(self, text="", **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height",      dp(28))
        kw.setdefault("spacing",     dp(8))
        kw.setdefault("padding",     [dp(6), dp(2)])
        super().__init__(**kw)
        self._bw = Widget(size_hint_x=None, width=dp(16))
        self._lbl = L(text, color=TEXT, size=dp(10))
        self.add_widget(self._bw)
        self.add_widget(self._lbl)
        self.bind(pos=self._d, size=self._d,
                  active=self._d, chk_color=self._d)

    def _d(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(1,1,1,.03)
            RoundedRectangle(pos=self.pos,size=self.size,radius=[dp(4)])
        self._bw.canvas.clear()
        bx = self._bw.x + dp(1)
        by = self._bw.y + (self._bw.height - dp(14))/2
        with self._bw.canvas:
            if self.active:
                Color(*self.chk_color)
                RoundedRectangle(pos=(bx,by),size=(dp(14),dp(14)),radius=[dp(3)])
                Color(0,0,0,1)
                Line(points=[bx+dp(3),by+dp(7),
                              bx+dp(6),by+dp(4),
                              bx+dp(11),by+dp(10)],
                     width=1.5, cap="round", joint="round")
            else:
                Color(*BORDER)
                Line(rounded_rectangle=[bx,by,dp(14),dp(14),dp(3)], width=dp(.8))

    def on_press(self): self.active = not self.active


class StatBox(BoxLayout):
    def __init__(self, label, accent, **kw):
        kw.setdefault("orientation", "vertical")
        kw.setdefault("spacing",     dp(2))
        kw.setdefault("padding",     [dp(6), dp(6)])
        super().__init__(**kw)
        self._ac = accent
        self._num = Label(text="0", font_size=dp(20), bold=True,
                          color=accent, size_hint_y=None, height=dp(26),
                          halign="center", valign="middle")
        self._num.bind(size=lambda w,*_: setattr(w,"text_size",w.size))
        self._lbl = L(label, color=MUTED, size=dp(8), halign="center",
                      size_hint_y=None, height=dp(14))
        self.add_widget(self._num)
        self.add_widget(self._lbl)
        self.bind(pos=self._d, size=self._d)

    def _d(self, *_):
        a = self._ac
        self.canvas.before.clear()
        with self.canvas.before:
            Color(a[0],a[1],a[2],.10)
            RoundedRectangle(pos=self.pos,size=self.size,radius=[R])
            Color(a[0],a[1],a[2],.28)
            Line(rounded_rectangle=[self.x,self.y,self.width,self.height,R],
                 width=dp(.7))

    def set(self, v): self._num.text = str(v)


# ─────────────────────────────────────────────────
#  RESULT ROW
# ─────────────────────────────────────────────────
ST_CLR = {"both": GREEN, "tcp": GOLD, "ping": AMBER, "dead": RED}
ST_TXT = {"both": "OK",  "tcp": "TCP", "ping": "PING", "dead": "DEAD"}

class ResultRow(RecycleDataViewBehavior, BoxLayout):
    index = NumericProperty(0)

    def __init__(self, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height",      dp(32))
        kw.setdefault("spacing",     dp(0))
        kw.setdefault("padding",     [dp(10),dp(0)])
        super().__init__(**kw)
        self.bind(pos=self._bg, size=self._bg)

        def c(fx, color=None, fs=dp(10)):
            l = Label(size_hint_x=fx, font_size=fs,
                      color=color or TEXT,
                      halign="left", valign="middle")
            l.bind(size=lambda w,*_: setattr(w,"text_size",w.size))
            return l

        self.c_tgt    = c(2.8, WHITE,  dp(10))
        self.c_ping   = c(1.0, TEXT,   dp(10))
        self.c_tcp    = c(1.0, TEXT,   dp(10))
        self.c_status = c(0.75, TEXT,  dp(10))
        for w in [self.c_tgt, self.c_ping, self.c_tcp, self.c_status]:
            self.add_widget(w)

    def _bg(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*ROW_O) if self.index % 2 else Color(*ROW_E)
            Rectangle(pos=self.pos, size=self.size)

    def refresh_view_attrs(self, rv, index, data):
        self.index = index
        self._bg()
        sc = ST_CLR.get(data.get("st","dead"), MUTED)
        self.c_tgt.text    = data.get("target","")
        pm  = data.get("p_ms"); pok = data.get("p_ok",False)
        tm  = data.get("t_ms"); tok = data.get("t_ok",False)
        self.c_ping.text   = (f"{pm}ms" if pm else "OK") if pok else "--"
        self.c_ping.color  = GREEN if pok else RED
        self.c_tcp.text    = (f"{tm}ms" if tm else "OK") if tok else "--"
        self.c_tcp.color   = GREEN if tok else RED
        self.c_status.text  = ST_TXT.get(data.get("st","dead"),"?")
        self.c_status.color = sc
        return super().refresh_view_attrs(rv, index, data)


class ResultTable(RecycleView):
    def __init__(self, **kw):
        super().__init__(**kw)
        lay = RecycleBoxLayout(
            default_size=(None, dp(32)),
            default_size_hint=(1, None),
            size_hint_y=None,
            orientation="vertical",
            spacing=dp(1),
        )
        lay.bind(minimum_height=lay.setter("height"))
        self.add_widget(lay)
        self.viewclass = "ResultRow"
        self.data = []


# ─────────────────────────────────────────────────
#  EXPORT MODAL
# ─────────────────────────────────────────────────
class ExportModal(ModalView):
    def __init__(self, results, **kw):
        kw.setdefault("size_hint",        (.86, .78))
        kw.setdefault("background_color", (0,0,0,.82))
        super().__init__(**kw)

        ok_results = [r for r in results if r["st"] == "both"]
        ip_text    = "\n".join(r["target"] for r in ok_results)

        root = Card(spacing=dp(10))
        self.add_widget(root)

        # header row
        hdr = BoxLayout(size_hint_y=None, height=dp(34), spacing=dp(8))
        hdr.add_widget(L("Export  —  Ping + TCP", color=GOLD,
                          size=dp(13), bold=True))
        hdr.add_widget(Widget())
        cl = PillBtn("Close", accent=RED,
                     size_hint=(None,None), size=(dp(76),dp(30)))
        cl.bind(on_release=self.dismiss)
        hdr.add_widget(cl)
        root.add_widget(hdr)
        root.add_widget(divider())

        root.add_widget(L(f"  {len(ok_results)} results  (Ping + TCP)",
                           color=GREEN, size=dp(11),
                           size_hint_y=None, height=dp(22)))

        sc = ScrollView()
        ti = TextInput(
            text=ip_text, multiline=True, readonly=True,
            background_color=list(BG2),
            foreground_color=list(WHITE),
            font_size=dp(11), size_hint_y=None,
        )
        ti.bind(minimum_height=ti.setter("height"))
        sc.add_widget(ti)
        root.add_widget(sc)

        self._ip = ip_text
        row2 = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))
        cb = PillBtn("Copy IP List", accent=GOLD,
                     size_hint_y=None, height=dp(36))
        cb.bind(on_release=self._copy)
        self._ck = L("", color=GREEN, size=dp(10), halign="right")
        row2.add_widget(cb)
        row2.add_widget(self._ck)
        root.add_widget(row2)

    def _copy(self, *_):
        Clipboard.copy(self._ip)
        self._ck.text = "Copied!"
        Clock.schedule_once(lambda _: setattr(self._ck,"text",""), 2)


# ─────────────────────────────────────────────────
#  MAIN ROOT
# ─────────────────────────────────────────────────
class Root(BoxLayout):
    def __init__(self, **kw):
        kw.setdefault("orientation","vertical")
        kw.setdefault("spacing",    dp(0))
        super().__init__(**kw)
        Window.clearcolor = BG0

        self._results  = []
        self._running  = False
        self._lock     = threading.Lock()
        self._total    = 0
        self._buf      = []
        self._cdnchk   = {}

        self._ui()

    # ──────────────────────────────────────────────
    def _ui(self):

        # ═══ TOP BAR ══════════════════════════════
        bar = BoxLayout(
            size_hint_y=None, height=dp(46),
            padding=[dp(14),dp(0),dp(14),dp(0)], spacing=dp(10)
        )
        with bar.canvas.before:
            Color(.08,.08,.11,1)
            bar._bg = Rectangle(pos=bar.pos, size=bar.size)
        bar.bind(pos=lambda *_: setattr(bar._bg,"pos",bar.pos),
                 size=lambda *_: setattr(bar._bg,"size",bar.size))

        # gold left stripe
        stripe = Widget(size_hint_x=None, width=dp(3))
        with stripe.canvas:
            Color(*GOLD)
            stripe._r = Rectangle(pos=stripe.pos, size=stripe.size)
        stripe.bind(pos=lambda w,*_: setattr(w._r,"pos",w.pos),
                    size=lambda w,*_: setattr(w._r,"size",w.size))
        bar.add_widget(stripe)

        # title block
        tb = BoxLayout(orientation="vertical", spacing=dp(1))
        tb.add_widget(L("PowerCodes  Scanner",
                         color=GOLD, size=dp(14), bold=True))
        tb.add_widget(L(f"v{APP_VERSION}  |  {TELEGRAM_HANDLE}  |  {GITHUB}",
                         color=MUTED, size=dp(8)))
        bar.add_widget(tb)
        bar.add_widget(Widget())

        self._status = L("Ready", color=MUTED, size=dp(11),
                          size_hint=(None,None), size=(dp(200),dp(36)),
                          halign="right")
        bar.add_widget(self._status)
        self.add_widget(bar)

        # thin gold line under bar
        ln = Widget(size_hint_y=None, height=dp(2))
        with ln.canvas:
            Color(*GOLD)
            ln._r = Rectangle(pos=ln.pos, size=ln.size)
        ln.bind(pos=lambda w,*_: setattr(w._r,"pos",w.pos),
                size=lambda w,*_: setattr(w._r,"size",w.size))
        self.add_widget(ln)

        # ═══ BODY ═════════════════════════════════
        body = BoxLayout(
            orientation="horizontal",
            spacing=dp(8),
            padding=[dp(10), dp(8), dp(10), dp(8)]
        )
        self.add_widget(body)

        # ─── LEFT SCROLL ──────────────────────────
        lsc = ScrollView(size_hint_x=None, width=dp(252), do_scroll_x=False)
        lcol = BoxLayout(orientation="vertical", spacing=dp(8),
                         size_hint_y=None, padding=[0,dp(2)])
        lcol.bind(minimum_height=lcol.setter("height"))
        lsc.add_widget(lcol)
        body.add_widget(lsc)

        # ─── CARD 1 : Targets ─────────────────────
        c1 = Card(size_hint_y=None, height=dp(250))
        lcol.add_widget(c1)

        c1.add_widget(L("TARGETS", color=GOLD, size=dp(9), bold=True,
                         size_hint_y=None, height=dp(16)))

        self._inp = BigInput(
            hint_text="1.2.3.4\n10.0.0.0/24\nexample.com",
            size_hint_y=None, height=dp(140)
        )
        self._inp.bind(text=lambda *_: Clock.schedule_once(self._recount,.3))
        c1.add_widget(self._inp)

        self._cnt = L("0 targets", color=MUTED, size=dp(9),
                       size_hint_y=None, height=dp(14), halign="right")
        c1.add_widget(self._cnt)

        # ─── CARD 2 : Settings ────────────────────
        c2 = Card(size_hint_y=None, height=dp(172))
        lcol.add_widget(c2)

        c2.add_widget(L("SETTINGS", color=GOLD, size=dp(9), bold=True,
                         size_hint_y=None, height=dp(16)))

        def row(label, val, filt="int"):
            r = BoxLayout(size_hint_y=None, height=dp(32), spacing=dp(6))
            r.add_widget(L(label, color=TEXT, size=dp(10), size_hint_x=1.8))
            fi = FieldInput(text=val,
                            input_filter=filt if filt!="str" else None,
                            size_hint_x=None, width=dp(72))
            r.add_widget(fi)
            return r, fi

        r1, self._port    = row("Port",              "443")
        r2, self._ping_to = row("Ping timeout  (ms)","1500")
        r3, self._tcp_to  = row("TCP timeout  (s)",  "2",  "float")
        r4, self._threads = row("Threads",           "50")
        for r in (r1, r2, r3, r4):
            c2.add_widget(r)

        # ─── CARD 3 : CDN Filter ──────────────────
        cdn_rows_h = len(ALL_CDN) * dp(30)
        c3 = Card(size_hint_y=None, height=dp(16+28+8)+cdn_rows_h+dp(16))
        lcol.add_widget(c3)

        hrow = BoxLayout(size_hint_y=None, height=dp(26), spacing=dp(6))
        hrow.add_widget(L("CDN FILTER  (export)", color=GOLD,
                           size=dp(9), bold=True))
        hrow.add_widget(Widget())
        for txt, val in [("All",True),("None",False)]:
            b = PillBtn(txt, accent=MUTED,
                        size_hint=(None,None), size=(dp(40),dp(22)))
            b._v = val
            b.bind(on_release=lambda btn,*_:
                   [setattr(c,"active",btn._v)
                    for c in self._cdnchk.values()])
            hrow.add_widget(b)
        c3.add_widget(hrow)

        self._cdnchk = {}
        for name in ALL_CDN:
            clr = list(CDN_COL.get(name, MUTED))
            ch  = CheckItem(text=name, active=True, chk_color=clr)
            self._cdnchk[name] = ch
            c3.add_widget(ch)

        # ─── CARD 4 : Buttons ─────────────────────
        c4 = Card(size_hint_y=None, height=dp(130))
        lcol.add_widget(c4)

        self._btn_scan  = PillBtn("Start Scan",     accent=GOLD,
                                   size_hint_y=None, height=dp(38))
        self._btn_stop  = PillBtn("Stop",           accent=RED,
                                   size_hint_y=None, height=dp(32))
        self._btn_exp   = PillBtn("Export Results", accent=GREEN,
                                   size_hint_y=None, height=dp(32))
        self._btn_stop.disabled = True

        self._btn_scan.bind(on_release=self._start)
        self._btn_stop.bind(on_release=self._stop)
        self._btn_exp.bind(on_release=self._export)

        for b in [self._btn_scan, self._btn_stop, self._btn_exp]:
            c4.add_widget(b)

        # ─── CARD 5 : Progress + Stats ────────────
        c5 = Card(size_hint_y=None, height=dp(108))
        lcol.add_widget(c5)

        self._prog = ProgressBar(max=100, value=0,
                                  size_hint_y=None, height=dp(6))
        c5.add_widget(self._prog)
        self._prog_lbl = L("0 / 0", color=MUTED, size=dp(9),
                            size_hint_y=None, height=dp(14), halign="center")
        c5.add_widget(self._prog_lbl)

        g = GridLayout(cols=2, spacing=dp(5), size_hint_y=None, height=dp(68))
        self._m_both = StatBox("Ping + TCP", GREEN)
        self._m_tcp  = StatBox("TCP Only",   GOLD)
        self._m_all  = StatBox("Scanned",    WHITE)
        self._m_dead = StatBox("Dead",        RED)
        for m in [self._m_both, self._m_tcp, self._m_all, self._m_dead]:
            g.add_widget(m)
        c5.add_widget(g)

        # ═══ RIGHT : TABLE ════════════════════════
        right = BoxLayout(orientation="vertical", spacing=dp(4))
        body.add_widget(right)

        # header row
        th = BoxLayout(
            size_hint_y=None, height=dp(24),
            padding=[dp(10),dp(0)], spacing=dp(0)
        )
        with th.canvas.before:
            Color(.12,.12,.16,1)
            th._bg = Rectangle(pos=th.pos, size=th.size)
        th.bind(pos=lambda *_: setattr(th._bg,"pos",th.pos),
                size=lambda *_: setattr(th._bg,"size",th.size))

        for txt,fx in [("TARGET",2.8),("PING",1.0),("TCP",1.0),("STATUS",0.75)]:
            th.add_widget(L(txt, color=MUTED, size=dp(8),
                             bold=True, size_hint_x=fx))
        right.add_widget(th)

        self._rv = ResultTable()
        right.add_widget(self._rv)

    # ──────────────────────────────────────────────
    def _recount(self, *_):
        n = len(parse_targets(self._inp.text))
        self._cnt.text = f"{n} targets"

    def _setstatus(self, t, c):
        self._status.text  = t
        self._status.color = c

    # ── scan ──────────────────────────────────────
    def _start(self, *_):
        targets = parse_targets(self._inp.text.strip())
        if not targets:
            self._setstatus("No valid targets", RED); return
        try:
            port  = int(self._port.text   or "443")
            pm    = int(self._ping_to.text or "1500")
            tm    = float(self._tcp_to.text or "2.0")
            wrk   = max(1, min(int(self._threads.text or "50"), 500))
        except ValueError:
            self._setstatus("Bad settings", RED); return

        self._results=[]; self._buf=[]
        self._total=len(targets); self._running=True
        self._rv.data=[]
        self._prog.value=0
        self._prog_lbl.text=f"0 / {self._total}"
        for m in [self._m_both,self._m_tcp,self._m_all,self._m_dead]: m.set(0)
        self._btn_scan.disabled=True
        self._btn_stop.disabled=False
        self._setstatus(f"Scanning  {self._total} targets...", GOLD)

        Clock.schedule_interval(self._flush, .25)
        threading.Thread(
            target=self._worker,
            args=(targets,port,pm,tm,wrk),
            daemon=True
        ).start()

    def _worker(self, targets, port, pm, tm, wrk):
        with concurrent.futures.ThreadPoolExecutor(max_workers=wrk) as ex:
            futs = {ex.submit(scan_one, t, port, pm, tm): t for t in targets}
            for f in concurrent.futures.as_completed(futs):
                if not self._running:
                    ex.shutdown(wait=False, cancel_futures=True); break
                try:
                    res = f.result()
                    with self._lock:
                        self._results.append(res)
                        self._buf.append(res)
                except Exception: pass
        Clock.schedule_once(lambda _: self._done(), 0)

    def _flush(self, dt):
        with self._lock:
            buf = list(self._buf); self._buf = []
            n   = len(self._results)
        if buf:
            self._rv.data = list(self._rv.data) + buf
        d = self._rv.data
        self._m_both.set(sum(1 for r in d if r["st"]=="both"))
        self._m_tcp.set( sum(1 for r in d if r["st"]=="tcp"))
        self._m_all.set(n)
        self._m_dead.set(sum(1 for r in d if r["st"]=="dead"))
        pct = n/self._total*100 if self._total else 0
        self._prog.value    = pct
        self._prog_lbl.text = f"{n} / {self._total}"

    def _done(self):
        Clock.unschedule(self._flush); self._flush(0)
        self._running=False
        self._btn_scan.disabled=False
        self._btn_stop.disabled=True
        self._setstatus(f"Done  —  {len(self._results)} checked", GREEN)

    def _stop(self, *_):
        Clock.unschedule(self._flush); self._flush(0)
        self._running=False
        self._btn_scan.disabled=False
        self._btn_stop.disabled=True
        self._setstatus("Stopped", AMBER)

    def _export(self, *_):
        with self._lock: data = list(self._results)
        if not data: self._setstatus("No results yet", RED); return
        active   = {n for n,c in self._cdnchk.items() if c.active}
        filtered = [r for r in data
                    if r["st"]=="both" and r.get("cdn","Unknown") in active]
        if not filtered:
            self._setstatus("No matching results", AMBER); return
        ExportModal(filtered).open()


# ─────────────────────────────────────────────────
#  APP
# ─────────────────────────────────────────────────
class ScanApp(App):
    title = f"PowerCodes Scanner  v{APP_VERSION}"
    def build(self):
        if not IS_ANDROID: Window.size = (1120, 720)
        else: Window.softinput_mode = "below_target"
        return Root()

if __name__ == "__main__":
    ScanApp().run()
