#!/usr/bin/env python3
"""Modern desktop GUI for the Enterprise File Integrity Monitor.

Dark "Indigo Aurora" theme — deep indigo-black with luminous lavender accents.
Surfaces every CLI capability (baseline, check, continuous monitor, stats,
honeypots, security status, logs) through one polished workspace.

Run with:  python fim_gui.py
"""

from __future__ import annotations

import json
import math
import os
import queue
import threading
import time
import tkinter as tk
import traceback
from collections import defaultdict
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import customtkinter as ctk
from PIL import Image, ImageDraw, ImageFont

from fim import EnterpriseFileIntegrityMonitor
from fim.models import ChangeEvent


# ============================================================================
# Theme — single dark "Indigo Aurora" palette
# ============================================================================

class Theme:
    """Dark-only palette. Class attributes so widgets reference them directly."""

    bg             = '#08081C'
    bg_alt         = '#10102A'
    bg_elev        = '#15142F'
    card           = '#1A1838'
    card_hover     = '#252343'
    card_active    = '#2E2A5A'
    border         = '#2B2950'
    border_strong  = '#48446F'
    border_glow    = '#7C70FF'
    text           = '#F2F0FA'
    text_muted     = '#A9A5C4'
    text_subtle    = '#706C90'
    accent         = '#7C70FF'
    accent_hover   = '#9A90FF'
    accent_pressed = '#5B4FE5'
    accent_soft    = '#2C2660'
    success        = '#34D399'
    success_soft   = '#0E2E29'
    warning        = '#FBBF24'
    warning_soft   = '#33271A'
    critical       = '#F87171'
    critical_soft  = '#311B1F'
    info           = '#7BBBFF'
    info_soft      = '#172238'
    sidebar        = '#05041A'
    sidebar_sel    = '#1A1838'
    switch_track   = '#3B3760'
    switch_knob    = '#F2F0FA'
    switch_border  = '#7C70FF'

    FONT_FAMILY = 'Segoe UI'
    MONO_FAMILY = 'Consolas'


# ============================================================================
# Icon rendering — Pillow-drawn, cached
# ============================================================================

def _hex_to_rgb(h: str) -> Tuple[int, int, int]:
    h = h.lstrip('#')
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _new_canvas(size: int) -> Tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    return img, ImageDraw.Draw(img)


def _draw_icon(name: str, size: int, color: str) -> Image.Image:
    img, d = _new_canvas(size)
    c = _hex_to_rgb(color)
    s = size
    stroke = max(2, s // 12)

    if name == 'dashboard':
        pad = s // 6
        gap = s // 12
        cell = (s - 2 * pad - gap) // 2
        for r in range(2):
            for cc in range(2):
                x = pad + cc * (cell + gap)
                y = pad + r * (cell + gap)
                d.rounded_rectangle([x, y, x + cell, y + cell],
                                    radius=cell // 4, fill=c)
    elif name == 'folders':
        pad = s // 6
        top = s // 3
        d.rounded_rectangle([pad, top - s // 8,
                             pad + s // 2.4, top + s // 18],
                            radius=stroke, fill=c)
        d.rounded_rectangle([pad, top, s - pad, s - pad],
                            radius=stroke, fill=c)
    elif name == 'scan':
        pad = s // 7
        r1 = s // 2.6
        cx = pad + r1
        cy = pad + r1
        d.ellipse([cx - r1, cy - r1, cx + r1, cy + r1],
                  outline=c, width=stroke)
        hx1 = cx + r1 * 0.7
        hy1 = cy + r1 * 0.7
        hx2 = s - pad
        hy2 = s - pad
        d.line([hx1, hy1, hx2, hy2], fill=c, width=stroke + 1)
    elif name == 'monitor':
        pad = s // 6
        cx = cy = s / 2
        r = (s - 2 * pad) / 2
        d.ellipse([cx - r, cy - r, cx + r, cy + r],
                  outline=c, width=stroke)
        r_inner = r * 0.42
        d.ellipse([cx - r_inner, cy - r_inner, cx + r_inner, cy + r_inner],
                  fill=c)
    elif name == 'activity':
        pad = s // 6
        d.line([pad, s - pad, s - pad, s - pad], fill=c, width=stroke - 1)
        pts = [
            (pad, s - pad - s // 8),
            (pad + (s - 2 * pad) * 0.33, s - pad - s // 2.3),
            (pad + (s - 2 * pad) * 0.55, s - pad - s // 3.5),
            (pad + (s - 2 * pad) * 0.8, s - pad - s // 1.6),
            (s - pad, s - pad - s // 2.1),
        ]
        d.line(pts, fill=c, width=stroke + 1, joint='curve')
        for p in pts:
            d.ellipse([p[0] - stroke, p[1] - stroke,
                       p[0] + stroke, p[1] + stroke], fill=c)
    elif name == 'logs':
        pad = s // 6
        d.rounded_rectangle([pad, pad, s - pad, s - pad],
                            radius=stroke, outline=c, width=stroke - 1)
        line_pad = pad + stroke + 2
        line_count = 4
        gap = (s - 2 * line_pad) // (line_count + 1)
        for i in range(1, line_count + 1):
            y = line_pad + i * gap
            d.line([line_pad, y, s - line_pad - (i % 2) * (s // 5), y],
                   fill=c, width=stroke - 1)
    elif name == 'security':
        pad = s // 7
        w = s - 2 * pad
        h = s - 2 * pad
        cx = s / 2
        top = pad
        pts = [
            (cx, top),
            (cx + w / 2, top + h * 0.2),
            (cx + w / 2, top + h * 0.55),
            (cx, top + h),
            (cx - w / 2, top + h * 0.55),
            (cx - w / 2, top + h * 0.2),
        ]
        d.polygon(pts, fill=c)
        cw = w * 0.45
        check = [
            (cx - cw / 2, top + h * 0.45),
            (cx - cw * 0.1, top + h * 0.62),
            (cx + cw / 2, top + h * 0.28),
        ]
        d.line(check, fill=(255, 255, 255, 0), width=stroke + 1, joint='curve')
    elif name == 'settings':
        pad = s // 6
        cx = cy = s / 2
        r_outer = (s - 2 * pad) / 2
        r_inner = r_outer * 0.68
        r_hole = r_outer * 0.30
        n = 8
        pts = []
        for i in range(n * 2):
            ang = (i * math.pi / n) - math.pi / 2
            r = r_outer if (i % 2 == 0) else r_inner
            pts.append((cx + r * math.cos(ang), cy + r * math.sin(ang)))
        d.polygon(pts, fill=c)
        d.ellipse([cx - r_hole, cy - r_hole,
                   cx + r_hole, cy + r_hole], fill=(0, 0, 0, 0))
    elif name == 'play':
        pad = s // 5
        pts = [(pad, pad), (s - pad, s / 2), (pad, s - pad)]
        d.polygon(pts, fill=c)
    elif name == 'stop':
        pad = s // 4
        d.rounded_rectangle([pad, pad, s - pad, s - pad],
                            radius=stroke, fill=c)
    elif name == 'refresh':
        pad = s // 6
        cx = cy = s / 2
        r = (s - 2 * pad) / 2
        d.arc([cx - r, cy - r, cx + r, cy + r], 30, 320,
              fill=c, width=stroke)
        d.polygon([
            (cx + r * 0.95, cy - r * 0.55),
            (cx + r * 0.4, cy - r * 0.55),
            (cx + r * 0.8, cy - r * 1.15),
        ], fill=c)
    return img


@lru_cache(maxsize=256)
def make_ctk_image(name: str, size: int, color: str) -> ctk.CTkImage:
    """Return (and cache) a CTkImage for the named icon at the given color."""
    img = _draw_icon(name, size * 2, color)
    return ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))


@lru_cache(maxsize=8)
def make_logo(size_w: int, size_h: int, accent: str,
              text_color: str) -> ctk.CTkImage:
    """Diamond-shield monogram with 'FIM' wordmark."""
    img = Image.new('RGBA', (size_w * 2, size_h * 2), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    W, H = size_w * 2, size_h * 2

    mark_size = H * 0.9
    mx = H * 0.6
    my = H / 2
    pts = [
        (mx, my - mark_size / 2),
        (mx + mark_size / 2, my),
        (mx, my + mark_size / 2),
        (mx - mark_size / 2, my),
    ]
    d.polygon(pts, fill=_hex_to_rgb(accent))
    d.polygon([
        (mx, my - mark_size * 0.25),
        (mx + mark_size * 0.25, my),
        (mx, my + mark_size * 0.25),
        (mx - mark_size * 0.25, my),
    ], fill=(0, 0, 0, 0))
    d.polygon([
        (mx - mark_size * 0.06, my - mark_size * 0.18),
        (mx + mark_size * 0.18, my - mark_size * 0.18),
        (mx + mark_size * 0.18, my - mark_size * 0.06),
        (mx + mark_size * 0.02, my - mark_size * 0.06),
        (mx + mark_size * 0.02, my + mark_size * 0.18),
        (mx - mark_size * 0.06, my + mark_size * 0.18),
    ], fill=_hex_to_rgb(accent))

    try:
        font = ImageFont.truetype('segoeuib.ttf', int(H * 0.55))
    except Exception:
        try:
            font = ImageFont.truetype('arialbd.ttf', int(H * 0.55))
        except Exception:
            font = ImageFont.load_default()
    tx = mx + mark_size * 0.7
    ty = (H - H * 0.55) / 2 - H * 0.08
    d.text((tx, ty), 'FIM', fill=_hex_to_rgb(text_color), font=font)

    return ctk.CTkImage(light_image=img, dark_image=img,
                        size=(size_w, size_h))


# ============================================================================
# Small reusable widgets
# ============================================================================

class Card(ctk.CTkFrame):
    """Rounded card with optional title/subtitle header."""

    def __init__(self, parent, title: Optional[str] = None,
                 subtitle: Optional[str] = None, **kwargs):
        super().__init__(
            parent,
            fg_color=Theme.card,
            border_color=Theme.border,
            border_width=1,
            corner_radius=14,
            **kwargs,
        )
        if title:
            head = ctk.CTkFrame(self, fg_color='transparent')
            head.pack(fill='x', padx=22, pady=(18, 0))
            ctk.CTkLabel(
                head, text=title,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                                 size=15, weight='bold'),
                text_color=Theme.text, anchor='w',
            ).pack(anchor='w')
            if subtitle:
                ctk.CTkLabel(
                    head, text=subtitle,
                    font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
                    text_color=Theme.text_muted, anchor='w',
                ).pack(anchor='w', pady=(2, 0))

    def body(self) -> ctk.CTkFrame:
        f = ctk.CTkFrame(self, fg_color='transparent')
        f.pack(fill='both', expand=True, padx=22, pady=(14, 18))
        return f


class Pill(ctk.CTkLabel):
    KIND_MAP = {
        'success':  ('success_soft', 'success'),
        'warning':  ('warning_soft', 'warning'),
        'critical': ('critical_soft', 'critical'),
        'neutral':  ('bg_alt', 'text_muted'),
        'accent':   ('accent_soft', 'accent'),
        'info':     ('info_soft', 'info'),
    }

    def __init__(self, parent, text: str, kind: str = 'neutral', **kw):
        bg_attr, fg_attr = self.KIND_MAP.get(kind, self.KIND_MAP['neutral'])
        super().__init__(
            parent, text=text,
            fg_color=getattr(Theme, bg_attr),
            text_color=getattr(Theme, fg_attr),
            corner_radius=8, padx=10, pady=2,
            font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                             size=11, weight='bold'),
            **kw,
        )


class PrimaryButton(ctk.CTkButton):
    def __init__(self, parent, text: str, command: Callable, **kw):
        super().__init__(
            parent, text=text, command=command,
            fg_color=Theme.accent, hover_color=Theme.accent_hover,
            text_color='#FFFFFF',
            corner_radius=10, height=36,
            font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                             size=13, weight='bold'),
            **kw,
        )


class SecondaryButton(ctk.CTkButton):
    def __init__(self, parent, text: str, command: Callable, **kw):
        super().__init__(
            parent, text=text, command=command,
            fg_color=Theme.card, hover_color=Theme.card_hover,
            text_color=Theme.text,
            border_color=Theme.border_strong, border_width=1,
            corner_radius=10, height=36,
            font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                             size=13, weight='bold'),
            **kw,
        )


class DangerButton(ctk.CTkButton):
    def __init__(self, parent, text: str, command: Callable, **kw):
        super().__init__(
            parent, text=text, command=command,
            fg_color='transparent', hover_color=Theme.critical_soft,
            text_color=Theme.critical,
            border_color=Theme.critical, border_width=1,
            corner_radius=10, height=36,
            font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                             size=13, weight='bold'),
            **kw,
        )


# ============================================================================
# Sidebar
# ============================================================================

class Sidebar(ctk.CTkFrame):
    NAV_ITEMS = [
        ('dashboard', 'Dashboard'),
        ('folders',   'Folders'),
        ('scan',      'Scan & Check'),
        ('monitor',   'Live Monitor'),
        ('activity',  'Activity'),
        ('logs',      'Logs'),
        ('security',  'Security'),
        ('settings',  'Settings'),
    ]

    def __init__(self, parent, on_nav: Callable[[str], None]):
        super().__init__(parent, fg_color=Theme.sidebar, width=232,
                         corner_radius=0)
        self.on_nav = on_nav
        self.buttons: Dict[str, ctk.CTkButton] = {}
        self.pack_propagate(False)
        self._build()

    def _build(self):
        head = ctk.CTkFrame(self, fg_color='transparent', height=82)
        head.pack(fill='x', padx=18, pady=(20, 8))
        head.pack_propagate(False)
        logo_img = make_logo(168, 38, Theme.accent, Theme.text)
        ctk.CTkLabel(head, text='', image=logo_img,
                     fg_color='transparent').pack(anchor='w')
        ctk.CTkLabel(
            head, text='File Integrity Monitor',
            font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=11),
            text_color=Theme.text_muted, anchor='w',
        ).pack(anchor='w', pady=(2, 0))

        for key, label in self.NAV_ITEMS:
            icon = make_ctk_image(key, 18, Theme.text_muted)
            btn = ctk.CTkButton(
                self, text='  ' + label, anchor='w',
                image=icon, compound='left',
                command=lambda k=key: self.on_nav(k),
                fg_color='transparent', hover_color=Theme.card_hover,
                text_color=Theme.text,
                corner_radius=10, height=40,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=13),
            )
            btn.pack(fill='x', padx=12, pady=2)
            self.buttons[key] = btn

        ctk.CTkFrame(self, fg_color='transparent', height=1).pack(
            fill='x', expand=True)

        self.status_frame = ctk.CTkFrame(self, fg_color='transparent')
        self.status_frame.pack(fill='x', padx=14, pady=(0, 16))
        self.status_dot = ctk.CTkLabel(
            self.status_frame, text='●',
            font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=14, weight='bold'),
            text_color=Theme.text_subtle, width=14,
        )
        self.status_dot.pack(side='left')
        self.status_label = ctk.CTkLabel(
            self.status_frame, text='Monitor idle',
            font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=11),
            text_color=Theme.text_muted, anchor='w',
        )
        self.status_label.pack(side='left', padx=(6, 0))

    def select(self, key: str):
        for k, btn in self.buttons.items():
            if k == key:
                btn.configure(
                    fg_color=Theme.sidebar_sel,
                    text_color=Theme.accent,
                    image=make_ctk_image(k, 18, Theme.accent),
                    font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                                     size=13, weight='bold'),
                )
            else:
                btn.configure(
                    fg_color='transparent',
                    text_color=Theme.text,
                    image=make_ctk_image(k, 18, Theme.text_muted),
                    font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=13),
                )

    def set_monitor_status(self, running: bool, detail: str = ''):
        if running:
            self.status_dot.configure(text_color=Theme.success)
            self.status_label.configure(
                text=detail or 'Monitor running', text_color=Theme.success)
        else:
            self.status_dot.configure(text_color=Theme.text_subtle)
            self.status_label.configure(
                text=detail or 'Monitor idle', text_color=Theme.text_muted)


# ============================================================================
# Worker & MonitorRunner
# ============================================================================

class FIMWorker:
    """Run blocking calls on a daemon thread, surface result via Tk after()."""

    def __init__(self):
        self.queue: queue.Queue = queue.Queue()

    def run(self, fn: Callable, *args, on_done: Optional[Callable] = None):
        def _runner():
            try:
                result = fn(*args)
                self.queue.put(('ok', result, on_done))
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                self.queue.put(('err', e, on_done))
        threading.Thread(target=_runner, daemon=True).start()

    def poll(self, root: tk.Misc):
        try:
            while True:
                status, payload, on_done = self.queue.get_nowait()
                if on_done is not None:
                    on_done(status, payload)
        except queue.Empty:
            pass
        root.after(120, lambda: self.poll(root))


class MonitorRunner:
    """Background continuous-scan loop with start/stop and event callback."""

    def __init__(self, fim: EnterpriseFileIntegrityMonitor):
        self.fim = fim
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.on_event: Optional[Callable[[str, str], None]] = None
        self.on_status: Optional[Callable[[bool, str], None]] = None
        self.on_changes: Optional[Callable[[], None]] = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, folders: List[str], interval: int) -> bool:
        if self.is_running() or not folders:
            return False
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, args=(list(folders), max(5, int(interval))),
            daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()

    def _emit(self, level: str, message: str):
        if self.on_event:
            try:
                self.on_event(level, message)
            except Exception:  # noqa: BLE001
                pass

    def _status(self, running: bool, detail: str = ''):
        if self.on_status:
            try:
                self.on_status(running, detail)
            except Exception:  # noqa: BLE001
                pass

    def _run(self, folders: List[str], interval: int):
        self._status(True, f'Watching {len(folders)} folder(s) every {interval}s')
        self._emit('info',
                   f'Monitor started — {len(folders)} folder(s), '
                   f'interval {interval}s')
        scan_count = 0
        try:
            while not self._stop.is_set():
                scan_count += 1
                ts = datetime.now().strftime('%H:%M:%S')
                self._emit('info', f'[{ts}] Scan #{scan_count} started')
                any_changes = False
                for folder in folders:
                    if self._stop.is_set():
                        break
                    try:
                        changes = self.fim.check_integrity(folder)
                    except Exception as e:  # noqa: BLE001
                        self._emit('error', f'  ✗ {folder}: {e}')
                        continue
                    total = sum(len(v) for v in (changes or {}).values())
                    if total:
                        any_changes = True
                        self._emit('warn',
                                   f'  ⚠ {folder}: {total} change(s)')
                        for ev in (changes.get('modified') or [])[:10]:
                            self._emit(ev.severity,
                                       f'      ↻ {ev.file_path}')
                        for ev in (changes.get('added') or [])[:10]:
                            self._emit(ev.severity,
                                       f'      + {ev.file_path}')
                        for ev in (changes.get('deleted') or [])[:10]:
                            self._emit(ev.severity,
                                       f'      ✕ {ev.file_path}')
                    else:
                        self._emit('ok', f'  ✓ {folder}: no changes')
                if any_changes and self.on_changes:
                    try:
                        self.on_changes()
                    except Exception:  # noqa: BLE001
                        pass
                self._emit('info', f'Next scan in {interval}s')
                self._stop.wait(timeout=interval)
        finally:
            self._status(False, 'Monitor idle')
            self._emit('info', 'Monitor stopped')


# ============================================================================
# Base view (scrollable + header)
# ============================================================================

class BaseView(ctk.CTkScrollableFrame):
    def __init__(self, parent, title: str, subtitle: str = ''):
        super().__init__(parent, fg_color=Theme.bg, corner_radius=0)
        self._build_header(title, subtitle)

    def _build_header(self, title: str, subtitle: str):
        head = ctk.CTkFrame(self, fg_color='transparent')
        head.pack(fill='x', padx=32, pady=(28, 18))
        ctk.CTkLabel(
            head, text=title,
            font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                             size=24, weight='bold'),
            text_color=Theme.text, anchor='w',
        ).pack(anchor='w')
        if subtitle:
            ctk.CTkLabel(
                head, text=subtitle,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=13),
                text_color=Theme.text_muted, anchor='w',
            ).pack(anchor='w', pady=(4, 0))


# ============================================================================
# Shared rendering helpers
# ============================================================================

SEV_KIND = {'critical': 'critical', 'high': 'warning',
            'medium': 'accent', 'low': 'neutral'}
TYPE_ICON = {'modified': '↻', 'added': '+', 'deleted': '✕'}


def render_activity_row(parent, ev: Dict):
    row = ctk.CTkFrame(parent, fg_color='transparent', height=44)
    row.pack(fill='x', pady=4)
    row.pack_propagate(False)
    Pill(row, ev['severity'].upper(),
         SEV_KIND.get(ev['severity'], 'neutral'),
         ).pack(side='left', padx=(0, 12))
    icon = TYPE_ICON.get(ev['event_type'], '•')
    ctk.CTkLabel(
        row, text=f"{icon} {ev['event_type']}",
        font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12, weight='bold'),
        text_color=Theme.text, width=90, anchor='w',
    ).pack(side='left')
    ctk.CTkLabel(
        row, text=ev['file_path'],
        font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
        text_color=Theme.text_muted, anchor='w',
    ).pack(side='left', fill='x', expand=True, padx=(8, 12))
    ts = ev['timestamp'][:19].replace('T', ' ')
    ctk.CTkLabel(
        row, text=ts,
        font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=11),
        text_color=Theme.text_subtle,
    ).pack(side='right')


def render_severity_bar(parent, severity: str, count: int, total: int):
    color = {
        'critical': Theme.critical, 'high': Theme.warning,
        'medium': Theme.accent,     'low': Theme.success,
    }.get(severity, Theme.text_muted)
    row = ctk.CTkFrame(parent, fg_color='transparent')
    row.pack(fill='x', pady=4)
    ctk.CTkLabel(
        row, text=severity.capitalize(),
        font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12, weight='bold'),
        text_color=color, width=80, anchor='w',
    ).pack(side='left')
    pb = ctk.CTkProgressBar(row, progress_color=color, fg_color=Theme.bg_alt,
                            corner_radius=4, height=10)
    pb.pack(side='left', fill='x', expand=True, padx=(8, 12))
    pb.set((count / total) if total else 0)
    ctk.CTkLabel(
        row, text=str(count),
        font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
        text_color=Theme.text, width=40, anchor='e',
    ).pack(side='right')


# ============================================================================
# Dashboard
# ============================================================================

class DashboardView(BaseView):
    STATS = [
        ('folders',  'Watched folders'),
        ('files',    'Files monitored'),
        ('changes',  'Changes (24h)'),
        ('critical', 'Critical alerts'),
    ]

    def __init__(self, parent, app: 'FIMApp'):
        super().__init__(parent,
                         'Dashboard',
                         'Overview of file integrity across your watched folders.')
        self.app = app
        self._build()

    def _build(self):
        self.status_card = Card(self)
        self.status_card.pack(fill='x', padx=32, pady=(0, 16))
        body = self.status_card.body()
        self.status_icon = ctk.CTkLabel(
            body, text='—', font=ctk.CTkFont(size=38, weight='bold'),
            text_color=Theme.text_muted, width=60,
        )
        self.status_icon.pack(side='left', padx=(0, 18))
        right = ctk.CTkFrame(body, fg_color='transparent')
        right.pack(side='left', fill='both', expand=True)
        self.status_title = ctk.CTkLabel(
            right, text='No baseline yet',
            font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                             size=20, weight='bold'),
            text_color=Theme.text, anchor='w',
        )
        self.status_title.pack(anchor='w')
        self.status_sub = ctk.CTkLabel(
            right, text='Add a folder to start monitoring.',
            font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=13),
            text_color=Theme.text_muted, anchor='w',
        )
        self.status_sub.pack(anchor='w', pady=(2, 0))
        self.monitor_pill = Pill(body, 'MONITOR IDLE', 'neutral')
        self.monitor_pill.pack(side='right', padx=(12, 0))

        stats_row = ctk.CTkFrame(self, fg_color='transparent')
        stats_row.pack(fill='x', padx=32, pady=(0, 16))
        self.stat_widgets: Dict[str, ctk.CTkLabel] = {}
        for i, (key, label) in enumerate(self.STATS):
            card = Card(stats_row)
            card.grid(row=0, column=i, sticky='nsew',
                      padx=(0, 12 if i < len(self.STATS) - 1 else 0))
            stats_row.grid_columnconfigure(i, weight=1)
            b = card.body()
            ctk.CTkLabel(
                b, text=label,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
                text_color=Theme.text_muted, anchor='w',
            ).pack(anchor='w')
            val = ctk.CTkLabel(
                b, text='—',
                font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                                 size=28, weight='bold'),
                text_color=Theme.text, anchor='w',
            )
            val.pack(anchor='w', pady=(4, 0))
            self.stat_widgets[key] = val

        actions = Card(self, title='Quick actions',
                       subtitle='Common operations at a glance.')
        actions.pack(fill='x', padx=32, pady=(0, 16))
        ab = actions.body()
        row = ctk.CTkFrame(ab, fg_color='transparent')
        row.pack(fill='x')
        PrimaryButton(row, '+ Add Folder',
                      lambda: self.app.nav('folders', action='add')
                      ).pack(side='left', padx=(0, 10))
        SecondaryButton(row, 'Run Check',
                        lambda: self.app.nav('scan')
                        ).pack(side='left', padx=(0, 10))
        SecondaryButton(row, 'Start Monitor',
                        lambda: self.app.nav('monitor')
                        ).pack(side='left', padx=(0, 10))
        SecondaryButton(row, 'Deploy Honeypots',
                        lambda: self.app.nav('security')
                        ).pack(side='left')

        self.activity_card = Card(self, title='Recent activity',
                                  subtitle='Last 5 detected changes.')
        self.activity_card.pack(fill='x', padx=32, pady=(0, 32))
        self.activity_body = self.activity_card.body()

        self.refresh()

    def refresh(self):
        folders = self.app.get_watched_folders()
        history = self.app.fim.db.get_change_history(hours=24)
        critical = sum(1 for h in history if h['severity'] == 'critical')
        file_count = len(self.app.fim.db.get_baseline())

        self.stat_widgets['folders'].configure(text=str(len(folders)))
        self.stat_widgets['files'].configure(text=str(file_count))
        self.stat_widgets['changes'].configure(text=str(len(history)))
        self.stat_widgets['critical'].configure(
            text=str(critical),
            text_color=Theme.critical if critical else Theme.text,
        )

        running = self.app.monitor.is_running()
        if running:
            self.monitor_pill.configure(
                text='● MONITOR LIVE', fg_color=Theme.success_soft,
                text_color=Theme.success)
        else:
            self.monitor_pill.configure(
                text='MONITOR IDLE', fg_color=Theme.bg_alt,
                text_color=Theme.text_muted)

        if not folders:
            self.status_icon.configure(text='—', text_color=Theme.text_muted)
            self.status_title.configure(text='No baseline yet',
                                        text_color=Theme.text)
            self.status_sub.configure(text='Add a folder to start monitoring.')
        elif critical:
            self.status_icon.configure(text='!', text_color=Theme.critical)
            self.status_title.configure(text=f'{critical} critical alert(s)',
                                        text_color=Theme.critical)
            self.status_sub.configure(text='Open Activity for full details.')
        elif history:
            self.status_icon.configure(text='~', text_color=Theme.warning)
            self.status_title.configure(
                text=f'{len(history)} change(s) in the last 24h',
                text_color=Theme.warning)
            self.status_sub.configure(text='Review recent activity below.')
        else:
            self.status_icon.configure(text='✓', text_color=Theme.success)
            self.status_title.configure(text='All clear',
                                        text_color=Theme.success)
            self.status_sub.configure(
                text='No changes detected across watched folders.')

        for w in self.activity_body.winfo_children():
            w.destroy()
        if not history:
            ctk.CTkLabel(
                self.activity_body,
                text='Nothing here yet — events will appear after your first check.',
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
                text_color=Theme.text_muted, anchor='w',
            ).pack(anchor='w')
        else:
            for ev in history[:5]:
                render_activity_row(self.activity_body, ev)


# ============================================================================
# Folders
# ============================================================================

class FoldersView(BaseView):
    def __init__(self, parent, app: 'FIMApp'):
        super().__init__(parent,
                         'Watched Folders',
                         'Directories under integrity monitoring.')
        self.app = app
        self._build()

    def _build(self):
        action_bar = ctk.CTkFrame(self, fg_color='transparent')
        action_bar.pack(fill='x', padx=32, pady=(0, 16))
        PrimaryButton(action_bar, '+ Add Folder',
                      self.add_folder).pack(side='left')
        SecondaryButton(action_bar, 'Refresh',
                        self.refresh).pack(side='left', padx=(10, 0))
        self.list_container = ctk.CTkFrame(self, fg_color='transparent')
        self.list_container.pack(fill='both', expand=True,
                                 padx=32, pady=(0, 32))
        self.refresh()

    def add_folder(self):
        path = filedialog.askdirectory(title='Select folder to monitor')
        if not path:
            return
        self.app.add_folder(path)
        self.refresh()
        self.app.dashboard.refresh()

    def refresh(self):
        for w in self.list_container.winfo_children():
            w.destroy()
        folders = self.app.get_watched_folders()
        if not folders:
            empty = Card(self.list_container)
            empty.pack(fill='x')
            b = empty.body()
            ctk.CTkLabel(
                b, text='No folders being monitored.',
                font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                                 size=14, weight='bold'),
                text_color=Theme.text,
            ).pack(anchor='w')
            ctk.CTkLabel(
                b, text="Click '+ Add Folder' to begin.",
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
                text_color=Theme.text_muted,
            ).pack(anchor='w', pady=(4, 0))
            return
        for folder in folders:
            self._render_folder_card(folder)

    def _render_folder_card(self, folder: str):
        card = Card(self.list_container)
        card.pack(fill='x', pady=(0, 12))
        b = card.body()
        top = ctk.CTkFrame(b, fg_color='transparent')
        top.pack(fill='x')
        baseline = self.app.fim.db.get_baseline(folder)
        exists = Path(folder).exists()
        ctk.CTkLabel(
            top, text=folder,
            font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                             size=14, weight='bold'),
            text_color=Theme.text, anchor='w',
        ).pack(side='left', fill='x', expand=True)
        if not exists:
            Pill(top, 'PATH MISSING', 'critical').pack(side='right')
        elif not baseline:
            Pill(top, 'NO BASELINE', 'warning').pack(side='right')
        else:
            Pill(top, f'{len(baseline)} files', 'success').pack(side='right')
        actions = ctk.CTkFrame(b, fg_color='transparent')
        actions.pack(fill='x', pady=(14, 0))
        SecondaryButton(actions, 'Re-baseline',
                        lambda f=folder: self.app.run_baseline([f])
                        ).pack(side='left', padx=(0, 8))
        SecondaryButton(actions, 'Check Now',
                        lambda f=folder: self.app.run_check(f)
                        ).pack(side='left', padx=(0, 8))
        DangerButton(actions, 'Remove',
                     lambda f=folder: self._remove(f)
                     ).pack(side='right')

    def _remove(self, folder: str):
        if not messagebox.askyesno(
                'Remove folder',
                f'Stop monitoring "{folder}"?\nBaseline entries for this '
                'folder will be removed.'):
            return
        self.app.remove_folder(folder)
        self.refresh()
        self.app.dashboard.refresh()


# ============================================================================
# Scan & Check
# ============================================================================

class ScanView(BaseView):
    def __init__(self, parent, app: 'FIMApp'):
        super().__init__(parent,
                         'Scan & Check',
                         'Run an integrity check against a baseline.')
        self.app = app
        self._build()

    def _build(self):
        picker = Card(self, title='Select folder',
                      subtitle='Pick a watched folder and run a fresh integrity check.')
        picker.pack(fill='x', padx=32, pady=(0, 16))
        b = picker.body()
        self.folder_var = tk.StringVar()
        self.folder_menu = ctk.CTkOptionMenu(
            b, variable=self.folder_var, values=['(no folders)'],
            fg_color=Theme.card_hover,
            button_color=Theme.accent,
            button_hover_color=Theme.accent_hover,
            text_color=Theme.text, dropdown_text_color=Theme.text,
            corner_radius=10, height=36,
            font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=13),
        )
        self.folder_menu.pack(fill='x')
        btn_row = ctk.CTkFrame(b, fg_color='transparent')
        btn_row.pack(fill='x', pady=(14, 0))
        self.check_btn = PrimaryButton(btn_row, '▶  Run Integrity Check',
                                       self._run)
        self.check_btn.pack(side='left')
        self.progress = ctk.CTkProgressBar(btn_row, mode='indeterminate',
                                           progress_color=Theme.accent,
                                           fg_color=Theme.bg_alt,
                                           corner_radius=4, height=6)
        self.progress.pack(side='left', fill='x', expand=True, padx=(16, 0))
        self.progress.set(0)
        self.results_card = Card(self, title='Results',
                                 subtitle='Run a check to see findings here.')
        self.results_card.pack(fill='both', expand=True,
                               padx=32, pady=(0, 32))
        self.results_body = self.results_card.body()
        self._show_idle()
        self.refresh_folders()

    def refresh_folders(self):
        folders = self.app.get_watched_folders()
        if folders:
            self.folder_menu.configure(values=folders)
            current = self.folder_var.get()
            if current not in folders:
                self.folder_var.set(folders[0])
        else:
            self.folder_menu.configure(values=['(no folders)'])
            self.folder_var.set('(no folders)')

    def _show_idle(self):
        for w in self.results_body.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            self.results_body,
            text='Results will appear here after you run a check.',
            font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
            text_color=Theme.text_muted, anchor='w',
        ).pack(anchor='w')

    def _run(self):
        folder = self.folder_var.get()
        if not folder or folder == '(no folders)':
            messagebox.showinfo('No folder',
                                'Add a folder first from the Folders view.')
            return
        baseline = self.app.fim.db.get_baseline(folder)
        if not baseline:
            if messagebox.askyesno(
                    'No baseline',
                    f'No baseline found for "{folder}".\nCreate one now?'):
                self.app.run_baseline([folder],
                                      on_done=lambda *_: self._do_check(folder))
            return
        self._do_check(folder)

    def _do_check(self, folder: str):
        self.check_btn.configure(state='disabled', text='Scanning…')
        self.progress.start()
        for w in self.results_body.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            self.results_body, text=f'Scanning {folder}…',
            font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
            text_color=Theme.text_muted, anchor='w',
        ).pack(anchor='w')

        def on_done(status, payload):
            self.progress.stop()
            self.progress.set(0)
            self.check_btn.configure(state='normal',
                                     text='▶  Run Integrity Check')
            for w in self.results_body.winfo_children():
                w.destroy()
            if status == 'err':
                messagebox.showerror('Scan failed', str(payload))
                self._show_idle()
                return
            self._render_results(payload)
            self.app.dashboard.refresh()
            self.app.activity.refresh()

        self.app.worker.run(self.app.fim.check_integrity, folder,
                            on_done=on_done)

    def _render_results(self, changes: Dict):
        if not changes or all(not v for v in changes.values()):
            row = ctk.CTkFrame(self.results_body, fg_color='transparent')
            row.pack(fill='x', pady=(4, 0))
            ctk.CTkLabel(
                row, text='✓',
                font=ctk.CTkFont(size=28, weight='bold'),
                text_color=Theme.success,
            ).pack(side='left', padx=(0, 12))
            inner = ctk.CTkFrame(row, fg_color='transparent')
            inner.pack(side='left', fill='x', expand=True)
            ctk.CTkLabel(
                inner, text='No changes detected',
                font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                                 size=16, weight='bold'),
                text_color=Theme.success, anchor='w',
            ).pack(anchor='w')
            ctk.CTkLabel(
                inner, text='All files match the baseline. System integrity verified.',
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
                text_color=Theme.text_muted, anchor='w',
            ).pack(anchor='w', pady=(2, 0))
            return

        total = sum(len(v) for v in changes.values())
        ctk.CTkLabel(
            self.results_body, text=f'{total} change(s) detected',
            font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                             size=16, weight='bold'),
            text_color=Theme.warning, anchor='w',
        ).pack(anchor='w', pady=(0, 12))
        for label, key, icon, _ in [
            ('Modified', 'modified', '↻', 'warning'),
            ('Added',    'added',    '+', 'accent'),
            ('Deleted',  'deleted',  '✕', 'neutral'),
        ]:
            evs = changes.get(key) or []
            if not evs:
                continue
            sec = ctk.CTkFrame(self.results_body, fg_color='transparent')
            sec.pack(fill='x', pady=(8, 4))
            header = ctk.CTkFrame(sec, fg_color='transparent')
            header.pack(fill='x')
            ctk.CTkLabel(
                header, text=f'{icon}  {label} ({len(evs)})',
                font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                                 size=13, weight='bold'),
                text_color=Theme.text, anchor='w',
            ).pack(anchor='w')
            for ev in evs[:25]:
                self._render_event_row(sec, ev)
            if len(evs) > 25:
                ctk.CTkLabel(
                    sec, text=f'… and {len(evs) - 25} more',
                    font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=11),
                    text_color=Theme.text_subtle, anchor='w',
                ).pack(anchor='w', pady=(4, 0))

    def _render_event_row(self, parent, event: ChangeEvent):
        row = ctk.CTkFrame(parent, fg_color=Theme.bg_alt, corner_radius=10)
        row.pack(fill='x', pady=4)
        top = ctk.CTkFrame(row, fg_color='transparent')
        top.pack(fill='x', padx=12, pady=8)
        Pill(top, event.severity.upper(),
             SEV_KIND.get(event.severity, 'neutral')
             ).pack(side='left', padx=(0, 10))
        ctk.CTkLabel(
            top, text=event.file_path,
            font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                             size=12, weight='bold'),
            text_color=Theme.text, anchor='w',
        ).pack(side='left', fill='x', expand=True)

        details = event.details or {}
        chips = []
        if details.get('honeypot'):
            chips.append(('🍯 honeypot', 'critical'))
        if details.get('ransomware_indicator'):
            chips.append(('🚨 ransomware', 'critical'))
        if details.get('ransomware_extension'):
            chips.append((f"ext {details['ransomware_extension']}", 'critical'))
        if details.get('entropy_alert'):
            chips.append((f"entropy {details.get('entropy')}", 'warning'))
        if details.get('yara_matches'):
            chips.append((f"yara: {', '.join(details['yara_matches'])}",
                          'critical'))
        if details.get('signature_alert'):
            chips.append((f"sig {details['signature_alert']}", 'warning'))
        if details.get('process'):
            p = details['process']
            chips.append((f"by {p.get('name')}", 'neutral'))
        if chips:
            chip_row = ctk.CTkFrame(row, fg_color='transparent')
            chip_row.pack(fill='x', padx=12, pady=(0, 8))
            for text, kind in chips:
                Pill(chip_row, text, kind).pack(side='left', padx=(0, 6))


# ============================================================================
# Live Monitor — continuous scanning
# ============================================================================

LEVEL_COLOR = {
    'critical': 'critical',
    'high':     'warning',
    'medium':   'accent',
    'low':      'text_muted',
    'warn':     'warning',
    'error':    'critical',
    'ok':       'success',
    'info':     'text_muted',
}


class MonitorView(BaseView):
    MAX_LINES = 600

    def __init__(self, parent, app: 'FIMApp'):
        super().__init__(parent,
                         'Live Monitor',
                         'Continuously rescan watched folders and stream events.')
        self.app = app
        self._build()
        self.app.monitor.on_event = self._post_event
        self.app.monitor.on_status = self._post_status
        self.app.monitor.on_changes = self._post_changes
        self._event_queue: queue.Queue = queue.Queue()
        self._line_count = 0
        self._poll_queue()

    def _build(self):
        controls = Card(self, title='Controls',
                        subtitle='Start/stop the background monitor.')
        controls.pack(fill='x', padx=32, pady=(0, 16))
        b = controls.body()
        row = ctk.CTkFrame(b, fg_color='transparent')
        row.pack(fill='x')
        ctk.CTkLabel(
            row, text='Interval (s):',
            font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
            text_color=Theme.text_muted,
        ).pack(side='left', padx=(0, 8))
        default_int = self.app.fim.config.get('monitoring.scan_interval', 60)
        self.interval_var = tk.StringVar(value=str(default_int))
        ctk.CTkEntry(
            row, textvariable=self.interval_var, width=70,
            fg_color=Theme.bg_alt, text_color=Theme.text,
            border_color=Theme.border, corner_radius=8, height=32,
        ).pack(side='left', padx=(0, 16))
        self.start_btn = PrimaryButton(row, '▶  Start Monitor', self._start)
        self.start_btn.pack(side='left', padx=(0, 8))
        self.stop_btn = DangerButton(row, '■  Stop', self._stop)
        self.stop_btn.pack(side='left')
        self.stop_btn.configure(state='disabled')
        self.status_pill = Pill(row, 'IDLE', 'neutral')
        self.status_pill.pack(side='right')

        self.status_label = ctk.CTkLabel(
            b, text='Not running — pick an interval and press Start.',
            font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
            text_color=Theme.text_muted, anchor='w',
        )
        self.status_label.pack(anchor='w', pady=(10, 0))

        log_card = Card(self, title='Live log',
                        subtitle='Newest events appear at the bottom.')
        log_card.pack(fill='both', expand=True, padx=32, pady=(0, 32))
        b = log_card.body()
        self.log_text = ctk.CTkTextbox(
            b, fg_color=Theme.bg_alt, text_color=Theme.text,
            border_color=Theme.border, border_width=1,
            corner_radius=8, height=320,
            font=ctk.CTkFont(family=Theme.MONO_FAMILY, size=12),
        )
        self.log_text.pack(fill='both', expand=True)
        for level, color_attr in LEVEL_COLOR.items():
            self.log_text.tag_config(level,
                                     foreground=getattr(Theme, color_attr))
        self.log_text.configure(state='disabled')

        act = ctk.CTkFrame(b, fg_color='transparent')
        act.pack(fill='x', pady=(10, 0))
        SecondaryButton(act, 'Clear log', self._clear).pack(side='right')

    # --- control handlers ----------------------------------------------------
    def _start(self):
        folders = self.app.get_watched_folders()
        if not folders:
            messagebox.showinfo('No folders',
                                'Add a watched folder before starting the monitor.')
            return
        try:
            interval = max(5, int(self.interval_var.get().strip()))
        except ValueError:
            messagebox.showerror('Bad interval',
                                 'Interval must be a positive integer (seconds).')
            return
        if not self.app.monitor.start(folders, interval):
            return
        self.start_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')

    def _stop(self):
        self.app.monitor.stop()
        self.stop_btn.configure(state='disabled')

    def _clear(self):
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', tk.END)
        self.log_text.configure(state='disabled')
        self._line_count = 0

    # --- callbacks from monitor thread --------------------------------------
    def _post_event(self, level: str, message: str):
        self._event_queue.put(('event', level, message))

    def _post_status(self, running: bool, detail: str):
        self._event_queue.put(('status', running, detail))

    def _post_changes(self):
        self._event_queue.put(('changes', None, None))

    # --- queue drain (on Tk main thread) ------------------------------------
    def _poll_queue(self):
        try:
            while True:
                kind, a, b = self._event_queue.get_nowait()
                if kind == 'event':
                    self._append_line(a, b)
                elif kind == 'status':
                    self._apply_status(a, b)
                elif kind == 'changes':
                    self.app.dashboard.refresh()
                    self.app.activity.refresh()
        except queue.Empty:
            pass
        self.after(180, self._poll_queue)

    def _append_line(self, level: str, text: str):
        self.log_text.configure(state='normal')
        ts = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f'[{ts}] {text}\n', (level,))
        self._line_count += 1
        if self._line_count > self.MAX_LINES:
            # Trim oldest 100 lines in one shot — cheap, keeps memory bounded.
            self.log_text.delete('1.0', '101.0')
            self._line_count -= 100
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')

    def _apply_status(self, running: bool, detail: str):
        if running:
            self.status_pill.configure(
                text='● RUNNING', fg_color=Theme.success_soft,
                text_color=Theme.success)
            self.status_label.configure(text=detail, text_color=Theme.success)
            self.start_btn.configure(state='disabled')
            self.stop_btn.configure(state='normal')
        else:
            self.status_pill.configure(
                text='IDLE', fg_color=Theme.bg_alt,
                text_color=Theme.text_muted)
            self.status_label.configure(text=detail or 'Not running.',
                                        text_color=Theme.text_muted)
            self.start_btn.configure(state='normal')
            self.stop_btn.configure(state='disabled')
        self.app.sidebar.set_monitor_status(running, detail)
        self.app.dashboard.refresh()


# ============================================================================
# Activity — full history + stats summary
# ============================================================================

class ActivityView(BaseView):
    RANGES = [('1h', 1), ('24h', 24), ('7d', 168), ('30d', 720)]

    def __init__(self, parent, app: 'FIMApp'):
        super().__init__(parent,
                         'Activity',
                         'Change history with severity and event-type breakdowns.')
        self.app = app
        self.hours = 24
        self._build()

    def _build(self):
        bar = ctk.CTkFrame(self, fg_color='transparent')
        bar.pack(fill='x', padx=32, pady=(0, 16))
        ctk.CTkLabel(
            bar, text='Time range:',
            font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
            text_color=Theme.text_muted,
        ).pack(side='left', padx=(0, 8))
        self.range_var = tk.StringVar(value='24h')
        for label, hours in self.RANGES:
            ctk.CTkRadioButton(
                bar, text=label, value=label, variable=self.range_var,
                command=lambda h=hours: self._set_hours(h),
                fg_color=Theme.accent,
                hover_color=Theme.accent_hover,
                text_color=Theme.text,
                border_color=Theme.border_strong,
                border_width_unchecked=1, border_width_checked=4,
                radiobutton_width=16, radiobutton_height=16,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
            ).pack(side='left', padx=4)
        SecondaryButton(bar, 'Refresh', self.refresh).pack(side='right')

        self.stats_row = ctk.CTkFrame(self, fg_color='transparent')
        self.stats_row.pack(fill='x', padx=32, pady=(0, 16))
        self.stat_labels: Dict[str, ctk.CTkLabel] = {}
        for i, (key, label) in enumerate([
            ('total',    'Total changes'),
            ('modified', 'Modified'),
            ('added',    'Added'),
            ('deleted',  'Deleted'),
        ]):
            card = Card(self.stats_row)
            card.grid(row=0, column=i, sticky='nsew',
                      padx=(0, 12 if i < 3 else 0))
            self.stats_row.grid_columnconfigure(i, weight=1)
            b = card.body()
            ctk.CTkLabel(
                b, text=label,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
                text_color=Theme.text_muted, anchor='w',
            ).pack(anchor='w')
            val = ctk.CTkLabel(
                b, text='0',
                font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                                 size=28, weight='bold'),
                text_color=Theme.text, anchor='w',
            )
            val.pack(anchor='w', pady=(4, 0))
            self.stat_labels[key] = val

        self.sev_card = Card(self, title='By severity',
                             subtitle='Distribution of detected events.')
        self.sev_card.pack(fill='x', padx=32, pady=(0, 16))
        self.sev_body = self.sev_card.body()

        self.list_card = Card(self, title='Events',
                              subtitle='Most recent first; capped at 200 rows.')
        self.list_card.pack(fill='both', expand=True, padx=32, pady=(0, 32))
        self.list_body = self.list_card.body()

        self.refresh()

    def _set_hours(self, h: int):
        self.hours = h
        self.refresh()

    def refresh(self):
        history = self.app.fim.db.get_change_history(hours=self.hours)

        by_type: Dict[str, int] = defaultdict(int)
        by_sev: Dict[str, int] = defaultdict(int)
        for ev in history:
            by_type[ev['event_type']] += 1
            by_sev[ev['severity']] += 1

        self.stat_labels['total'].configure(text=str(len(history)))
        self.stat_labels['modified'].configure(text=str(by_type['modified']))
        self.stat_labels['added'].configure(text=str(by_type['added']))
        self.stat_labels['deleted'].configure(text=str(by_type['deleted']))

        for w in self.sev_body.winfo_children():
            w.destroy()
        total_for_bars = max((max(by_sev.values()) if by_sev else 0), 1)
        for sev in ('critical', 'high', 'medium', 'low'):
            render_severity_bar(self.sev_body, sev,
                                by_sev.get(sev, 0), total_for_bars)

        for w in self.list_body.winfo_children():
            w.destroy()
        if not history:
            ctk.CTkLabel(
                self.list_body, text='No events in the selected range.',
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
                text_color=Theme.text_muted, anchor='w',
            ).pack(anchor='w')
            return
        for ev in history[:200]:
            render_activity_row(self.list_body, ev)
        if len(history) > 200:
            ctk.CTkLabel(
                self.list_body, text=f'… and {len(history) - 200} more',
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=11),
                text_color=Theme.text_subtle, anchor='w',
            ).pack(anchor='w', pady=(8, 0))


# ============================================================================
# Logs — tail of structured JSON log streams
# ============================================================================

class LogsView(BaseView):
    LOG_FILES = [
        ('events', 'Events',       'events.json'),
        ('alerts', 'Alerts',       'alerts.json'),
        ('system', 'System',       'system.json'),
        ('perf',   'Performance',  'performance.json'),
    ]
    MAX_LINES = 500

    def __init__(self, parent, app: 'FIMApp'):
        super().__init__(parent, 'Logs',
                         'Structured JSON log streams from the FIM core.')
        self.app = app
        self.current = 'events'
        self._build()

    def _build(self):
        bar = ctk.CTkFrame(self, fg_color='transparent')
        bar.pack(fill='x', padx=32, pady=(0, 12))
        self.tab_btns: Dict[str, ctk.CTkButton] = {}
        for key, label, _ in self.LOG_FILES:
            btn = ctk.CTkButton(
                bar, text=label, width=120,
                command=lambda k=key: self._switch(k),
                fg_color='transparent', hover_color=Theme.card_hover,
                text_color=Theme.text_muted,
                corner_radius=8, height=32,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
            )
            btn.pack(side='left', padx=(0, 6))
            self.tab_btns[key] = btn
        SecondaryButton(bar, 'Refresh', self.refresh).pack(side='right')

        card = Card(self, title='Tail',
                    subtitle=f'Newest {self.MAX_LINES} entries.')
        card.pack(fill='both', expand=True, padx=32, pady=(0, 32))
        body = card.body()
        self.log_text = ctk.CTkTextbox(
            body, fg_color=Theme.bg_alt, text_color=Theme.text,
            border_color=Theme.border, border_width=1,
            corner_radius=8, height=380,
            font=ctk.CTkFont(family=Theme.MONO_FAMILY, size=12),
        )
        self.log_text.pack(fill='both', expand=True)
        self.log_text.tag_config('critical', foreground=Theme.critical)
        self.log_text.tag_config('high', foreground=Theme.warning)
        self.log_text.tag_config('medium', foreground=Theme.accent)
        self.log_text.tag_config('low', foreground=Theme.text_muted)
        self.log_text.tag_config('info', foreground=Theme.text_muted)
        self.log_text.tag_config('warning', foreground=Theme.warning)
        self.log_text.tag_config('error', foreground=Theme.critical)
        self.log_text.tag_config('header', foreground=Theme.text_subtle)
        self.log_text.configure(state='disabled')
        self._switch('events')

    def _switch(self, key: str):
        self.current = key
        for k, btn in self.tab_btns.items():
            if k == key:
                btn.configure(fg_color=Theme.accent_soft,
                              text_color=Theme.accent)
            else:
                btn.configure(fg_color='transparent',
                              text_color=Theme.text_muted)
        self.refresh()

    def refresh(self):
        filename = next(f for k, _, f in self.LOG_FILES if k == self.current)
        log_dir = self.app.fim.config.get('logging.log_directory', 'logs')
        path = Path(log_dir) / filename

        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', tk.END)
        if not path.exists():
            self.log_text.insert(tk.END,
                                 '(no log entries yet — file does not exist)')
            self.log_text.configure(state='disabled')
            return
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except OSError as e:
            self.log_text.insert(tk.END, f'Error reading log: {e}')
            self.log_text.configure(state='disabled')
            return

        if len(lines) > self.MAX_LINES:
            self.log_text.insert(tk.END,
                                 f'... ({len(lines) - self.MAX_LINES} '
                                 f'earlier lines hidden)\n\n', ('header',))
            lines = lines[-self.MAX_LINES:]

        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue
            self._render_entry(raw)
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')

    def _render_entry(self, raw: str):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            self.log_text.insert(tk.END, raw + '\n')
            return
        ts = obj.get('timestamp', '') or obj.get('alert_timestamp', '')
        ts = ts[:19].replace('T', ' ') if ts else '?'
        if self.current == 'events':
            sev = (obj.get('severity') or 'low').lower()
            t = (obj.get('event_type') or '').upper()
            fp = obj.get('file_path', '')
            line = f'[{ts}] [{sev.upper():>8}] {t:>8}  {fp}\n'
            self.log_text.insert(tk.END, line, (sev,))
        elif self.current == 'alerts':
            sev = (obj.get('severity') or 'critical').lower()
            msg = (obj.get('message') or obj.get('alert_type') or
                   obj.get('event_type') or 'alert')
            fp = obj.get('file_path', '')
            tail = f' — {fp}' if fp else ''
            line = f'[{ts}] [{sev.upper()}] {msg}{tail}\n'
            self.log_text.insert(tk.END, line, (sev,))
        elif self.current == 'system':
            lv = (obj.get('level') or 'info').lower()
            msg = obj.get('message', '')
            line = f'[{ts}] [{lv.upper():>7}] {msg}\n'
            tag = 'error' if lv == 'error' else \
                  'warning' if lv == 'warning' else 'info'
            self.log_text.insert(tk.END, line, (tag,))
        else:  # perf
            op = obj.get('operation', '')
            dur = obj.get('duration_seconds', 0)
            files = obj.get('files_scanned', '?')
            cpu = obj.get('cpu_percent')
            mem = obj.get('memory_mb')
            extra = ''
            if cpu is not None or mem is not None:
                extra = f' [cpu {cpu}% mem {mem:.1f}MB]' if (
                    cpu is not None and mem is not None
                ) else ''
            line = f'[{ts}] {op:<20} {dur:>7.2f}s  files={files}{extra}\n'
            self.log_text.insert(tk.END, line, ('info',))


# ============================================================================
# Security — feature toggles, status summary, honeypot management
# ============================================================================

class SecurityView(BaseView):
    FEATURES = [
        ('enable_entropy_analysis',
         'Entropy analysis',
         'Detects encrypted or compressed content via Shannon entropy.'),
        ('enable_yara_scanning',
         'YARA scanning',
         'Match files against your custom YARA rules in ./yara_rules.'),
        ('enable_signature_verification',
         'Digital signature verification',
         'Verify Authenticode signatures on Windows binaries.'),
        ('enable_ransomware_detection',
         'Ransomware detection',
         'Score bulk-change patterns and ransomware-associated extensions.'),
        ('enable_honeypot',
         'Honeypot tracking',
         'Any change to a designated honeypot raises a critical alert.'),
        ('enable_process_attribution',
         'Process attribution',
         'Identify the process holding an open handle on changed files.'),
    ]

    SECURITY_ATTR = {
        'enable_entropy_analysis':       'enable_entropy',
        'enable_yara_scanning':          'enable_yara',
        'enable_signature_verification': 'enable_signature',
        'enable_ransomware_detection':   'enable_ransomware',
        'enable_honeypot':               'enable_honeypot',
        'enable_process_attribution':    'enable_process_attr',
    }

    def __init__(self, parent, app: 'FIMApp'):
        super().__init__(parent,
                         'Security',
                         'Detection features, threat indicators, and honeypots.')
        self.app = app
        self.switch_vars: Dict[str, tk.BooleanVar] = {}
        self._build()

    def _build(self):
        self.status_card = Card(self, title='Status summary',
                                subtitle='Enabled detection capabilities and counters.')
        self.status_card.pack(fill='x', padx=32, pady=(0, 16))
        self.status_body = self.status_card.body()

        toggles = Card(self, title='Detection features',
                       subtitle='Toggle individual security modules.')
        toggles.pack(fill='x', padx=32, pady=(0, 16))
        b = toggles.body()
        for key, name, desc in self.FEATURES:
            row = ctk.CTkFrame(b, fg_color='transparent')
            row.pack(fill='x', pady=10)
            wrap = ctk.CTkFrame(row, fg_color='transparent')
            wrap.pack(side='left', fill='x', expand=True)
            ctk.CTkLabel(
                wrap, text=name,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                                 size=13, weight='bold'),
                text_color=Theme.text, anchor='w',
            ).pack(anchor='w')
            ctk.CTkLabel(
                wrap, text=desc,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=11),
                text_color=Theme.text_muted, anchor='w',
            ).pack(anchor='w', pady=(2, 0))
            var = tk.BooleanVar(value=bool(
                self.app.fim.config.get(f'security.{key}', False)))
            self.switch_vars[key] = var
            ctk.CTkSwitch(
                row, text='', variable=var,
                command=lambda k=key, v=var: self._toggle(k, v),
                progress_color=Theme.accent,
                button_color=Theme.switch_knob,
                button_hover_color=Theme.switch_knob,
                fg_color=Theme.switch_track,
                width=72, height=30,
                switch_width=72, switch_height=30,
                corner_radius=18,
                border_color=Theme.switch_border, border_width=2,
            ).pack(side='right', padx=(16, 0))

        hp = Card(self, title='Honeypots',
                  subtitle='Deploy and track decoy files.')
        hp.pack(fill='x', padx=32, pady=(0, 32))
        b = hp.body()
        action_row = ctk.CTkFrame(b, fg_color='transparent')
        action_row.pack(fill='x')
        PrimaryButton(action_row, 'Deploy in folder…', self._deploy
                      ).pack(side='left', padx=(0, 8))
        SecondaryButton(action_row, 'Register existing file…',
                        self._register_existing
                        ).pack(side='left', padx=(0, 8))
        SecondaryButton(action_row, 'Refresh list', self.refresh
                        ).pack(side='left')
        self.hp_list = ctk.CTkFrame(b, fg_color='transparent')
        self.hp_list.pack(fill='x', pady=(14, 0))
        self.refresh()

    # --- summary -------------------------------------------------------------
    def _render_status(self):
        for w in self.status_body.winfo_children():
            w.destroy()
        sec = self.app.fim.security
        left = ctk.CTkFrame(self.status_body, fg_color='transparent')
        left.pack(side='left', fill='both', expand=True)
        right = ctk.CTkFrame(self.status_body, fg_color='transparent')
        right.pack(side='right', fill='y')

        items = [
            ('Entropy analysis',                 sec.enable_entropy),
            ('YARA scanning',                    sec.enable_yara),
            ('Digital signature verification',   sec.enable_signature),
            ('Ransomware detection heuristics',  sec.enable_ransomware),
            ('Honeypot tracking',                sec.enable_honeypot),
            ('Process attribution',              sec.enable_process_attr),
        ]
        for label, on in items:
            row = ctk.CTkFrame(left, fg_color='transparent')
            row.pack(fill='x', pady=2)
            ctk.CTkLabel(
                row, text='✓' if on else '✗',
                font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                                 size=14, weight='bold'),
                text_color=Theme.success if on else Theme.text_subtle,
                width=18,
            ).pack(side='left')
            ctk.CTkLabel(
                row, text=label,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
                text_color=Theme.text if on else Theme.text_muted,
                anchor='w',
            ).pack(side='left', padx=(8, 0))

        yara_loaded = bool(getattr(sec, 'yara_rules', None))
        registered = len(sec.honeypot_files)
        threshold = sec.ransomware_score_threshold
        for label, value, kind in [
            ('YARA rules', 'loaded' if yara_loaded else 'none',
             'success' if yara_loaded else 'neutral'),
            ('Honeypots',  str(registered),
             'success' if registered else 'neutral'),
            ('Ransomware score', str(threshold), 'accent'),
        ]:
            row = ctk.CTkFrame(right, fg_color='transparent')
            row.pack(fill='x', pady=2, padx=(20, 0))
            ctk.CTkLabel(
                row, text=label,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=11),
                text_color=Theme.text_muted, anchor='w', width=120,
            ).pack(side='left')
            Pill(row, value, kind).pack(side='right')

    # --- toggles -------------------------------------------------------------
    def _toggle(self, key: str, var: tk.BooleanVar):
        value = bool(var.get())
        self.app.fim.config.set(f'security.{key}', value)
        attr = self.SECURITY_ATTR.get(key)
        if attr is not None:
            setattr(self.app.fim.security, attr, value)
        self._render_status()

    # --- honeypots -----------------------------------------------------------
    def _deploy(self):
        folder = filedialog.askdirectory(title='Deploy honeypots into folder')
        if not folder:
            return
        deployed = self.app.fim.security.deploy_honeypots(folder)
        if deployed:
            messagebox.showinfo(
                'Honeypots deployed',
                f'Created {len(deployed)} decoy file(s) in:\n{folder}')
        else:
            messagebox.showinfo(
                'Nothing to deploy',
                'All standard honeypot names already exist in that folder.')
        self.refresh()
        self.app.dashboard.refresh()

    def _register_existing(self):
        path = filedialog.askopenfilename(
            title='Pick file to register as honeypot')
        if not path:
            return
        existing = list(self.app.fim.config.get(
            'security.honeypot_files', []) or [])
        absp = str(Path(path).resolve())
        if absp not in existing:
            existing.append(absp)
            self.app.fim.config.set('security.honeypot_files', existing)
            self.app.fim.security.honeypot_files.add(
                os.path.normcase(os.path.normpath(absp)))
        self.refresh()

    def refresh(self):
        self._render_status()
        for w in self.hp_list.winfo_children():
            w.destroy()
        honeypots = list(self.app.fim.config.get(
            'security.honeypot_files', []) or [])
        if not honeypots:
            ctk.CTkLabel(
                self.hp_list,
                text='No honeypots registered yet.',
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
                text_color=Theme.text_muted, anchor='w',
            ).pack(anchor='w')
            return
        for path in honeypots:
            row = ctk.CTkFrame(self.hp_list, fg_color=Theme.bg_alt,
                               corner_radius=10)
            row.pack(fill='x', pady=4)
            inner = ctk.CTkFrame(row, fg_color='transparent')
            inner.pack(fill='x', padx=12, pady=8)
            exists = Path(path).exists()
            Pill(inner, '✓ EXISTS' if exists else '✗ MISSING',
                 'success' if exists else 'critical'
                 ).pack(side='left', padx=(0, 10))
            ctk.CTkLabel(
                inner, text=path,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
                text_color=Theme.text, anchor='w',
            ).pack(side='left', fill='x', expand=True)
            ctk.CTkButton(
                inner, text='Remove', width=80,
                command=lambda p=path: self._remove(p),
                fg_color='transparent', hover_color=Theme.critical_soft,
                text_color=Theme.critical,
                border_color=Theme.border_strong, border_width=1,
                corner_radius=8, height=28,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                                 size=11, weight='bold'),
            ).pack(side='right')

    def _remove(self, path: str):
        if not messagebox.askyesno('Remove honeypot',
                                   f'Stop tracking honeypot:\n{path}?'):
            return
        existing = list(self.app.fim.config.get(
            'security.honeypot_files', []) or [])
        existing = [p for p in existing if p != path]
        self.app.fim.config.set('security.honeypot_files', existing)
        self.app.fim.security.honeypot_files.discard(
            os.path.normcase(os.path.normpath(path)))
        self.refresh()


# ============================================================================
# Settings
# ============================================================================

class SettingsView(BaseView):
    FIELDS = [
        ('monitoring.scan_interval',           'Scan interval (seconds)',  60),
        ('monitoring.worker_threads',          'Worker threads',            4),
        ('monitoring.max_file_size_mb',        'Max file size (MB)',      500),
        ('performance.cache_ttl_seconds',      'Hash cache TTL (sec)',    300),
        ('alerting.alert_threshold',           'Alert threshold (changes/scan)', 10),
        ('security.entropy_sample_bytes',      'Entropy sample bytes',    1048576),
        ('security.ransomware_score_threshold','Ransomware score threshold', 50),
        ('security.ransomware_bulk_threshold', 'Ransomware bulk threshold', 10),
    ]

    def __init__(self, parent, app: 'FIMApp'):
        super().__init__(parent,
                         'Settings',
                         'Tune scan throughput, limits, and detection thresholds.')
        self.app = app
        self._build()

    def _build(self):
        card = Card(self, title='Monitoring & detection',
                    subtitle='Changes apply on the next scan.')
        card.pack(fill='x', padx=32, pady=(0, 16))
        b = card.body()
        self.vars: Dict[str, tk.StringVar] = {}
        for key, label, default in self.FIELDS:
            row = ctk.CTkFrame(b, fg_color='transparent')
            row.pack(fill='x', pady=6)
            ctk.CTkLabel(
                row, text=label,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY, size=12),
                text_color=Theme.text, anchor='w', width=260,
            ).pack(side='left')
            var = tk.StringVar(value=str(self.app.fim.config.get(key, default)))
            self.vars[key] = var
            ctk.CTkEntry(
                row, textvariable=var, width=130,
                fg_color=Theme.bg_alt, text_color=Theme.text,
                border_color=Theme.border, corner_radius=8, height=32,
            ).pack(side='left')

        info = Card(self, title='Paths',
                    subtitle='Where FIM stores its state.')
        info.pack(fill='x', padx=32, pady=(0, 16))
        ib = info.body()
        for label, value in [
            ('Config file', str(self.app.fim.config.config_file)),
            ('Database',    self.app.fim.db.db_path),
            ('Log directory', self.app.fim.config.get(
                'logging.log_directory', 'logs')),
        ]:
            row = ctk.CTkFrame(ib, fg_color='transparent')
            row.pack(fill='x', pady=4)
            ctk.CTkLabel(
                row, text=label,
                font=ctk.CTkFont(family=Theme.FONT_FAMILY,
                                 size=12, weight='bold'),
                text_color=Theme.text_muted, anchor='w', width=140,
            ).pack(side='left')
            ctk.CTkLabel(
                row, text=value,
                font=ctk.CTkFont(family=Theme.MONO_FAMILY, size=12),
                text_color=Theme.text, anchor='w',
            ).pack(side='left', fill='x', expand=True)

        action_row = ctk.CTkFrame(self, fg_color='transparent')
        action_row.pack(fill='x', padx=32, pady=(0, 32))
        PrimaryButton(action_row, 'Save settings', self._save
                      ).pack(side='left')

    def _save(self):
        updates: Dict[str, object] = {}
        for key, var in self.vars.items():
            raw = var.get().strip()
            try:
                value: object = int(raw)
            except ValueError:
                try:
                    value = float(raw)
                except ValueError:
                    value = raw
            updates[key] = value
        self.app.fim.config.set_many(updates)
        # Apply select live properties without restart.
        self.app.fim.scanner.worker_threads = self.app.fim.config.get(
            'monitoring.worker_threads', 4)
        self.app.fim.scanner.max_file_size = self.app.fim.config.get(
            'monitoring.max_file_size_mb', 500) * 1024 * 1024
        sec = self.app.fim.security
        sec.entropy_sample_bytes = int(self.app.fim.config.get(
            'security.entropy_sample_bytes', 1048576))
        sec.ransomware_score_threshold = int(self.app.fim.config.get(
            'security.ransomware_score_threshold', 50))
        sec.ransomware_bulk_threshold = int(self.app.fim.config.get(
            'security.ransomware_bulk_threshold', 10))
        messagebox.showinfo('Saved', 'Settings updated.')


# ============================================================================
# Application
# ============================================================================

class FIMApp(ctk.CTk):
    WATCHED_KEY = 'watch_directories'

    def __init__(self, config_file: str = 'fim_config.json',
                 db_path: str = 'fim_database.db'):
        super().__init__()
        self.title('FIM — File Integrity Monitor')
        self.geometry('1240x800')
        self.minsize(1040, 680)

        ctk.set_appearance_mode('dark')
        ctk.set_default_color_theme('blue')
        self.configure(fg_color=Theme.bg)

        self.fim = EnterpriseFileIntegrityMonitor(
            config_file=config_file, db_path=db_path)
        self.worker = FIMWorker()
        self.monitor = MonitorRunner(self.fim)
        self.worker.poll(self)

        self._current_view = 'dashboard'
        self._build_shell()

    # --- build ---------------------------------------------------------------
    def _build_shell(self):
        self.container = ctk.CTkFrame(self, fg_color=Theme.bg,
                                      corner_radius=0)
        self.container.pack(fill='both', expand=True)

        self.sidebar = Sidebar(self.container, self.nav)
        self.sidebar.pack(side='left', fill='y')
        ctk.CTkFrame(self.container, fg_color=Theme.border,
                     width=1, corner_radius=0).pack(side='left', fill='y')
        self.content_holder = ctk.CTkFrame(self.container,
                                           fg_color=Theme.bg,
                                           corner_radius=0)
        self.content_holder.pack(side='left', fill='both', expand=True)

        self.dashboard = DashboardView(self.content_holder, self)
        self.folders = FoldersView(self.content_holder, self)
        self.scan = ScanView(self.content_holder, self)
        self.monitor_view = MonitorView(self.content_holder, self)
        self.activity = ActivityView(self.content_holder, self)
        self.logs = LogsView(self.content_holder, self)
        self.security = SecurityView(self.content_holder, self)
        self.settings = SettingsView(self.content_holder, self)

        self.views = {
            'dashboard': self.dashboard,
            'folders':   self.folders,
            'scan':      self.scan,
            'monitor':   self.monitor_view,
            'activity':  self.activity,
            'logs':      self.logs,
            'security':  self.security,
            'settings':  self.settings,
        }
        self.nav(self._current_view)

    # --- nav -----------------------------------------------------------------
    def nav(self, key: str, **kwargs):
        for v in self.views.values():
            v.pack_forget()
        self.views[key].pack(fill='both', expand=True)
        self.sidebar.select(key)
        self._current_view = key
        if key == 'scan':
            self.scan.refresh_folders()
        if key == 'activity':
            self.activity.refresh()
        if key == 'logs':
            self.logs.refresh()
        if key == 'folders' and kwargs.get('action') == 'add':
            self.after(150, self.folders.add_folder)

    # --- config / folders ----------------------------------------------------
    def get_watched_folders(self) -> List[str]:
        return list(self.fim.config.get(self.WATCHED_KEY, []) or [])

    def add_folder(self, path: str):
        folders = self.get_watched_folders()
        if path in folders:
            messagebox.showinfo('Already watching',
                                'That folder is already monitored.')
            return
        folders.append(path)
        self.fim.config.set(self.WATCHED_KEY, folders)
        self.run_baseline([path])

    def remove_folder(self, path: str):
        folders = [f for f in self.get_watched_folders() if f != path]
        self.fim.config.set(self.WATCHED_KEY, folders)
        baseline = self.fim.db.get_baseline(path)
        for fp in baseline:
            self.fim.db.delete_baseline_entry(fp)

    # --- background operations ----------------------------------------------
    def run_baseline(self, paths: List[str],
                     on_done: Optional[Callable] = None):
        def _baseline():
            for p in paths:
                files = self.fim.scan_directory(p)
                self.fim.db.save_baseline_batch(files.values(), p)
            return True

        def _after(status, payload):
            if status == 'err':
                messagebox.showerror('Baseline failed', str(payload))
            self.dashboard.refresh()
            self.folders.refresh()
            self.scan.refresh_folders()
            if on_done:
                on_done(status, payload)

        self.worker.run(_baseline, on_done=_after)

    def run_check(self, folder: str):
        self.nav('scan')
        self.scan.folder_var.set(folder)
        self.after(200, self.scan._run)

    # --- lifecycle -----------------------------------------------------------
    def on_close(self):
        try:
            if self.monitor.is_running():
                self.monitor.stop()
            self.fim.cleanup()
        finally:
            self.destroy()


def main():
    ctk.set_appearance_mode('dark')
    ctk.set_default_color_theme('blue')
    app = FIMApp()
    app.protocol('WM_DELETE_WINDOW', app.on_close)
    app.mainloop()


if __name__ == '__main__':
    main()
