import base64
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import webbrowser
import urllib.request
import urllib.error
from datetime import date, datetime, timedelta
from pathlib import Path

import customtkinter as ctk
from PIL import Image, ImageDraw, ImageTk
from tkinter import filedialog, messagebox, Canvas

try:
    from google_auth_oauthlib.flow import InstalledAppFlow
except ImportError:
    InstalledAppFlow = None

try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None


APP_NAME = "LifeVault"
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "lifevault.db"
VAULT_DIR = BASE_DIR / "vault"
TEMP_DIR = BASE_DIR / ".temp"
VAULT_DIR.mkdir(exist_ok=True)
TEMP_DIR.mkdir(exist_ok=True)

ASSET_DIR = BASE_DIR / "assets"
LOGO_FULL_PATH = ASSET_DIR / "lifevault-logo-512.png"
LOGO_SMALL_PATH = ASSET_DIR / "lifevault-favicon-48.png"
APP_ICON_PATH = ASSET_DIR / "lifevault.ico"

CATEGORIES = ["Identity", "Insurance", "Vehicle", "Education", "Financial", "Medical", "Other"]

# ---- Design tokens ---------------------------------------------------------
# The visual identity is taken straight from the LifeVault logo: deep navy
# surfaces, cyan/teal accents and clean white content areas. Everything below
# only controls appearance - no behaviour depends on these values.
BG = "#F4F7FB"                  # content background
CARD = "#FFFFFF"                # cards / surfaces
CARD_ALT = "#F8FAFC"            # inset / hover surface
TEXT = "#0F172A"                # primary text
MUTED = "#64748B"               # secondary text
PRIMARY = "#0E7490"             # brand action colour (deep teal)
PRIMARY_HOVER = "#155E75"       # action hover
PRIMARY_SOFT = "#ECFEFF"        # tinted action background
PRIMARY_TINT = "#CFFAFE"        # stronger tint (avatar / icon chips)
ACCENT = "#22D3EE"              # bright cyan used on dark surfaces
ACCENT_TEXT = "#0E7490"         # accent colour with readable contrast on white
BORDER = "#E3EAF2"              # hairline border
BORDER_STRONG = "#CBD9E6"       # inputs / controls
DANGER = "#DC2626"
DANGER_SOFT = "#FEF2F2"
SUCCESS = "#16A34A"
SUCCESS_SOFT = "#DCFCE7"
WARNING = "#D97706"
WARNING_SOFT = "#FEF3C7"
SIDEBAR = "#0B1220"             # dark navy rail
SIDEBAR_HOVER = "#15243A"
SIDEBAR_ACTIVE = "#12314A"
SIDEBAR_LINE = "#1E2E45"
SIDEBAR_TEXT = "#C7D2E0"
RADIUS = 14                     # standard card corner radius

# Type scale (Segoe UI keeps the original look; sizes are standardised here so
# every screen uses the same hierarchy).
H1 = ("Segoe UI", 26, "bold")
H2 = ("Segoe UI", 22, "bold")
H3 = ("Segoe UI", 16, "bold")
CARD_TITLE = ("Segoe UI", 13, "bold")
BODY = ("Segoe UI", 12)
BODY_MUTED = ("Segoe UI", 11)
CAPTION = ("Segoe UI", 10)
MICRO = ("Segoe UI", 9)
LABEL = ("Segoe UI", 10, "bold")


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return base64.b64encode(digest).decode(), base64.b64encode(salt).decode()


def verify_password(password, stored_hash, stored_salt):
    salt = base64.b64decode(stored_salt.encode())
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return secrets.compare_digest(base64.b64encode(digest).decode(), stored_hash)


def make_fernet_key(password, salt_b64):
    salt = base64.b64decode(salt_b64.encode())
    raw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000, dklen=32)
    return base64.urlsafe_b64encode(raw)


def encrypt_file(src, dst, key):
    if Fernet is None:
        raise RuntimeError("cryptography is not installed.")
    data = Path(src).read_bytes()
    Path(dst).write_bytes(Fernet(key).encrypt(data))


def decrypt_file(src, dst, key):
    if Fernet is None:
        raise RuntimeError("cryptography is not installed.")
    data = Path(src).read_bytes()
    Path(dst).write_bytes(Fernet(key).decrypt(data))


def open_path(path):
    path = str(Path(path).resolve())
    if sys.platform.startswith("win"):
        os.startfile(path)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.create()

    def create(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            created_at TEXT NOT NULL,
            vault_key_password TEXT,
            recovery_hash TEXT,
            recovery_salt TEXT,
            vault_key_recovery TEXT
        );

        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            original_name TEXT NOT NULL,
            expiry_date TEXT,
            is_emergency INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            relation TEXT,
            is_emergency INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS profile (
            user_id INTEGER PRIMARY KEY,
            full_name TEXT,
            blood_group TEXT,
            allergies TEXT,
            medical_notes TEXT,
            vehicle_number TEXT,
            insurance_info TEXT,
            emergency_instructions TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)
        self._ensure_column("users", "vault_key_password", "TEXT")
        self._ensure_column("users", "recovery_hash", "TEXT")
        self._ensure_column("users", "recovery_salt", "TEXT")
        self._ensure_column("users", "vault_key_recovery", "TEXT")
        self._ensure_column("profile", "full_name", "TEXT")
        self._ensure_column("profile", "insurance_info", "TEXT")
        self.conn.commit()

    def _ensure_column(self, table, column, data_type):
        columns = {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {data_type}")

    def execute(self, sql, params=(), fetch=False, one=False):
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        if fetch:
            rows = cur.fetchall()
            if one:
                return rows[0] if rows else None
            return rows
        return cur.lastrowid

    def close(self):
        self.conn.close()


class LifeVault(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.user = None
        self.fernet_key = None
        self.is_locked = False
        self.current_page = None
        self._sidebar_visible = True
        self._sidebar_manually_collapsed = False
        self._mobile_menu_open = False
        self._resize_pending = False
        self.last_activity = time.time()
        self.temp_files = []
        self._logo_images = {}
        self.title("LifeVault — Smart Personal Document and Emergency Management System")
        self.geometry("%dx%d" % self.clamp_geometry(1360, 820))
        self.minsize(700, 560)
        self.apply_window_icon()
        self.protocol("WM_DELETE_WINDOW", self.shutdown)
        self.bind_all("<Key>", self.touch)
        self.bind_all("<Button>", self.touch)
        self.bind("<Configure>", self._on_window_configure, add="+")
        self.show_login()
        self.after(60_000, self.auto_lock_check)

    def touch(self, _event=None):
        self.last_activity = time.time()

    def auto_lock_check(self):
        # 15-minute inactivity lock after login.
        if self.user and not self.is_locked and time.time() - self.last_activity > 900:
            self.lock_vault(show_message=True)
        self.after(60_000, self.auto_lock_check)

    def clear(self):
        for w in self.winfo_children():
            w.destroy()

    def shutdown(self):
        for p in self.temp_files:
            try:
                Path(p).unlink(missing_ok=True)
            except Exception:
                pass
        self.db.close()
        self.destroy()

    # ---------------- AUTH ----------------

    def apply_window_icon(self):
        """Taskbar / Alt-Tab icon built from the exported logo assets."""
        try:
            if APP_ICON_PATH.exists():
                self.iconbitmap(str(APP_ICON_PATH))
                return
            if LOGO_FULL_PATH.exists():
                with Image.open(LOGO_FULL_PATH) as source:
                    photo = ImageTk.PhotoImage(image=source.convert("RGBA"))
                self.iconphoto(True, photo)
                self._logo_images[("window-icon",)] = photo
        except Exception:
            pass

    def logo_image(self, size):
        """Cached CTkImage of the mark. Small sizes use the simplified favicon."""
        key = ("logo", int(size))
        cached = self._logo_images.get(key)
        if cached is not None:
            return cached
        source = LOGO_SMALL_PATH if int(size) <= 48 else LOGO_FULL_PATH
        try:
            if not source.exists():
                return None
            with Image.open(source) as opened:
                image = opened.convert("RGBA")
            photo = ctk.CTkImage(light_image=image, dark_image=image,
                                 size=(int(size), int(size)))
            self._logo_images[key] = photo
            return photo
        except Exception:
            return None

    def brand_logo(self, parent, size=72, dark=True):
        """LifeVault mark, rendered from assets/ (falls back to the drawn version)."""
        image = self.logo_image(size)
        if image is not None:
            return ctk.CTkLabel(parent, image=image, text="", fg_color="transparent")
        return self.brand_logo_fallback(parent, size, dark)

    def brand_logo_fallback(self, parent, size=72, dark=True):
        frame = ctk.CTkFrame(parent, width=size, height=size,
                             fg_color="#123554", corner_radius=20,
                             border_width=1, border_color="#1D6B91")
        frame.pack_propagate(False)
        canvas = Canvas(frame, width=size, height=size, bg="#123554", highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        x = size / 2
        center_y = size * .49
        canvas.create_oval(size*.13, size*.13, size*.87, size*.87,
                           outline="#155E75", width=max(1, size//36))
        canvas.create_polygon(
            x, size*.16, size*.76, size*.25, size*.72, size*.61,
            x, size*.84, size*.28, size*.61, size*.24, size*.25,
            fill="#123452", outline="#67E8F9", width=max(2, size//28),
            joinstyle="round"
        )
        vault_left, vault_top = size*.37, size*.36
        vault_right, vault_bottom = size*.63, size*.62
        canvas.create_rectangle(vault_left, vault_top, vault_right, vault_bottom,
                                fill="#0B1B31", outline="#BAF3FC", width=max(1, size//36))
        canvas.create_oval(size*.43, size*.42, size*.57, size*.56,
                           fill="#0E7490", outline="#A5F3FC", width=max(1, size//40))
        canvas.create_oval(size*.48, size*.47, size*.52, size*.51,
                           fill="#E0FBFF", outline="")
        canvas.create_line(size*.50, size*.43, size*.50, size*.39,
                           fill="#A5F3FC", width=max(1, size//40))
        canvas.create_line(size*.56, size*.49, size*.60, size*.49,
                           fill="#A5F3FC", width=max(1, size//40))
        return frame

    def draw_auth_backdrop(self, canvas, width, height):
        if width < 2 or height < 2:
            return
        canvas.delete("auth_art")
        top = (11, 18, 32)
        bottom = (15, 46, 72)
        bands = 36
        for index in range(bands):
            ratio = index / max(1, bands - 1)
            color = "#" + "".join(
                f"{round(top[channel] + (bottom[channel] - top[channel]) * ratio):02x}"
                for channel in range(3)
            )
            y0 = height * index / bands
            y1 = height * (index + 1) / bands + 1
            canvas.create_rectangle(0, y0, width, y1, fill=color, outline=color, tags="auth_art")
        canvas.create_polygon(
            width*.56, 0, width, 0, width, height*.70, width*.84, height*.59,
            fill="#102A43", outline="", tags="auth_art"
        )
        canvas.create_line(width*.58, 0, width*.98, height*.44, fill="#164E63",
                           width=2, tags="auth_art")
        canvas.create_line(width*.98, height*.44, width*.64, height,
                           fill="#155E75", width=2, tags="auth_art")
        canvas.create_line(width*.72, 0, width, height*.30,
                           fill="#123B57", width=1, tags="auth_art")

    def auth_brand_panel(self, parent, heading="LifeVault", subtitle=None):
        # The panel is a flat deep navy: decorative layers behind the content
        # would be painted over by the transparent layout frames, so the
        # visual interest comes from the logo, accent rule and chips instead.
        content = ctk.CTkFrame(parent, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=36, pady=32)
        # Equal spacers keep the brand block vertically centred on tall
        # screens while collapsing safely on short ones.
        ctk.CTkFrame(content, fg_color="transparent",
                     height=1).pack(fill="both", expand=True)
        body = ctk.CTkFrame(content, fg_color="transparent")
        body.pack(fill="x")
        # The logo itself is final - it is only positioned, never restyled.
        self.brand_logo(body, 66).pack(anchor="w", pady=(0, 14))
        brand_name = ctk.CTkFrame(body, fg_color="transparent")
        brand_name.pack(anchor="w", pady=(0, 7))
        ctk.CTkLabel(brand_name, text="Life", text_color="#FFFFFF",
                     font=("Segoe UI", 36, "bold")).pack(side="left")
        ctk.CTkLabel(brand_name, text="Vault", text_color=ACCENT_TEXT,
                     font=("Segoe UI", 36, "bold")).pack(side="left")
        ctk.CTkLabel(
            body, text=subtitle or "Smart Personal Document and\nEmergency Management System",
            text_color="#A5D8E8", font=("Segoe UI", 13),
            justify="left", wraplength=320
        ).pack(anchor="w")
        ctk.CTkFrame(body, width=56, height=3, fg_color=ACCENT,
                     corner_radius=2).pack(anchor="w", pady=(24, 16))
        ctk.CTkLabel(
            body, text="Keep what matters,\nsafe, prepared and accessible.",
            text_color="#F8FAFC", font=("Segoe UI", 21, "bold"),
            justify="left", wraplength=320
        ).pack(anchor="w")

        highlights = ctk.CTkFrame(body, fg_color="transparent")
        highlights.pack(anchor="w", fill="x", pady=(22, 18))
        for label in ("ORGANIZE", "MONITOR", "PREPARE"):
            chip = ctk.CTkFrame(highlights, fg_color="#0F2A45",
                                corner_radius=999, border_width=1,
                                border_color="#1D6B91")
            chip.pack(side="left", padx=(0, 9))
            ctk.CTkLabel(chip, text=label, text_color=ACCENT_TEXT,
                         font=("Segoe UI", 9, "bold")).pack(padx=12, pady=5)

        features = ctk.CTkFrame(body, fg_color="transparent")
        features.pack(anchor="w", fill="x", pady=(2, 0))
        for icon_kind, label in (("vault", "Encrypted document vault"),
                                 ("calendar", "Expiry tracking and alerts"),
                                 ("alert", "One-click emergency mode"),
                                 ("contacts", "Trusted emergency contacts")):
            row = ctk.CTkFrame(features, fg_color="transparent")
            row.pack(anchor="w", pady=4)
            icon = Canvas(row, width=22, height=22, bg=SIDEBAR,
                          highlightthickness=0, bd=0)
            self.draw_outline_icon(icon, icon_kind, color=ACCENT)
            icon.pack(side="left", padx=(0, 10))
            ctk.CTkLabel(row, text=label, text_color="#C7D7E5",
                         font=("Segoe UI", 11)).pack(side="left")

        ctk.CTkFrame(body, fg_color="transparent", height=10).pack(anchor="w")
        ctk.CTkLabel(body, text="LOCAL-FIRST  ·  ENCRYPTED  ·  OFFLINE READY",
                     text_color="#5C7C97", font=("Segoe UI", 9, "bold")
                     ).pack(anchor="w", pady=(14, 0))
        ctk.CTkFrame(content, fg_color="transparent",
                     height=1).pack(fill="both", expand=True)

    def clamp_geometry(self, width, height, reserve=(96, 112)):
        """Clamp a logical window size so it always fits the visible screen.

        ``winfo screenheight/screenwidth`` are reported in the same scaled
        units as ``wm geometry`` on this platform, so the reserved space for
        the title bar and taskbar is subtracted directly.
        """
        try:
            width = int(min(width, self.winfo_screenwidth() - reserve[0]))
            height = int(min(height, self.winfo_screenheight() - reserve[1]))
        except Exception:
            pass
        return max(320, width), max(320, height)

    def auth_shell(self, window, heading="LifeVault", subtitle=None,
                   geometry="1180x760", minimum=(760, 600)):
        for widget in window.winfo_children():
            widget.destroy()
        window.configure(fg_color=SIDEBAR)
        try:
            start_w, start_h = geometry.split("x", 1)
            start_h = start_h.split("+", 1)[0]
            start_w = start_w.split("+", 1)[0]
            geometry = "%dx%d" % self.clamp_geometry(int(start_w), int(start_h))
            minimum = self.clamp_geometry(*minimum)
        except Exception:
            pass
        window.geometry(geometry)
        window.minsize(*minimum)
        root = ctk.CTkFrame(window, fg_color=BG, corner_radius=0)
        root.pack(fill="both", expand=True)
        left = ctk.CTkFrame(root, corner_radius=0, fg_color=SIDEBAR)
        left.place(relx=0, rely=0, relwidth=.40, relheight=1)
        self.auth_brand_panel(left, heading=heading, subtitle=subtitle)
        right = ctk.CTkFrame(root, corner_radius=0, fg_color=BG)
        right.place(relx=.40, rely=0, relwidth=.60, relheight=1)
        return right

    def auth_card(self, parent, relheight=.91):
        shadow = ctk.CTkFrame(parent, fg_color="#DDE6F0", corner_radius=26)
        shadow.place(relx=.5, rely=.5, relwidth=.90, relheight=relheight,
                     anchor="center", y=6)
        card = ctk.CTkFrame(
            parent, fg_color=CARD, corner_radius=26,
            border_width=1, border_color="#E7EDF5"
        )
        card.place(relx=.5, rely=.5, relwidth=.90, relheight=relheight,
                   anchor="center")
        card._shadow = shadow
        # Scrollable body: on short screens the card scrolls instead of
        # pushing content out of the window. The scrollbar is hidden until
        # the content actually overflows.
        body = ctk.CTkScrollableFrame(
            card, fg_color=CARD, corner_radius=24,
            scrollbar_button_color=BORDER_STRONG,
            scrollbar_button_hover_color="#A9BCD0"
        )
        body.pack(fill="both", expand=True)
        body._auth_card = card
        body._sb_grid = None
        try:
            info = body._scrollbar.grid_info()
            info.pop("in", None)
            body._sb_grid = info
            body._scrollbar.grid_remove()
        except Exception:
            body._sb_grid = None
        self.queue_auth_fit(body, parent)
        return body

    def queue_auth_fit(self, body, host, delay=50):
        """Schedule a (re)fit of the auth card once widgets are realised."""
        if getattr(self, "_fit_retry_pending", False):
            return
        self._fit_retry_pending = True

        def run():
            self._fit_retry_pending = False
            try:
                if body.winfo_exists() and host.winfo_exists():
                    self.fit_auth_card(body, host)
            except Exception:
                pass
        self.after(delay, run)

    def fit_auth_card(self, card, panel=None, debug=False):
        """Size the auth card to its content (scrolling when it cannot fit)."""
        try:
            body = card if hasattr(card, "_auth_card") else card
            card = getattr(body, "_auth_card", body)
            host = panel if panel is not None else card.master
            self._auth_fit = (body, host)
            body.update_idletasks()
            host.update_idletasks()
            avail = host.winfo_height()
            attempts = getattr(body, "_fit_attempts", 0)
            if avail < 400 and attempts < 6:
                # The window has not been laid out yet - try again shortly.
                body._fit_attempts = attempts + 1
                self.queue_auth_fit(body, host, delay=60)
                return
            body._fit_attempts = 0
            if avail <= 1:
                return
            content = 0
            for child in body.winfo_children():
                try:
                    content = max(content, child.winfo_y() + child.winfo_reqheight())
                except Exception:
                    continue
            if content <= 0:
                return
            height = int(min(content + 20, avail * 0.98))
            info = card.place_info()
            if abs(int(info.get("height", 0) or 0) - height) > 1 or info.get("relheight") not in (None, "0"):
                card.place_configure(relx=.5, rely=.5, anchor="center",
                                     relheight=0, height=height)
                shadow = getattr(card, "_shadow", None)
                if shadow is not None and shadow.winfo_exists():
                    shadow.place_configure(relx=.5, rely=.5, anchor="center", y=6,
                                           relheight=0, height=height)
            scrollable = content > height
            self.toggle_auth_scrollbar(body, scrollable)
            if debug:
                print(f"  [fit] content={content} avail={avail} -> card={height}"
                      f" scroll={scrollable}")
        except Exception as exc:
            if debug:
                print("  [fit] failed:", repr(exc))

    def toggle_auth_scrollbar(self, body, scrollable):
        """Show the auth scrollbar only when the card content overflows."""
        try:
            sb = getattr(body, "_scrollbar", None)
            if sb is None or not sb.winfo_exists():
                return
            if scrollable:
                if not sb.winfo_ismapped():
                    sb.grid(**(getattr(body, "_sb_grid", None) or {}))
                    try:
                        body._parent_canvas.yview_moveto(0)
                    except Exception:
                        pass
            elif sb.winfo_ismapped():
                info = sb.grid_info()
                info.pop("in", None)
                body._sb_grid = info
                sb.grid_remove()
        except Exception:
            pass

    def refit_auth_card(self):
        """Re-run the auth card fit after a window resize."""
        ref = getattr(self, "_auth_fit", None)
        if not ref:
            self._auth_fit = None
            return
        card, host = ref
        try:
            if not card.winfo_exists() or not host.winfo_exists():
                self._auth_fit = None
                return
            self.fit_auth_card(card, host)
        except Exception:
            self._auth_fit = None

    def draw_outline_icon(self, canvas, kind, color="#64748B"):
        canvas.delete("all")
        canvas.configure(width=22, height=22)
        if kind == "email":
            canvas.create_rectangle(2.5, 4.5, 19.5, 17.5, outline=color, width=1.7)
            canvas.create_line(3, 5, 11, 11.5, 19, 5, fill=color, width=1.7)
            canvas.create_line(3, 17, 8.5, 12.5, fill=color, width=1.4)
            canvas.create_line(19, 17, 13.5, 12.5, fill=color, width=1.4)
        elif kind in ("lock", "vault"):
            canvas.create_line(6, 10, 6, 7.5, 7, 4.5, 9, 2.8, 11, 2.3,
                               13, 2.8, 15, 4.5, 16, 7.5, 16, 10,
                               fill=color, width=1.8, smooth=True)
            canvas.create_rectangle(4, 9, 18, 19, outline=color, width=1.8)
            canvas.create_oval(10, 12, 12, 14, fill=color, outline=color)
            canvas.create_line(11, 13.5, 11, 16.5, fill=color, width=1.6)
        elif kind == "calendar":
            canvas.create_rectangle(3, 4, 19, 19, outline=color, width=1.7)
            canvas.create_line(3, 8, 19, 8, fill=color, width=1.7)
            canvas.create_line(7, 2.5, 7, 6, fill=color, width=1.7)
            canvas.create_line(15, 2.5, 15, 6, fill=color, width=1.7)
            canvas.create_oval(7, 11, 9, 13, fill=color, outline=color)
            canvas.create_oval(12, 11, 14, 13, fill=color, outline=color)
            canvas.create_oval(7, 15, 9, 17, fill=color, outline=color)
        elif kind == "alert":
            canvas.create_polygon(11, 2.5, 20, 18.5, 2, 18.5,
                                  outline=color, fill="", width=1.7, joinstyle="round")
            canvas.create_line(11, 8, 11, 13, fill=color, width=1.8)
            canvas.create_oval(10.2, 15, 11.8, 16.6, fill=color, outline=color)
        elif kind == "dashboard":
            for x, y in ((3, 3), (12, 3), (3, 12), (12, 12)):
                canvas.create_rectangle(x, y, x + 6, y + 6, outline=color, width=1.5)
        elif kind == "document":
            canvas.create_polygon(5, 2.5, 14, 2.5, 18.5, 7, 18.5, 19.5,
                                  4, 19.5, 4, 3.5, outline=color, fill="", width=1.6)
            canvas.create_line(13.5, 3, 13.5, 7.5, 18, 7.5, fill=color, width=1.5)
            canvas.create_line(7, 11, 15, 11, fill=color, width=1.4)
            canvas.create_line(7, 14, 15, 14, fill=color, width=1.4)
            canvas.create_line(7, 17, 12, 17, fill=color, width=1.4)
        elif kind == "contacts":
            canvas.create_oval(7.5, 2.5, 14.5, 9.5, outline=color, width=1.5)
            canvas.create_arc(2, 9, 20, 22, start=0, extent=180,
                              style="arc", outline=color, width=1.6)
            canvas.create_oval(2.5, 5, 7, 9.5, outline=color, width=1.3)
            canvas.create_oval(15, 5, 19.5, 9.5, outline=color, width=1.3)
        elif kind == "readiness":
            canvas.create_polygon(11, 2, 19, 5, 18, 13, 11, 20,
                                  4, 13, 3, 5, outline=color, fill="", width=1.6)
            canvas.create_line(7, 11, 10, 14, 15, 8, fill=color, width=1.7)
        elif kind == "pack":
            canvas.create_rectangle(3, 7, 19, 19, outline=color, width=1.6)
            canvas.create_line(8, 7, 8, 5, 9.5, 3.5, 12.5, 3.5, 14, 5, 14, 7,
                               fill=color, width=1.5, smooth=True)
            canvas.create_line(3, 11, 19, 11, fill=color, width=1.3)
        elif kind == "settings":
            canvas.create_oval(6, 6, 16, 16, outline=color, width=1.7)
            canvas.create_oval(9, 9, 13, 13, outline=color, width=1.5)
            for angle in range(0, 360, 45):
                import math
                radians = math.radians(angle)
                canvas.create_line(11 + 5 * math.cos(radians), 11 + 5 * math.sin(radians),
                                   11 + 8 * math.cos(radians), 11 + 8 * math.sin(radians),
                                   fill=color, width=1.6)
        elif kind == "menu":
            for y in (5, 10.5, 16):
                canvas.create_line(3, y, 19, y, fill=color, width=1.8)
        elif kind == "user":
            canvas.create_oval(7.5, 2.5, 14.5, 9.5, outline=color, width=1.6)
            canvas.create_arc(2.5, 9, 19.5, 22.5, start=0, extent=180,
                              style="arc", outline=color, width=1.6)
        elif kind == "key":
            canvas.create_oval(3.5, 6.5, 11.5, 14.5, outline=color, width=1.8)
            canvas.create_oval(6, 9, 9, 12, outline=color, width=1.4)
            canvas.create_line(11, 11, 19.5, 11, fill=color, width=1.8)
            canvas.create_line(17, 11, 17, 14, fill=color, width=1.7)
            canvas.create_line(14.5, 11, 14.5, 13.5, fill=color, width=1.7)
        elif kind == "search":
            canvas.create_oval(3.5, 3.5, 14, 14, outline=color, width=1.8)
            canvas.create_line(14, 14, 19.5, 19.5, fill=color, width=2.0)
        elif kind == "phone":
            canvas.create_polygon(5, 3, 9, 3, 11, 8, 8.5, 10.5,
                                  11, 14, 14, 17, 16.5, 14.5, 21, 17.5,
                                  21, 19.5, 19, 21, 5, 21, 3, 19.5,
                                  3, 5, outline=color, fill="", width=1.5,
                                  joinstyle="round")
        elif kind == "plus":
            canvas.create_line(11, 4, 11, 18, fill=color, width=2.0)
            canvas.create_line(4, 11, 18, 11, fill=color, width=2.0)
        elif kind == "check":
            canvas.create_line(4, 11.5, 9, 16.5, 18.5, 6, fill=color,
                               width=2.0, smooth=False)
        elif kind == "logout":
            canvas.create_line(12, 4, 19, 11, 12, 18, fill=color, width=1.7)
            canvas.create_line(19, 11, 8, 11, fill=color, width=1.7)
            canvas.create_line(9, 4, 4, 4, 4, 18, 9, 18, fill=color, width=1.6)
        elif kind in ("eye", "eye_off"):
            canvas.create_line(2, 11, 5, 7, 8.5, 4.8, 11, 4, 14, 4.8,
                               17, 7, 20, 11, 17, 15, 14, 17.2, 11, 18,
                               8, 17.2, 5, 15, 2, 11,
                               fill=color, width=1.7, smooth=True)
            canvas.create_oval(8.5, 8.5, 13.5, 13.5, outline=color, width=1.6)
            canvas.create_oval(10.2, 10.2, 11.8, 11.8, fill=color, outline=color)
            if kind == "eye_off":
                canvas.create_line(3, 19, 19, 3, fill=color, width=1.8)

    def auth_entry(self, parent, icon, placeholder, show=None, outlined=False,
                   visibility_var=None):
        # Accept both drawn icon kinds ("email", "lock") and legacy glyphs.
        kind = {"@": "email", "●": "lock", "◇": "readiness"}.get(icon, icon)
        field = ctk.CTkFrame(parent, height=50, fg_color=CARD, corner_radius=12,
                             border_width=1, border_color=BORDER_STRONG)
        field.pack_propagate(False)
        icon_canvas = Canvas(field, width=20, height=20, bg=CARD,
                             highlightthickness=0, bd=0)
        self.draw_outline_icon(icon_canvas, kind, color="#7C8DA3")
        icon_canvas.pack(side="left", padx=(15, 11), pady=15)

        entry = ctk.CTkEntry(
            field, height=46, corner_radius=0, border_width=0,
            placeholder_text=placeholder, show=show or "",
            fg_color="transparent", text_color=TEXT,
            placeholder_text_color="#94A3B8", font=("Segoe UI", 13)
        )
        entry.pack(side="left", fill="both", expand=True, padx=(0, 12), pady=1)

        def _focus_in(_event=None):
            try:
                field.configure(border_color=PRIMARY, border_width=2)
                self.draw_outline_icon(icon_canvas, kind, color=PRIMARY)
            except Exception:
                pass

        def _focus_out(_event=None):
            try:
                field.configure(border_color=BORDER_STRONG, border_width=1)
                self.draw_outline_icon(icon_canvas, kind, color="#7C8DA3")
            except Exception:
                pass

        entry.bind("<FocusIn>", _focus_in)
        entry.bind("<FocusOut>", _focus_out)
        entry._field = field
        entry._field_icon = (icon_canvas, kind)

        if visibility_var is not None:
            eye_canvas = Canvas(field, width=22, height=22, bg=CARD,
                                highlightthickness=0, bd=0, cursor="hand2")
            self.draw_outline_icon(eye_canvas, "eye_off", color="#7C8DA3")
            eye_canvas.pack(side="right", padx=(5, 12), pady=15)
            entry._visibility_icon = eye_canvas

            def toggle_visibility(_event=None):
                visibility_var.set(not visibility_var.get())
                entry.configure(show="" if visibility_var.get() else "\u2022")
                self.draw_outline_icon(eye_canvas,
                                       "eye" if visibility_var.get() else "eye_off",
                                       color=PRIMARY if visibility_var.get() else "#7C8DA3")
                return "break"

            eye_canvas.bind("<Button-1>", toggle_visibility)
        return field, entry

    def app_icon(self, parent, kind, color="#94A3B8", background=SIDEBAR, size=20):
        icon = Canvas(parent, width=size, height=size, bg=background,
                      highlightthickness=0, bd=0)
        self.draw_outline_icon(icon, kind, color=color)
        return icon

    def auth_divider(self, parent, text):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=38, pady=12)
        ctk.CTkFrame(row, height=1, fg_color=BORDER_STRONG).pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(row, text=text, text_color="#94A3B8",
                     font=("Segoe UI", 10)).pack(side="left", padx=12)
        ctk.CTkFrame(row, height=1, fg_color=BORDER_STRONG).pack(side="left", fill="x", expand=True)

    # ---------------- shared presentation helpers (appearance only) ----------------

    def auth_field_label(self, parent, text):
        ctk.CTkLabel(parent, text=text.upper(), text_color="#7C8DA3",
                     font=("Segoe UI", 9, "bold"), anchor="w").pack(anchor="w")

    def auth_status(self, parent, text="", tone="neutral", pady=(0, 11)):
        """Status strip used for loading, success and error feedback."""
        strip = ctk.CTkFrame(parent, fg_color=CARD_ALT, corner_radius=10,
                             border_width=1, border_color=BORDER)
        strip.pack(fill="x", pady=pady)
        dot = Canvas(strip, width=10, height=10, bg=CARD_ALT,
                     highlightthickness=0, bd=0)
        dot.pack(side="left", padx=(12, 8), pady=9)
        label = ctk.CTkLabel(strip, text=text, text_color=MUTED,
                             font=("Segoe UI", 11), anchor="w", justify="left")
        label.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=9)
        strip._dot, strip._label = dot, label
        strip._tone, strip._base_text = "neutral", text
        self.set_auth_status(strip, text, tone)
        return strip

    def set_auth_status(self, strip, text, tone="neutral"):
        if strip is None:
            return
        try:
            if not strip.winfo_exists():
                return
            palette = {
                "neutral": (CARD_ALT, BORDER, MUTED, "#94A3B8"),
                "busy": ("#ECFEFF", "#A5F3FC", PRIMARY, "#0891B2"),
                "error": (DANGER_SOFT, "#FECACA", DANGER, DANGER),
                "success": ("#ECFDF5", "#A7F3D0", "#15803D", SUCCESS),
            }
            bg, border, fg, dot = palette.get(tone, palette["neutral"])
            strip.configure(fg_color=bg, border_color=border)
            strip._dot.configure(bg=bg)
            strip._dot.delete("all")
            strip._dot.create_oval(2, 2, 8, 8, fill=dot, outline="")
            strip._label.configure(text=text, text_color=fg)
            strip._tone, strip._base_text = tone, text
            if tone == "busy":
                self._pulse_status(strip, 0)
        except Exception:
            pass

    def _pulse_status(self, strip, step):
        try:
            if not strip.winfo_exists() or getattr(strip, "_tone", "") != "busy":
                return
            strip._label.configure(text=(strip._base_text or "") + "." * (step % 4))
        except Exception:
            return
        strip.after(350, lambda: self._pulse_status(strip, step + 1))

    def run_auth_action(self, button, busy_text, action):
        """Show a busy state on an auth button while its action runs."""
        if getattr(self, "_auth_busy", False):
            return
        self._auth_busy = True
        try:
            original = button.cget("text")
        except Exception:
            original = None
        try:
            button.configure(text=busy_text, state="disabled",
                             fg_color=PRIMARY_HOVER, cursor="watch")
            self.update_idletasks()
            self.update()
        except Exception:
            pass
        try:
            action()
        finally:
            self._auth_busy = False
            try:
                if button.winfo_exists():
                    button.configure(text=original, state="normal",
                                     fg_color=PRIMARY, cursor="")
            except Exception:
                pass

    def ui_card(self, parent, fill="x", padx=0, pady=5, radius=RADIUS,
                surface=CARD, border=BORDER):
        card = ctk.CTkFrame(parent, fg_color=surface, corner_radius=radius,
                            border_width=1, border_color=border)
        card.pack(fill=fill, padx=padx, pady=pady)
        return card

    def ui_card_header(self, parent, title, hint=None, padx=17):
        head = ctk.CTkFrame(parent, fg_color="transparent")
        head.pack(fill="x", padx=padx, pady=(15, 8))
        ctk.CTkLabel(head, text=title, text_color=TEXT,
                     font=CARD_TITLE).pack(side="left")
        if hint:
            ctk.CTkLabel(head, text=hint, text_color=MUTED,
                         font=CAPTION).pack(side="right")
        return head

    def ui_pill(self, parent, text, background, color, side=None, padx=0, pady=0):
        pill = ctk.CTkFrame(parent, fg_color=background, corner_radius=999)
        ctk.CTkLabel(pill, text=text, text_color=color,
                     font=("Segoe UI", 9, "bold")).pack(padx=9, pady=3)
        if side:
            pill.pack(side=side, padx=padx, pady=pady)
        return pill

    def ui_empty(self, parent, title, hint="", kind="document", pady=30):
        box = ctk.CTkFrame(parent, fg_color=CARD_ALT, corner_radius=14,
                           border_width=1, border_color=BORDER)
        box.pack(fill="x", padx=5, pady=pady)
        holder = ctk.CTkFrame(box, fg_color="transparent")
        holder.pack(pady=(22, 0))
        chip = ctk.CTkFrame(holder, width=54, height=54, fg_color=PRIMARY_SOFT,
                            corner_radius=27)
        chip.pack()
        chip.pack_propagate(False)
        self.app_icon(chip, kind, color=PRIMARY, background=PRIMARY_SOFT,
                      size=24).place(relx=.5, rely=.5, anchor="center")
        ctk.CTkLabel(box, text=title, text_color=TEXT,
                     font=("Segoe UI", 13, "bold")).pack(pady=(12, 0))
        if hint:
            ctk.CTkLabel(box, text=hint, text_color=MUTED, font=CAPTION,
                         wraplength=420, justify="center").pack(pady=(4, 20))
        else:
            ctk.CTkFrame(box, height=18, fg_color="transparent").pack()
        return box

    def google_mark(self, parent, size=22):
        scale = 4
        pixel_size = size * scale
        image = Image.new("RGBA", (pixel_size, pixel_size), (255, 255, 255, 0))
        drawing = ImageDraw.Draw(image)
        inset = round(pixel_size * .12)
        box = (inset, inset, pixel_size - inset, pixel_size - inset)
        stroke = max(scale * 3, round(pixel_size * .18))
        drawing.arc(box, 270, 330, fill="#EA4335", width=stroke)
        drawing.arc(box, 330, 360, fill="#4285F4", width=stroke)
        drawing.arc(box, 0, 35, fill="#4285F4", width=stroke)
        drawing.arc(box, 35, 145, fill="#34A853", width=stroke)
        drawing.arc(box, 145, 270, fill="#FBBC05", width=stroke)
        center = pixel_size / 2
        drawing.line((center, center, pixel_size - inset, center),
                     fill="#4285F4", width=stroke)
        image = image.resize((size, size), Image.Resampling.LANCZOS)
        mark = Canvas(parent, width=size, height=size, bg="#FFFFFF",
                      highlightthickness=0, bd=0, cursor="hand2")
        mark.image = ImageTk.PhotoImage(image)
        mark.create_image(size / 2, size / 2, image=mark.image)
        return mark

    def show_login(self):
        self.geometry("1240x820")
        self.minsize(700, 620)
        right = self.auth_shell(self, geometry="1240x800", minimum=(700, 620))
        card = self.auth_card(right, relheight=.94)

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.pack(fill="x", padx=38, pady=(30, 0))
        ctk.CTkLabel(head, text="Welcome back", text_color=TEXT,
                     font=("Segoe UI", 25, "bold"), anchor="w").pack(anchor="w")
        ctk.CTkLabel(head, text="Sign in to unlock your encrypted document vault.",
                     text_color=MUTED, font=("Segoe UI", 12),
                     anchor="w").pack(anchor="w", pady=(5, 0))

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=38, pady=(20, 0))

        self.auth_field_label(form, "Email address")
        email_field, self.login_email = self.auth_entry(
            form, "email", "you@example.com", outlined=True
        )
        email_field.pack(fill="x", pady=(5, 12))

        self.auth_field_label(form, "Password")
        self.login_password_visible = ctk.BooleanVar(value=False)
        password_field, self.login_password = self.auth_entry(
            form, "lock", "Enter your master password", show="\u2022",
            outlined=True, visibility_var=self.login_password_visible
        )
        password_field.pack(fill="x", pady=(5, 10))

        options = ctk.CTkFrame(form, fg_color="transparent")
        options.pack(fill="x", pady=(0, 2))
        self.add_password_toggle(
            options, self.login_password, variable=self.login_password_visible
        ).pack(side="left")
        ctk.CTkButton(options, text="Forgot password?", height=28,
                      fg_color="transparent", hover_color=PRIMARY_SOFT,
                      text_color=PRIMARY, font=("Segoe UI", 11, "bold"),
                      command=self.forgot_password_info).pack(side="right")

        self.login_status = self.auth_status(
            form, "Protected with salted PBKDF2 hashing and a locally encrypted vault.",
            tone="neutral", pady=(10, 12)
        )

        def submit_login():
            self.set_auth_status(self.login_status, "Verifying your credentials", "busy")
            self.login()

        signin = ctk.CTkButton(
            form, text="Sign in  →", height=48, corner_radius=12,
            fg_color=PRIMARY, hover_color=PRIMARY_HOVER, border_width=0,
            text_color="#FFFFFF", font=("Segoe UI", 13, "bold"),
            command=lambda: self.run_auth_action(signin, "Signing in…", submit_login)
        )
        signin.pack(fill="x", pady=(0, 4))

        self.auth_divider(card, "or continue with")
        google_control = ctk.CTkFrame(
            card, height=46, fg_color=CARD, corner_radius=12,
            border_width=1, border_color=BORDER_STRONG
        )
        google_control.pack(fill="x", padx=38)
        google_control.pack_propagate(False)
        google_canvas = self.google_mark(google_control, size=22)
        google_canvas.pack(side="left", padx=(15, 5), pady=11)
        google_canvas.bind("<Button-1>", lambda _event: self.google_signin())
        google_button = ctk.CTkButton(
            google_control, text="Continue with Google", height=42, corner_radius=10,
            fg_color="transparent", hover_color=CARD_ALT,
            text_color="#1F2937", font=("Segoe UI", 12, "bold"),
            command=self.google_signin
        )
        google_button.pack(side="left", fill="both", expand=True, padx=(0, 5), pady=1)
        self._google_button = google_button

        signup = ctk.CTkFrame(card, fg_color="transparent")
        signup.pack(pady=(14, 2))
        ctk.CTkLabel(signup, text="New to LifeVault? ",
                     text_color=MUTED, font=("Segoe UI", 11)).pack(side="left")
        ctk.CTkButton(signup, text="Create an account", height=26,
                      fg_color="transparent", hover_color=PRIMARY_SOFT,
                      text_color=PRIMARY, font=("Segoe UI", 11, "bold"),
                      command=self.show_register).pack(side="left")

        ctk.CTkLabel(
            card, text="🔒 Your data is protected with strong encryption and secure authentication.",
            text_color="#94A3B8", font=("Segoe UI", 9), wraplength=430,
            justify="center"
        ).pack(pady=(8, 15), padx=18)
        self.fit_auth_card(card, right)

    def google_signin(self):
        """Google sign-in with a busy state (the OAuth flow itself is unchanged)."""
        button = getattr(self, "_google_button", None)
        if button is None:
            self.google_login()
            return
        self.run_auth_action(button, "Opening Google…", self.google_login)

    def add_password_toggle(self, parent, *entries, text="Show password", variable=None):
        visible = variable or ctk.BooleanVar(value=False)

        def update_visibility():
            mask = "" if visible.get() else "\u2022"
            for entry in entries:
                entry.configure(show=mask)
                eye_icon = getattr(entry, "_visibility_icon", None)
                if eye_icon is not None:
                    self.draw_outline_icon(
                        eye_icon, "eye" if visible.get() else "eye_off"
                    )

        return ctk.CTkCheckBox(
            parent, text=text, variable=visible, command=update_visibility,
            onvalue=True, offvalue=False, checkbox_width=18, checkbox_height=18,
            border_width=2, corner_radius=5, border_color=BORDER_STRONG,
            fg_color=PRIMARY, hover_color=PRIMARY_TINT,
            checkmark_color="#FFFFFF", text_color=TEXT,
            hover=False, font=("Segoe UI", 11),
        )

    def new_recovery_code(self):
        token = secrets.token_hex(16).upper()
        return "-".join(token[i:i + 4] for i in range(0, len(token), 4))

    def recovery_material(self, code):
        normalized = code.replace("-", "").replace(" ", "").upper()
        code_hash, code_salt = hash_password(normalized)
        return code_hash, code_salt, make_fernet_key(normalized, code_salt)

    def google_login(self):
        """Real Google OAuth login when credentials.json is supplied."""
        if InstalledAppFlow is None:
            messagebox.showerror(
                "Google Login Setup",
                "Google OAuth package is not installed yet.\n\n"
                "Run the updated Run_LifeVault.bat once to install it."
            )
            return
        credentials_path = BASE_DIR / "credentials.json"
        if not credentials_path.exists():
            messagebox.showinfo(
                "Connect Google Login",
                "One-time setup is required.\n\n"
                "1. Create a Google OAuth Desktop App.\n"
                "2. Download its JSON file.\n"
                "3. Rename it to credentials.json.\n"
                "4. Put it beside main.py.\n\n"
                "A setup guide is included with this project."
            )
            try:
                webbrowser.open("https://console.cloud.google.com/apis/credentials")
            except Exception:
                pass
            return
        try:
            scopes = [
                "openid",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
            ]
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), scopes=scopes)
            creds = flow.run_local_server(port=0, prompt="select_account")
            req = urllib.request.Request(
                "https://openidconnect.googleapis.com/v1/userinfo",
                headers={"Authorization": f"Bearer {creds.token}"}
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                info = json.loads(response.read().decode("utf-8"))
            email = info.get("email", "").strip().lower()
            if info.get("email_verified") is not True:
                raise RuntimeError("Google did not confirm that this email address is verified.")
            name = info.get("name") or info.get("given_name") or "Google User"
            sub = info.get("sub", "")
            if not email or not sub:
                raise RuntimeError("Google did not return a valid account identity.")

            row = self.db.execute("SELECT * FROM users WHERE email=?", (email,), fetch=True, one=True)
            if row:
                self.login_email.delete(0, "end")
                self.login_email.insert(0, email)
                messagebox.showinfo(
                    "Google identity verified",
                    "Google verified this email. Enter your LifeVault master password to unlock its encrypted local vault."
                )
            else:
                self.google_identity = (name, email)
                self.show_register()
                messagebox.showinfo(
                    "Google identity verified",
                    "Set a LifeVault master password and recovery code to create your encrypted local vault."
                )
        except Exception as exc:
            messagebox.showerror("Google Login Failed", f"Google sign-in could not be completed.\n\n{exc}")

    def forgot_password_info(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("Recover LifeVault")
        dlg.geometry("1080x720")
        dlg.minsize(760, 600)
        dlg.grab_set()
        content = self.auth_shell(
            dlg, heading="LifeVault", geometry="1080x720", minimum=(760, 600)
        )
        card = self.auth_card(content, relheight=.94)
        ctk.CTkLabel(card, text="Recover your vault", text_color="#0F172A",
                     font=("Segoe UI", 25, "bold")).pack(pady=(17, 2))
        ctk.CTkLabel(
            card,
            text="Recovery is local; no email reset is sent. Losing both credentials means the encrypted vault cannot be recovered.",
            text_color="#64748B", font=("Segoe UI", 10), wraplength=450,
            justify="center"
        ).pack(padx=25, pady=(0, 7))
        email_field, email = self.auth_entry(card, "@", "Account email")
        email_field.pack(fill="x", padx=32, pady=3)
        current_email = self.login_email.get().strip()
        if current_email:
            email.insert(0, current_email)
        recovery_field, recovery = self.auth_entry(card, "◇", "Recovery code")
        recovery_field.pack(fill="x", padx=32, pady=3)
        new_password_field, new_password = self.auth_entry(card, "●", "New password", show="\u2022")
        new_password_field.pack(fill="x", padx=32, pady=3)
        confirm_field, confirm = self.auth_entry(card, "●", "Confirm new password", show="\u2022")
        confirm_field.pack(fill="x", padx=32, pady=3)
        recovery_visibility = ctk.CTkFrame(card, fg_color="transparent")
        recovery_visibility.pack(fill="x", padx=32, pady=(1, 2))
        self.add_password_toggle(recovery_visibility, new_password, text="Show new password").pack(side="left")
        self.add_password_toggle(recovery_visibility, confirm, text="Show confirmation").pack(side="right")

        def recover():
            account_email = email.get().strip().lower()
            code = recovery.get().strip().replace("-", "").replace(" ", "").upper()
            password = new_password.get()
            if not account_email or not code or not password or not confirm.get():
                messagebox.showerror("Missing information", "Complete all recovery fields.", parent=dlg)
                return
            if len(password) < 8 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
                messagebox.showerror("Weak password", "Use at least 8 characters, including a letter and a number.", parent=dlg)
                return
            if password != confirm.get():
                messagebox.showerror("Password mismatch", "The new passwords do not match.", parent=dlg)
                return
            row = self.db.execute("SELECT * FROM users WHERE email=?", (account_email,), fetch=True, one=True)
            if not row or not row["recovery_hash"] or not row["vault_key_recovery"]:
                messagebox.showerror("Recovery unavailable", "No recoverable LifeVault account was found for that email.", parent=dlg)
                return
            try:
                if not verify_password(code, row["recovery_hash"], row["recovery_salt"]):
                    messagebox.showerror("Invalid recovery code", "Check the code and try again.", parent=dlg)
                    return
                vault_key = Fernet(make_fernet_key(code, row["recovery_salt"])).decrypt(
                    row["vault_key_recovery"].encode()
                )
            except Exception:
                messagebox.showerror("Invalid recovery code", "The recovery code could not unlock this vault.", parent=dlg)
                return

            password_hash, password_salt = hash_password(password)
            fresh_code = self.new_recovery_code()
            recovery_hash, recovery_salt, recovery_key = self.recovery_material(fresh_code)
            password_key = make_fernet_key(password, password_salt)
            self.db.execute(
                "UPDATE users SET password_hash=?, password_salt=?, vault_key_password=?, recovery_hash=?, recovery_salt=?, vault_key_recovery=? WHERE id=?",
                (password_hash, password_salt, Fernet(password_key).encrypt(vault_key).decode(),
                 recovery_hash, recovery_salt, Fernet(recovery_key).encrypt(vault_key).decode(), row["id"])
            )
            self.login_email.delete(0, "end")
            self.login_email.insert(0, account_email)
            dlg.destroy()
            messagebox.showinfo(
                "Password updated",
                f"Your master password was changed and the vault data was preserved.\n\n"
                f"A new recovery code has been generated; the old one no longer works:\n\n{fresh_code}\n\n"
                "Store this code somewhere safe. It is shown only once."
            )

        ctk.CTkButton(card, text="Verify Code and Update Password", height=46,
                      fg_color="#0E7490", hover_color="#155E75",
                      font=("Segoe UI", 12, "bold"), command=recover).pack(
            fill="x", padx=32, pady=(9, 14)
        )

    def show_register(self):
        right = self.auth_shell(self, heading="Create your LifeVault",
                                geometry="1240x860", minimum=(700, 660))
        card = self.auth_card(right, relheight=.95)

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.pack(fill="x", padx=38, pady=(26, 0))
        ctk.CTkLabel(head, text="Create your vault", text_color=TEXT,
                     font=("Segoe UI", 25, "bold"), anchor="w").pack(anchor="w")
        ctk.CTkLabel(head, text="Set up your secure personal document vault.",
                     text_color=MUTED, font=("Segoe UI", 12),
                     anchor="w").pack(anchor="w", pady=(5, 0))

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=38, pady=(18, 0))

        self.auth_field_label(form, "Full name")
        name_field, self.reg_name = self.auth_entry(form, "user", "Your full name")
        name_field.pack(fill="x", pady=(4, 10))

        self.auth_field_label(form, "Email address")
        email_field, self.reg_email = self.auth_entry(form, "email", "you@example.com")
        email_field.pack(fill="x", pady=(4, 10))

        self.auth_field_label(form, "Master password")
        password_field, self.reg_password = self.auth_entry(
            form, "lock", "At least 8 characters", show="\u2022"
        )
        password_field.pack(fill="x", pady=(4, 10))

        self.auth_field_label(form, "Confirm password")
        confirm_field, self.reg_confirm = self.auth_entry(
            form, "lock", "Repeat your master password", show="\u2022"
        )
        confirm_field.pack(fill="x", pady=(4, 6))

        visibility_row = ctk.CTkFrame(form, fg_color="transparent")
        visibility_row.pack(fill="x", pady=(4, 0))
        self.add_password_toggle(visibility_row, self.reg_password,
                                 text="Show master password").pack(side="left")
        self.add_password_toggle(visibility_row, self.reg_confirm,
                                 text="Show confirmation").pack(side="right")

        identity = getattr(self, "google_identity", None)
        if identity:
            self.reg_name.insert(0, identity[0])
            self.reg_email.insert(0, identity[1])
            self.reg_email.configure(state="disabled")

        ctk.CTkLabel(form, text="Minimum 8 characters, including a letter and a number. Your password protects the vault.",
                     text_color=MUTED, font=("Segoe UI", 10),
                     wraplength=460, justify="left").pack(anchor="w", pady=(8, 0))

        self.reg_status = self.auth_status(
            form, "A one-time recovery code is generated when your vault is created.",
            tone="neutral", pady=(10, 10)
        )

        def submit_register():
            self.set_auth_status(self.reg_status, "Creating your encrypted vault", "busy")
            self.register()

        create = ctk.CTkButton(
            form, text="Create secure vault  →", height=48, corner_radius=12,
            fg_color=PRIMARY, hover_color=PRIMARY_HOVER, text_color="#FFFFFF",
            font=("Segoe UI", 13, "bold"),
            command=lambda: self.run_auth_action(create, "Creating vault…", submit_register)
        )
        create.pack(fill="x", pady=(0, 4))

        ctk.CTkButton(card, text="← Back to sign in", height=30,
                      fg_color="transparent", hover_color=PRIMARY_SOFT,
                      text_color=PRIMARY, font=("Segoe UI", 11, "bold"),
                      command=self.show_login).pack(pady=(6, 4))
        ctk.CTkLabel(card, text="Local-first • SQLite • encrypted document vault",
                     text_color="#94A3B8", font=("Segoe UI", 9)).pack(pady=(0, 14))
        self.fit_auth_card(card, right)

    def register(self):
        status = getattr(self, "reg_status", None)
        name = self.reg_name.get().strip()
        email = self.reg_email.get().strip().lower()
        password = self.reg_password.get()
        confirm = self.reg_confirm.get()

        if not name or not email or not password:
            self.set_auth_status(status, "Complete all fields to create your vault.", "error")
            messagebox.showerror("Missing information", "Please complete all fields.")
            return
        if len(password) < 8:
            self.set_auth_status(status, "Use at least 8 characters for the master password.", "error")
            messagebox.showerror("Weak password", "Use at least 8 characters.")
            return
        if password != confirm:
            self.set_auth_status(status, "The two passwords do not match.", "error")
            messagebox.showerror("Password mismatch", "Passwords do not match.")
            return

        if len(password) < 8 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
            self.set_auth_status(status, "Include at least one letter and one number.", "error")
            messagebox.showerror("Weak password", "Use at least 8 characters, including a letter and a number.")
            return
        ph, salt = hash_password(password)
        recovery_code = self.new_recovery_code()
        recovery_hash, recovery_salt, recovery_key = self.recovery_material(recovery_code)
        vault_key = Fernet.generate_key()
        password_key = make_fernet_key(password, salt)
        try:
            uid = self.db.execute(
                "INSERT INTO users(name,email,password_hash,password_salt,created_at,vault_key_password,recovery_hash,recovery_salt,vault_key_recovery) VALUES(?,?,?,?,?,?,?,?,?)",
                (name, email, ph, salt, now(), Fernet(password_key).encrypt(vault_key).decode(),
                 recovery_hash, recovery_salt, Fernet(recovery_key).encrypt(vault_key).decode())
            )
            self.db.execute("INSERT INTO profile(user_id, full_name, emergency_instructions) VALUES(?,?,?)",
                            (uid, name, "Stay calm. Contact a trusted person and use the emergency information stored in LifeVault."))
            messagebox.showinfo(
                "Vault created - save your recovery code",
                f"Your secure local vault is ready. Save this recovery code now; it is shown only once:\n\n"
                f"{recovery_code}\n\nLosing both your master password and recovery code means the encrypted vault cannot be recovered."
            )
            self.google_identity = None
            self.show_login()
        except sqlite3.IntegrityError:
            messagebox.showerror("Account exists", "That email is already registered.")

    def login(self):
        status = getattr(self, "login_status", None)
        email = self.login_email.get().strip()
        password = self.login_password.get()
        if not email:
            self.set_auth_status(status, "Enter the email address registered with this account.", "error")
            messagebox.showerror("Email required", "Enter the email address registered with this LifeVault account.")
            return
        row = self.db.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,), fetch=True, one=True)
        if not row:
            self.set_auth_status(status, "No LifeVault account matches that email address.", "error")
            messagebox.showerror("Account not found", "No LifeVault account matches that email address.")
            return
        if not verify_password(password, row["password_hash"], row["password_salt"]):
            self.set_auth_status(status, "The master password does not match this account.", "error")
            messagebox.showerror(
                "Password not recognized",
                "The LifeVault account was found, but the master password does not match. "
                "The stored password hash and vault data were not changed."
            )
            return
        password_key = make_fernet_key(password, row["password_salt"])
        show_recovery = False
        if row["vault_key_password"]:
            try:
                self.fernet_key = Fernet(password_key).decrypt(row["vault_key_password"].encode())
            except Exception:
                self.set_auth_status(status, "The encrypted vault key could not be unlocked.", "error")
                messagebox.showerror("Vault error", "The encrypted vault key could not be unlocked.")
                return
        else:
            # Upgrade accounts created before vault-key wrapping was introduced.
            self.fernet_key = password_key
            row = dict(row)
            row["vault_key_password"] = Fernet(password_key).encrypt(self.fernet_key).decode()
            show_recovery = True
        if not row["recovery_hash"] or not row["vault_key_recovery"]:
            recovery_code = self.new_recovery_code()
            recovery_hash, recovery_salt, recovery_key = self.recovery_material(recovery_code)
            self.db.execute(
                "UPDATE users SET vault_key_password=?, recovery_hash=?, recovery_salt=?, vault_key_recovery=? WHERE id=?",
                (row["vault_key_password"], recovery_hash, recovery_salt,
                 Fernet(recovery_key).encrypt(self.fernet_key).decode(), row["id"])
            )
            show_recovery = True
        elif row["vault_key_password"]:
            recovery_code = None
        if show_recovery:
            messagebox.showinfo(
                "Save your new recovery code",
                f"Your vault was upgraded and a recovery code was generated:\n\n{recovery_code}\n\n"
                "This is shown only once. Keep it safe; losing it and your password means the vault cannot be recovered."
            )
        row = self.db.execute("SELECT * FROM users WHERE id=?", (row["id"],), fetch=True, one=True)
        self.user = dict(row)
        self.is_locked = False
        self.last_activity = time.time()
        self.audit("LOGIN", "Vault unlocked")
        self.show_app()

    def logout(self, show_message=False):
        if self.user:
            self.audit("LOGOUT", "Session ended")
        self.user = None
        self.fernet_key = None
        self.is_locked = False
        if show_message:
            messagebox.showinfo("Logged out", "You have been logged out of LifeVault.")
        self.show_login()

    def confirm_logout(self):
        if messagebox.askyesno(
                "Logout",
                "Are you sure you want to logout?"):
            self.logout()

    def confirm_lock(self):
        if messagebox.askyesno("Lock Vault", "Lock your vault?"):
            self.lock_vault()

    def lock_vault(self, show_message=False):
        if not self.user:
            self.show_login()
            return
        self.fernet_key = None
        self.is_locked = True
        if show_message:
            messagebox.showinfo("Vault Locked", "Your vault is locked.")
        self.show_locked()

    def show_locked(self):
        if not self.user:
            self.show_login()
            return
        content = self.auth_shell(self, heading="LifeVault",
                                  geometry="1180x780", minimum=(640, 560))
        card = self.auth_card(content, relheight=.86)

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.pack(fill="x", padx=38, pady=(34, 0))
        chip = ctk.CTkFrame(head, width=46, height=46, fg_color=PRIMARY_SOFT,
                            corner_radius=23)
        chip.pack(anchor="w")
        chip.pack_propagate(False)
        self.app_icon(chip, "lock", color=PRIMARY, background=PRIMARY_SOFT,
                      size=22).place(relx=.5, rely=.5, anchor="center")
        ctk.CTkLabel(head, text="Vault locked", text_color=TEXT,
                     font=("Segoe UI", 25, "bold"), anchor="w").pack(
            anchor="w", pady=(14, 0)
        )
        ctk.CTkLabel(head, text="Your documents are encrypted. Unlock to continue.",
                     text_color=MUTED, font=("Segoe UI", 12),
                     anchor="w").pack(anchor="w", pady=(5, 0))

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=38, pady=(22, 0))
        self.auth_field_label(form, "Master password")
        password_field, self.lock_password_entry = self.auth_entry(
            form, "lock", "Enter your master password", show="\u2022"
        )
        password_field.pack(fill="x", pady=(5, 8))
        self.add_password_toggle(form, self.lock_password_entry).pack(anchor="w")

        self.lock_status = self.auth_status(
            form, "Locked after inactivity. Your vault key is not in memory.",
            tone="neutral", pady=(12, 12)
        )

        def submit_unlock():
            self.set_auth_status(self.lock_status, "Checking your master password", "busy")
            self.unlock_vault()

        unlock = ctk.CTkButton(
            form, text="Unlock vault  →", height=48, corner_radius=12,
            fg_color=PRIMARY, hover_color=PRIMARY_HOVER, text_color="#FFFFFF",
            font=("Segoe UI", 13, "bold"),
            command=lambda: self.run_auth_action(unlock, "Unlocking…", submit_unlock)
        )
        unlock.pack(fill="x", pady=(0, 4))
        self.lock_password_entry.bind("<Return>", lambda _event: submit_unlock())

        ctk.CTkButton(card, text="Log out instead", height=30, fg_color="transparent",
                      hover_color=PRIMARY_SOFT, text_color=PRIMARY,
                      font=("Segoe UI", 11, "bold"),
                      command=self.confirm_logout).pack(pady=(10, 14))
        self.fit_auth_card(card, content)

    def unlock_vault(self):
        if not self.user or not self.is_locked:
            return
        status = getattr(self, "lock_status", None)
        password = self.lock_password_entry.get()
        try:
            if not verify_password(password, self.user["password_hash"], self.user["password_salt"]):
                self.set_auth_status(status, "That master password is not correct.", "error")
                messagebox.showerror("Unlock failed", "The master password is incorrect.")
                self.lock_password_entry.focus_set()
                return
            password_key = make_fernet_key(password, self.user["password_salt"])
            if self.user.get("vault_key_password"):
                vault_key = Fernet(password_key).decrypt(
                    self.user["vault_key_password"].encode()
                )
            else:
                vault_key = password_key
        except Exception:
            self.set_auth_status(status, "The vault could not be unlocked with that password.", "error")
            messagebox.showerror("Unlock failed", "The vault could not be unlocked with that password.")
            self.lock_password_entry.focus_set()
            return
        self.fernet_key = vault_key
        self.is_locked = False
        self.last_activity = time.time()
        self.show_app()

    # ---------------- SHELL ----------------

    def show_app(self):
        self.clear()
        self.configure(fg_color=BG)
        self._sidebar_manually_collapsed = False
        self._mobile_menu_open = False
        self.shell = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.shell.pack(fill="both", expand=True)
        self.shell.pack_propagate(False)
        self.sidebar = ctk.CTkFrame(self.shell, width=245, corner_radius=0, fg_color=SIDEBAR)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand_row = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand_row.pack(fill="x", padx=18, pady=(14, 2))
        self.brand_logo(brand_row, 40).pack(side="left", padx=(0, 10))
        brand_text = ctk.CTkFrame(brand_row, fg_color="transparent")
        brand_text.pack(side="left", fill="x", expand=True)
        wordmark = ctk.CTkFrame(brand_text, fg_color="transparent")
        wordmark.pack(anchor="w")
        ctk.CTkLabel(wordmark, text="Life", text_color="#F8FAFC",
                     font=("Segoe UI", 19, "bold")).pack(side="left")
        ctk.CTkLabel(wordmark, text="Vault", text_color=ACCENT,
                     font=("Segoe UI", 19, "bold")).pack(side="left")
        ctk.CTkLabel(self.sidebar, text="ORGANIZE · MONITOR · PREPARE",
                     text_color="#5D748F", font=("Segoe UI", 8, "bold")).pack(
            anchor="w", padx=20, pady=(3, 10)
        )

        self.content_host = ctk.CTkFrame(self.shell, fg_color=BG, corner_radius=0)
        self.content_host.pack(side="right", fill="both", expand=True)
        self.content_host.pack_propagate(False)
        self._sidebar_buttons = []
        self._nav_items = []
        nav = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent", corner_radius=0,
                                     scrollbar_button_color="#1C2B42",
                                     scrollbar_button_hover_color="#27395A")
        nav.pack(fill="both", expand=True, padx=6, pady=(0, 8))

        items = [
            ("Dashboard", "dashboard", self.show_dashboard),
            ("Document Vault", "document", self.show_documents),
            ("Emergency Contacts", "contacts", self.show_contacts),
            ("Readiness", "readiness", self.show_readiness),
            ("Emergency Mode", "alert", self.show_emergency),
            ("Emergency Pack", "pack", self.show_pack),
            ("Settings", "settings", self.show_settings),
        ]
        sections = (
            ("OVERVIEW", items[0:2]),
            ("EMERGENCY", items[2:6]),
            ("ACCOUNT", items[6:7]),
        )
        for section_title, section_items in sections:
            ctk.CTkLabel(nav, text=section_title, text_color="#546B85",
                         font=("Segoe UI", 9, "bold"), anchor="w").pack(
                anchor="w", padx=12, pady=(9, 2)
            )
            for label, icon_kind, command in section_items:
                row = ctk.CTkFrame(nav, fg_color="transparent", corner_radius=9, height=38)
                row.pack(fill="x", padx=6, pady=1)
                row.pack_propagate(False)
                icon = self.app_icon(row, icon_kind, color="#8FA3BC", background=SIDEBAR)
                icon.pack(side="left", padx=(12, 9))
                action = lambda callback=command: self.navigate(callback)
                icon.bind("<Button-1>", lambda _event, callback=action: callback())
                button = ctk.CTkButton(row, text=label, anchor="w", height=38, corner_radius=9,
                                       fg_color="transparent", hover_color=SIDEBAR_HOVER,
                                       text_color=SIDEBAR_TEXT, font=("Segoe UI", 12),
                                       command=action)
                button.pack(side="left", fill="both", expand=True, padx=(0, 4))
                self._sidebar_buttons.append(button)
                self._nav_items.append((row, button, icon, icon_kind))

        footer = ctk.CTkFrame(self.sidebar, fg_color=SIDEBAR, corner_radius=0)
        footer.pack(side="bottom", fill="x", padx=12, pady=(8, 10))
        ctk.CTkFrame(footer, height=1, fg_color=SIDEBAR_LINE).pack(fill="x", padx=6, pady=(0, 8))

        user_chip = ctk.CTkFrame(footer, fg_color="#0F1D31", corner_radius=12)
        user_chip.pack(fill="x", padx=2, pady=(0, 8))
        initials = "".join(part[0].upper()
                           for part in self.user.get("name", "LV").split()[:2]) or "LV"
        chip_avatar = ctk.CTkFrame(user_chip, width=30, height=30,
                                   fg_color="#0E3A4F", corner_radius=15)
        chip_avatar.pack(side="left", padx=(9, 8), pady=7)
        chip_avatar.pack_propagate(False)
        ctk.CTkLabel(chip_avatar, text=initials, text_color=ACCENT,
                     font=("Segoe UI", 10, "bold")).place(relx=.5, rely=.5, anchor="center")
        chip_text = ctk.CTkFrame(user_chip, fg_color="transparent")
        chip_text.pack(side="left", fill="x", expand=True, pady=6)
        ctk.CTkLabel(chip_text, text=self.user.get("name", "LifeVault User"),
                     text_color="#E7EEF6", font=("Segoe UI", 11, "bold"),
                     anchor="w").pack(anchor="w", fill="x")
        ctk.CTkLabel(chip_text, text=self.user.get("email", ""),
                     text_color="#7E93AC", font=("Segoe UI", 9),
                     anchor="w").pack(anchor="w", fill="x")

        status_row = ctk.CTkFrame(footer, fg_color="transparent")
        status_row.pack(anchor="w", padx=8, pady=(0, 6))
        status_dot = Canvas(status_row, width=10, height=10, bg=SIDEBAR,
                            highlightthickness=0, bd=0)
        status_dot.create_oval(1, 1, 9, 9, fill=SUCCESS, outline="")
        status_dot.pack(side="left", padx=(0, 7))
        ctk.CTkLabel(status_row, text="Vault unlocked", text_color="#A7F3D0",
                     font=("Segoe UI", 10, "bold")).pack(side="left")
        lock_row = ctk.CTkFrame(footer, fg_color="transparent")
        lock_row.pack(fill="x", pady=(0, 4))
        self.app_icon(lock_row, "lock", color="#CBD5E1").pack(side="left", padx=(12, 8))
        ctk.CTkButton(lock_row, text="Lock Vault", height=36, anchor="w",
                      fg_color="#15243A", hover_color="#1E3555",
                      font=("Segoe UI", 11, "bold"), command=self.confirm_lock).pack(
            side="left", fill="x", expand=True
        )
        logout_row = ctk.CTkFrame(footer, fg_color="transparent")
        logout_row.pack(fill="x")
        self.app_icon(logout_row, "logout", color="#F87171").pack(side="left", padx=(12, 8))
        ctk.CTkButton(logout_row, text="Logout", height=38, anchor="w",
                      fg_color="transparent", hover_color="#2A1520",
                      text_color="#FCA5A5", font=("Segoe UI", 11, "bold"),
                      command=self.confirm_logout).pack(side="left", fill="x", expand=True)
        self.sync_nav()
        self._apply_sidebar_visibility(True)
        self.show_dashboard()

    def _apply_sidebar_visibility(self, visible):
        if not hasattr(self, "sidebar") or not self.sidebar.winfo_exists():
            return
        if visible and not self.sidebar.winfo_manager():
            self.sidebar.pack(side="left", fill="y", before=self.content_host)
        elif not visible and self.sidebar.winfo_manager():
            self.sidebar.pack_forget()
        self._sidebar_visible = visible

    def _on_window_configure(self, event=None):
        if event is not None and event.widget is not self:
            return
        if self._resize_pending:
            return
        self._resize_pending = True
        self.after_idle(self._update_responsive_navigation)

    def _update_responsive_navigation(self):
        self._resize_pending = False
        if getattr(self, "_in_refit", False):
            return
        self._in_refit = True
        try:
            self.refit_auth_card()
        finally:
            self._in_refit = False
        if not hasattr(self, "sidebar") or not self.sidebar.winfo_exists():
            return
        if self.is_compact_window():
            self._apply_sidebar_visibility(self._mobile_menu_open)
        else:
            self._mobile_menu_open = False
            self._apply_sidebar_visibility(not self._sidebar_manually_collapsed)
        self.maybe_rerender_page()

    PAGE_BUILDERS = {
        "LifeVault Dashboard": "show_dashboard",
        "Document Vault": "show_documents",
        "Emergency Contacts": "show_contacts",
        "Emergency Readiness": "show_readiness",
        "Emergency Mode": "show_emergency",
        "Emergency Pack": "show_pack",
        "Settings": "show_settings",
    }

    def layout_bucket(self):
        """Discrete responsive bucket for the current window size."""
        try:
            scale = ctk.ScalingTracker.get_widget_scaling(self)
            window = self.winfo_width() / scale
            content = (self.content_host.winfo_width() / scale
                       if hasattr(self, "content_host") and self.content_host.winfo_exists()
                       else window)
        except Exception:
            window, content = 0, 0
        return (self.is_compact_window(), content >= 760, content >= 900,
                content >= 1300, window >= 900, window >= 1300)

    def maybe_rerender_page(self):
        """Rebuild the visible page once it crosses a responsive breakpoint."""
        bucket = self.layout_bucket()
        previous = getattr(self, "_layout_bucket_value", None)
        self._layout_bucket_value = bucket
        if previous is None or previous == bucket:
            return
        if not hasattr(self, "content_host") or not self.content_host.winfo_exists():
            return
        builder = self.PAGE_BUILDERS.get(getattr(self, "_active_page", ""))
        if not builder or getattr(self, "_rendering_page", False):
            return
        self._rendering_page = True
        try:
            getattr(self, builder)()
        finally:
            self._rendering_page = False

    def is_compact_window(self):
        breakpoint = 820 * ctk.ScalingTracker.get_widget_scaling(self)
        return self.winfo_width() < breakpoint

    def toggle_sidebar(self):
        if self.is_compact_window():
            self._mobile_menu_open = not self._sidebar_visible
            self._apply_sidebar_visibility(self._mobile_menu_open)
        else:
            self._sidebar_manually_collapsed = self._sidebar_visible
            self._apply_sidebar_visibility(not self._sidebar_visible)

    def navigate(self, action):
        action()
        if self.is_compact_window():
            self._mobile_menu_open = False
            self._apply_sidebar_visibility(False)

    NAV_BY_TITLE = {
        "LifeVault Dashboard": 0,
        "Document Vault": 1,
        "Emergency Contacts": 2,
        "Emergency Readiness": 3,
        "Emergency Mode": 4,
        "Emergency Pack": 5,
        "Settings": 6,
    }

    def sync_nav(self):
        """Highlight the sidebar entry that belongs to the visible page."""
        items = getattr(self, "_nav_items", None)
        if not items:
            return
        active = self.NAV_BY_TITLE.get(getattr(self, "_active_page", ""), -1)
        for index, (row, button, icon, kind) in enumerate(items):
            if not row.winfo_exists():
                continue
            on = index == active
            try:
                row.configure(fg_color=SIDEBAR_ACTIVE if on else "transparent")
                button.configure(
                    fg_color="transparent",
                    hover_color="#1B3050" if on else SIDEBAR_HOVER,
                    text_color="#FFFFFF" if on else SIDEBAR_TEXT,
                    font=("Segoe UI", 12, "bold") if on else ("Segoe UI", 12),
                )
                icon.configure(bg=SIDEBAR_ACTIVE if on else SIDEBAR)
                self.draw_outline_icon(icon, kind, color=ACCENT if on else "#8FA3BC")
            except Exception:
                continue

    def page(self, title, subtitle="", content_color=BG, title_color=TEXT, subtitle_color=MUTED):
        try:
            shell_ok = hasattr(self, "content_host") and self.content_host.winfo_exists()
        except Exception:
            shell_ok = False
        if not shell_ok:
            # The shell was torn down (lock/logout screens) - rebuild it once.
            if not getattr(self, "user", None):
                raise RuntimeError("LifeVault shell is unavailable")
            depth = getattr(self, "_page_rebuild_depth", 0)
            if depth > 2:
                raise RuntimeError("LifeVault shell is unavailable")
            self._page_rebuild_depth = depth + 1
            try:
                self.show_app()
            finally:
                self._page_rebuild_depth = depth
            return self.page(title, subtitle, content_color, title_color,
                             subtitle_color)
        for widget in self.content_host.winfo_children():
            widget.destroy()
        self._active_page = title
        main = ctk.CTkFrame(self.content_host, fg_color=content_color, corner_radius=0)
        main.pack(fill="both", expand=True)
        header = ctk.CTkFrame(main, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(19, 6))
        menu_bitmap = Image.new("RGBA", (24, 24), (255, 255, 255, 0))
        menu_draw = ImageDraw.Draw(menu_bitmap)
        for y in (5, 11, 17):
            menu_draw.line((3, y, 21, y), fill="#334155", width=2)
        self.menu_icon_image = ctk.CTkImage(light_image=menu_bitmap,
                                            dark_image=menu_bitmap,
                                            size=(20, 20))
        self.menu_button = ctk.CTkButton(
            header, text="", image=self.menu_icon_image, width=42, height=42,
            corner_radius=10, fg_color=CARD, hover_color=PRIMARY_SOFT,
            border_width=1, border_color=BORDER, command=self.toggle_sidebar
        )
        self.menu_button.pack(side="left", padx=(0, 13))
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(title_frame, text=title, text_color=title_color,
                     font=("Segoe UI", 22, "bold"), anchor="w").pack(
            anchor="w", fill="x"
        )
        if subtitle:
            ctk.CTkLabel(title_frame, text=subtitle, text_color=subtitle_color,
                         font=("Segoe UI", 11), anchor="w", wraplength=760,
                         justify="left").pack(anchor="w", fill="x")
        user_area = ctk.CTkFrame(header, fg_color=CARD, corner_radius=999,
                                 border_width=1, border_color=BORDER)
        user_area.pack(side="right", padx=(14, 0))
        initials = "".join(part[0].upper() for part in self.user.get("name", "LV").split()[:2]) or "LV"
        avatar = ctk.CTkFrame(user_area, width=30, height=30, fg_color=PRIMARY_TINT,
                              corner_radius=15)
        avatar.pack(side="left", padx=(4, 8), pady=4)
        avatar.pack_propagate(False)
        ctk.CTkLabel(avatar, text=initials, text_color=PRIMARY_HOVER,
                     font=("Segoe UI", 10, "bold")).place(relx=.5, rely=.5, anchor="center")
        ctk.CTkLabel(user_area, text=self.user.get("name", "LifeVault User"),
                     text_color=TEXT, font=("Segoe UI", 11, "bold")).pack(
            side="left", padx=(0, 14)
        )
        ctk.CTkFrame(main, height=1, fg_color=BORDER).pack(fill="x", padx=24)
        self.sync_nav()
        return main

    # ---------------- DASHBOARD ----------------

    def stats(self):
        docs = self.db.execute("SELECT COUNT(*) c FROM documents WHERE user_id=?", (self.user["id"],), fetch=True, one=True)["c"]
        contacts = self.db.execute("SELECT COUNT(*) c FROM contacts WHERE user_id=?", (self.user["id"],), fetch=True, one=True)["c"]
        active = 0
        expired = 0
        expiring = 0
        rows = self.db.execute("SELECT expiry_date FROM documents WHERE user_id=?",
                               (self.user["id"],), fetch=True)
        for r in rows:
            status, _ = self.status(r["expiry_date"])
            if status.endswith("ACTIVE"):
                active += 1
            elif status.endswith("EXPIRED"):
                expired += 1
            elif status.endswith("EXPIRING SOON"):
                expiring += 1
        return docs, active, contacts, expiring, expired

    def readiness_score(self):
        uid = self.user["id"]
        checks = []
        contacts = self.db.execute("SELECT COUNT(*) c FROM contacts WHERE user_id=? AND is_emergency=1", (uid,), fetch=True, one=True)["c"]
        insurance = self.db.execute("SELECT COUNT(*) c FROM documents WHERE user_id=? AND category='Insurance'", (uid,), fetch=True, one=True)["c"]
        vehicle_docs = self.db.execute("SELECT COUNT(*) c FROM documents WHERE user_id=? AND category='Vehicle'", (uid,), fetch=True, one=True)["c"]
        documents = self.db.execute("SELECT COUNT(*) c FROM documents WHERE user_id=?", (uid,), fetch=True, one=True)["c"]
        profile = self.db.execute("SELECT * FROM profile WHERE user_id=?", (uid,), fetch=True, one=True)
        valid_documents = False
        for doc in self.db.execute("SELECT expiry_date FROM documents WHERE user_id=?", (uid,), fetch=True):
            expiry = doc["expiry_date"]
            try:
                if not expiry or datetime.strptime(expiry, "%Y-%m-%d").date() >= date.today():
                    valid_documents = True
                    break
            except ValueError:
                continue

        checks.append(("Emergency contact exists", contacts > 0, 20))
        checks.append(("Insurance information exists", bool(insurance or (profile and profile["insurance_info"])), 20))
        checks.append(("Vehicle information exists", bool(vehicle_docs or (profile and profile["vehicle_number"])), 20))
        checks.append(("Documents exist", documents > 0, 20))
        checks.append(("At least one valid document", valid_documents, 20))

        score = sum(weight for _, ok, weight in checks if ok)
        return score, checks

    def show_dashboard(self):
        main = self.page("LifeVault Dashboard",
                         "Your personal emergency readiness dashboard")
        body = ctk.CTkScrollableFrame(main, fg_color="transparent",
                                      scrollbar_button_color="#CBD5E1",
                                      scrollbar_button_hover_color="#94A3B8")
        body.pack(fill="both", expand=True, padx=24, pady=(14, 18))
        docs, active, contacts, expiring, expired = self.stats()
        score, checks = self.readiness_score()
        scale = ctk.ScalingTracker.get_widget_scaling(self)
        compact = self.content_host.winfo_width() / scale < 760

        metric_grid = ctk.CTkFrame(body, fg_color="transparent")
        metric_grid.pack(fill="x", pady=(0, 14))
        logical_width = self.content_host.winfo_width() / scale
        window_logical_width = self.winfo_width() / scale
        metric_columns = 2 if compact else 6 if window_logical_width >= 1300 else 3
        metrics = (
            ("document", "Total Documents", docs),
            ("document", "Active Documents", active),
            ("calendar", "Expiring Soon", expiring),
            ("alert", "Expired", expired),
            ("contacts", "Emergency Contacts", contacts),
            ("readiness", "Readiness", f"{score}%"),
        )
        for index, (icon, title, value) in enumerate(metrics):
            self.stat(metric_grid, icon, title, value,
                      index // metric_columns, index % metric_columns, metric_columns)

        overview = ctk.CTkFrame(body, fg_color="transparent")
        overview.pack(fill="x", pady=(0, 14))
        readiness_card = ctk.CTkFrame(overview, fg_color=CARD, corner_radius=RADIUS,
                                      border_width=1, border_color=BORDER)
        alerts_card = ctk.CTkFrame(overview, fg_color=CARD, corner_radius=RADIUS,
                                   border_width=1, border_color=BORDER)
        if compact:
            readiness_card.pack(fill="x", pady=(0, 12))
            alerts_card.pack(fill="x")
        else:
            readiness_card.pack(side="left", fill="both", expand=True, padx=(0, 7))
            alerts_card.pack(side="left", fill="both", expand=True, padx=(7, 0))

        # --- readiness card ---
        self.ui_card_header(readiness_card, "Emergency Readiness")
        ring_holder = ctk.CTkFrame(readiness_card, fg_color="transparent")
        ring_holder.pack(fill="x", padx=17, pady=(2, 0))
        ring = Canvas(ring_holder, width=112, height=112, bg="#FFFFFF",
                      highlightthickness=0, bd=0)
        ring.pack(side="left", padx=(0, 15), pady=(2, 8))
        ring.create_oval(10, 10, 102, 102, outline="#E7EEF6", width=10)
        arc = ring.create_arc(10, 10, 102, 102, start=90, extent=0,
                              style="arc", outline=PRIMARY, width=10)
        ring.create_text(56, 56, text=f"{score}%", fill=TEXT,
                         font=("Segoe UI", 20, "bold"))
        summary = ctk.CTkFrame(ring_holder, fg_color="transparent")
        summary.pack(side="left", fill="both", expand=True, pady=(0, 8))
        passed = sum(1 for _, ok, _ in checks if ok)
        ctk.CTkLabel(summary, text="Your vault is well prepared." if score >= 80 else
                     "Your preparation is building." if score >= 40 else
                     "Add key details to improve completeness.",
                     text_color=TEXT, font=(CARD_TITLE[0], 13, "bold"),
                     wraplength=260, justify="left", anchor="w").pack(
            anchor="w", fill="x"
        )
        ctk.CTkLabel(summary, text=f"{passed} of {len(checks)} readiness checks passed.",
                     text_color=MUTED, font=BODY_MUTED, anchor="w").pack(
            anchor="w", pady=(5, 9)
        )
        ctk.CTkButton(summary, text="View Readiness", height=32, width=140,
                      corner_radius=9, fg_color=PRIMARY_SOFT, hover_color=PRIMARY_TINT,
                      text_color=PRIMARY, font=("Segoe UI", 11, "bold"),
                      command=self.show_readiness).pack(anchor="w")
        self.animate_ring(ring, arc, score)

        # --- alerts card ---
        self.ui_card_header(alerts_card, "Important Alerts")
        profile = self.db.execute("SELECT * FROM profile WHERE user_id=?",
                                  (self.user["id"],), fetch=True, one=True)
        alert_items = []
        if expired:
            alert_items.append(("alert", f"{expired} expired document(s) need attention.", DANGER, DANGER_SOFT))
        if expiring:
            alert_items.append(("calendar", f"{expiring} document(s) expire within 30 days.", WARNING, WARNING_SOFT))
        if contacts == 0:
            alert_items.append(("contacts", "Add an emergency contact.", DANGER, DANGER_SOFT))
        if not (profile and profile["insurance_info"]) and not self.db.execute(
                "SELECT id FROM documents WHERE user_id=? AND category='Insurance' LIMIT 1",
                (self.user["id"],), fetch=True, one=True):
            alert_items.append(("document", "Insurance information is missing.", WARNING, WARNING_SOFT))
        if not alert_items:
            alert_items.append(("readiness", "No urgent alerts.", SUCCESS, SUCCESS_SOFT))
        for icon, text, color, tint in alert_items[:3]:
            alert_row = ctk.CTkFrame(alerts_card, fg_color=CARD_ALT, corner_radius=10)
            alert_row.pack(fill="x", padx=16, pady=5)
            chip = ctk.CTkFrame(alert_row, width=30, height=30, fg_color=tint,
                                corner_radius=8)
            chip.pack(side="left", padx=(9, 10), pady=7)
            chip.pack_propagate(False)
            self.app_icon(chip, icon, color=color, background=tint, size=18).place(
                relx=.5, rely=.5, anchor="center"
            )
            ctk.CTkLabel(alert_row, text=text, text_color=TEXT,
                         font=("Segoe UI", 11), wraplength=330,
                         justify="left", anchor="w").pack(
                side="left", fill="x", expand=True, padx=(0, 10), pady=7
            )
        ctk.CTkLabel(alerts_card, text="Based on information currently in your vault.",
                     text_color=MUTED, font=CAPTION).pack(
            anchor="w", padx=17, pady=(6, 12)
        )

        # --- quick actions ---
        quick = ctk.CTkFrame(body, fg_color=CARD, corner_radius=RADIUS,
                             border_width=1, border_color=BORDER)
        quick.pack(fill="x", pady=(0, 14))
        self.ui_card_header(quick, "Quick Actions", hint="Jump straight to a task")
        action_row = ctk.CTkFrame(quick, fg_color="transparent")
        action_row.pack(fill="x", padx=12, pady=(0, 13))
        actions = (("Add Document", "document", self.add_document),
                   ("Emergency Mode", "alert", self.show_emergency),
                   ("Emergency Pack", "pack", self.show_pack),
                   ("Add Contact", "contacts", self.add_contact))
        action_columns = 2 if compact else 4 if logical_width >= 900 else 2
        for column in range(action_columns):
            action_row.grid_columnconfigure(column, weight=1, uniform="quick")
        for index, (label, icon, callback) in enumerate(actions):
            action = ctk.CTkButton(
                action_row, text=label, height=52, corner_radius=11, anchor="center",
                fg_color=CARD_ALT, hover_color=PRIMARY_SOFT,
                text_color=TEXT, font=("Segoe UI", 11, "bold"),
                border_width=1, border_color=BORDER, command=callback
            )
            action.grid(row=index // action_columns, column=index % action_columns,
                        sticky="ew", padx=5, pady=5)

        # --- recent + upcoming ---
        tables = ctk.CTkFrame(body, fg_color="transparent")
        tables.pack(fill="x")
        recent_card = ctk.CTkFrame(tables, fg_color=CARD, corner_radius=RADIUS,
                                   border_width=1, border_color=BORDER)
        upcoming_card = ctk.CTkFrame(tables, fg_color=CARD, corner_radius=RADIUS,
                                     border_width=1, border_color=BORDER)
        if compact:
            recent_card.pack(fill="x", pady=(0, 12))
            upcoming_card.pack(fill="x")
        else:
            recent_card.pack(side="left", fill="both", expand=True, padx=(0, 7))
            upcoming_card.pack(side="left", fill="both", expand=True, padx=(7, 0))

        self.ui_card_header(recent_card, "Recent Documents", hint="Latest in your vault")
        recent = self.db.execute("SELECT name,category,expiry_date,is_emergency FROM documents WHERE user_id=? ORDER BY id DESC LIMIT 4",
                                 (self.user["id"],), fetch=True)
        table_head = ctk.CTkFrame(recent_card, fg_color=CARD_ALT, corner_radius=8)
        table_head.pack(fill="x", padx=12, pady=(0, 4))
        for heading_text, width in (("Document", 2), ("Category", 1), ("Expiry / Status", 2), ("Pack", 1)):
            ctk.CTkLabel(table_head, text=heading_text, text_color=MUTED,
                         font=(CAPTION[0], 9, "bold"), anchor="w").pack(
                side="left", fill="x", expand=True, padx=6, pady=7
            )
        if recent:
            for document in recent:
                row = ctk.CTkFrame(recent_card, fg_color="transparent")
                row.pack(fill="x", padx=12, pady=2)
                status, status_color = self.status(document["expiry_date"])
                values = (document["name"], document["category"],
                          f"{document['expiry_date'] or 'No expiry'} · {status}",
                          "Selected" if document["is_emergency"] else "—")
                for value in values:
                    ctk.CTkLabel(row, text=value, text_color=status_color if value.startswith(("ACTIVE", "EXPIRED", "EXPIRING")) else TEXT,
                                 font=(BODY_MUTED[0], 10), anchor="w", wraplength=150,
                                 justify="left").pack(side="left", fill="x", expand=True, padx=6, pady=7)
        else:
            self.ui_empty(recent_card, "No documents added yet.",
                          "Add your first document to see it here.", kind="document",
                          pady=(6, 16))

        self.ui_card_header(upcoming_card, "Upcoming Expiry", hint="Next 12 months")
        upcoming = self.db.execute("""SELECT name,expiry_date FROM documents WHERE user_id=? AND expiry_date IS NOT NULL
                                     AND expiry_date>=? ORDER BY expiry_date LIMIT 4""",
                                   (self.user["id"], date.today().isoformat()), fetch=True)
        if upcoming:
            for document in upcoming:
                row = ctk.CTkFrame(upcoming_card, fg_color=CARD_ALT, corner_radius=9)
                row.pack(fill="x", padx=12, pady=4)
                ctk.CTkLabel(row, text=document["expiry_date"], text_color=PRIMARY,
                             font=(BODY_MUTED[0], 10, "bold"), width=88).pack(side="left", padx=9, pady=8)
                ctk.CTkLabel(row, text=document["name"], text_color=TEXT,
                             font=BODY_MUTED, anchor="w").pack(side="left", fill="x", expand=True, padx=6)
        else:
            self.ui_empty(upcoming_card, "No upcoming expirations.",
                          "Documents with an expiry date will appear here.",
                          kind="calendar", pady=(6, 16))

    def animate_ring(self, canvas, item, target, step=0, total=14):
        """Draw the readiness ring from zero to its score (subtle motion only)."""
        try:
            if not canvas.winfo_exists():
                return
            if step >= total:
                canvas.itemconfig(item, extent=-target * 3.6)
                return
            ease = 1 - (1 - (step + 1) / total) ** 2
            canvas.itemconfig(item, extent=-target * 3.6 * ease)
            canvas.after(40, lambda: self.animate_ring(canvas, item, target,
                                                       step + 1, total))
        except Exception:
            return

    def stat(self, parent, icon, title, value, row, column, columns):
        card = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=RADIUS,
                            border_width=1, border_color=BORDER)
        card.grid(row=row, column=column, sticky="nsew", padx=5, pady=5)
        parent.grid_columnconfigure(column, weight=1, uniform="stat")
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=14, pady=(13, 0))
        chip = ctk.CTkFrame(top, width=34, height=34, fg_color=PRIMARY_SOFT,
                            corner_radius=10)
        chip.pack(side="left")
        chip.pack_propagate(False)
        self.app_icon(chip, icon, color=PRIMARY, background=PRIMARY_SOFT,
                      size=18).place(relx=.5, rely=.5, anchor="center")
        ctk.CTkLabel(top, text=str(value), text_color=TEXT,
                     font=("Segoe UI", 21, "bold")).pack(side="right")
        ctk.CTkLabel(card, text=title, text_color=MUTED, font=BODY_MUTED,
                     wraplength=170, justify="left", anchor="w").pack(
            anchor="w", fill="x", padx=14, pady=(9, 13)
        )

    # ---------------- DOCUMENTS ----------------

    def show_documents(self):
        main = self.page("Document Vault", "Securely organize and manage your important documents.")
        toolbar = ctk.CTkFrame(main, fg_color="transparent")
        toolbar.pack(fill="x", padx=24, pady=(10, 12))
        # On narrow content widths the search field gets its own row so the
        # filters and the primary action keep comfortable targets.
        logical_width = self.content_host.winfo_width() / ctk.ScalingTracker.get_widget_scaling(self)
        narrow_toolbar = logical_width < 900
        controls = ctk.CTkFrame(toolbar, fg_color="transparent")

        self.search_var = ctk.StringVar()
        search_frame = ctk.CTkFrame(toolbar, fg_color=CARD, corner_radius=10,
                                    border_width=1, border_color=BORDER, height=43)
        if narrow_toolbar:
            search_frame.pack(fill="x", pady=(0, 8))
            controls.pack(fill="x")
        else:
            search_frame.pack(side="left", fill="x", expand=True, padx=(0, 9))
            controls.pack(side="left")
        search_frame.pack_propagate(False)
        self.app_icon(search_frame, "search", color=MUTED, background=CARD,
                      size=18).pack(side="left", padx=(11, 3), pady=11)
        search = ctk.CTkEntry(search_frame, textvariable=self.search_var,
                              height=39, border_width=0, corner_radius=0,
                              fg_color="transparent", placeholder_text="Search documents...",
                              text_color=TEXT, placeholder_text_color="#94A3B8",
                              font=("Segoe UI", 11))
        search.pack(side="left", fill="both", expand=True, padx=(2, 8), pady=1)
        search.bind("<KeyRelease>", lambda _event: self.refresh_docs())

        self.category_filter = ctk.CTkComboBox(
            controls, width=132, height=42, values=["All"] + CATEGORIES,
            command=lambda _value: self.refresh_docs(), font=("Segoe UI", 10),
            border_color=BORDER_STRONG, button_color="#E8EEF5",
            button_hover_color="#DCE6F0", fg_color=CARD, text_color=TEXT
        )
        self.category_filter.set("All")
        self.category_filter.pack(side="left", padx=(0, 7))
        self.status_filter = ctk.CTkComboBox(
            controls, width=138, height=42,
            values=["All statuses", "Active", "Expiring Soon", "Expired"],
            command=lambda _value: self.refresh_docs(), font=("Segoe UI", 10),
            border_color=BORDER_STRONG, button_color="#E8EEF5",
            button_hover_color="#DCE6F0", fg_color=CARD, text_color=TEXT
        )
        self.status_filter.set("All statuses")
        self.status_filter.pack(side="left", padx=(0, 7))
        ctk.CTkButton(controls, text="Add Document", height=42, corner_radius=9,
                      fg_color=PRIMARY, hover_color=PRIMARY_HOVER,
                      font=("Segoe UI", 10, "bold"), command=self.add_document).pack(side="right")

        self.doc_scroll = ctk.CTkScrollableFrame(main, fg_color="transparent",
                                                scrollbar_button_color="#CBD5E1",
                                                scrollbar_button_hover_color="#94A3B8")
        self.doc_scroll.pack(fill="both", expand=True, padx=20, pady=(0, 16))
        self.refresh_docs()

    def refresh_docs(self):
        if not hasattr(self, "doc_scroll") or not self.doc_scroll.winfo_exists():
            return
        for w in self.doc_scroll.winfo_children():
            w.destroy()
        q = getattr(self, "search_var", ctk.StringVar()).get().strip().lower()
        rows = self.db.execute("SELECT * FROM documents WHERE user_id=? ORDER BY id DESC",
                               (self.user["id"],), fetch=True)
        all_rows = rows
        selected_category = self.category_filter.get() if hasattr(self, "category_filter") else "All"
        selected_status = self.status_filter.get() if hasattr(self, "status_filter") else "All statuses"
        rows = [r for r in rows
                if (not q or q in r["name"].lower() or q in r["category"].lower()
                    or q in self.status(r["expiry_date"])[0].lower())
                and (selected_category == "All" or r["category"] == selected_category)
                and (selected_status == "All statuses" or self.status(r["expiry_date"])[0].lower().endswith(selected_status.lower()))]
        if not rows:
            if not all_rows:
                self.ui_empty(self.doc_scroll, "Your vault is empty.",
                              "Add your first document to keep it organised and protected.",
                              kind="document", pady=14)
            else:
                self.ui_empty(self.doc_scroll, "No documents match this view.",
                              "Try a different search term, category or status filter.",
                              kind="search", pady=14)
            return

        table = ctk.CTkFrame(self.doc_scroll, fg_color=CARD, corner_radius=12,
                             border_width=1, border_color=BORDER)
        table.pack(fill="x", padx=5, pady=4)
        headings = ("Document", "Category", "Expiry", "Status", "Emergency Pack", "Actions")
        column_weights = (3, 2, 2, 2, 2, 2)
        for column, (heading, weight) in enumerate(zip(headings, column_weights)):
            table.grid_columnconfigure(column, weight=weight, uniform="documents")
        # Header band is created first so the labels paint on top of it.
        header_band = ctk.CTkFrame(table, fg_color=CARD_ALT, corner_radius=8)
        header_band.grid(row=0, column=0, columnspan=6, sticky="new",
                         padx=1, pady=(1, 0))
        for column, (heading, weight) in enumerate(zip(headings, column_weights)):
            ctk.CTkLabel(table, text=heading, text_color=MUTED,
                         font=(CAPTION[0], 9, "bold"), anchor="w").grid(
                row=0, column=column, sticky="ew", padx=11, pady=10
            )
        ctk.CTkFrame(table, height=1, fg_color=BORDER).grid(
            row=1, column=0, columnspan=6, sticky="ew", padx=8
        )
        for r in rows:
            row_index = rows.index(r) + 2
            row_bg = "#FFFFFF" if row_index % 2 == 0 else "#FBFCFE"
            ctk.CTkFrame(table, height=1, fg_color=row_bg).grid(
                row=row_index, column=0, columnspan=6, sticky="nsew"
            )
            name_cell = ctk.CTkFrame(table, fg_color=row_bg, corner_radius=0)
            name_cell.grid(row=row_index, column=0, sticky="nsew", padx=(4, 0), pady=2)
            self.app_icon(name_cell, "document", color=PRIMARY,
                          background=row_bg, size=18).pack(side="left", padx=(8, 7), pady=7)
            ctk.CTkLabel(name_cell, text=r["name"], text_color=TEXT,
                         font=("Segoe UI", 10, "bold"), anchor="w",
                         wraplength=220).pack(side="left", fill="x", expand=True, pady=5)
            ctk.CTkLabel(table, text=r["category"], text_color=MUTED,
                         font=BODY_MUTED, anchor="w").grid(
                row=row_index, column=1, sticky="ew", padx=10, pady=8
            )
            ctk.CTkLabel(table, text=r["expiry_date"] or "No expiry", text_color=MUTED,
                         font=BODY_MUTED, anchor="w").grid(
                row=row_index, column=2, sticky="ew", padx=10, pady=8
            )
            status, color = self.status(r["expiry_date"])
            status_text = status
            badge_bg = "#DCFCE7" if color == SUCCESS else "#FEF3C7" if color == WARNING else "#FEE2E2"
            badge = ctk.CTkFrame(table, fg_color=badge_bg, corner_radius=7)
            badge.grid(row=row_index, column=3, sticky="w", padx=7, pady=6)
            ctk.CTkLabel(badge, text=status_text, text_color=color,
                         font=("Segoe UI", 8, "bold")).pack(padx=8, pady=4)
            ctk.CTkLabel(table, text="Selected" if r["is_emergency"] else "Not selected",
                         text_color=PRIMARY if r["is_emergency"] else MUTED,
                         font=("Segoe UI", 9, "bold" if r["is_emergency"] else "normal"),
                         anchor="w").grid(row=row_index, column=4, sticky="ew", padx=8, pady=8)
            actions = ctk.CTkFrame(table, fg_color="transparent")
            actions.grid(row=row_index, column=5, sticky="e", padx=7, pady=5)
            ctk.CTkButton(actions, text="Open", width=52, height=29,
                          fg_color="#ECFEFF", hover_color="#CFFAFE",
                          text_color=PRIMARY, font=("Segoe UI", 9, "bold"),
                          command=lambda rid=r["id"]: self.open_document(rid)).pack(side="left", padx=2)
            ctk.CTkButton(actions, text="Delete", width=54, height=29,
                          fg_color="#FEF2F2", hover_color="#FEE2E2",
                          text_color=DANGER, font=("Segoe UI", 9, "bold"),
                          command=lambda rid=r["id"]: self.delete_document(rid)).pack(side="left", padx=2)

    def status(self, expiry):
        if not expiry:
            return "ACTIVE", SUCCESS
        try:
            days = (datetime.strptime(expiry, "%Y-%m-%d").date() - date.today()).days
            if days < 0:
                return "EXPIRED", DANGER
            if days <= 30:
                return "EXPIRING SOON", WARNING
            return "ACTIVE", SUCCESS
        except ValueError:
            return "CHECK DATE", WARNING

    def add_document(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("Add Document")
        dlg.geometry("560x650")
        dlg.minsize(500, 580)
        dlg.configure(fg_color="#F5F7FB")
        dlg.grab_set()
        card = ctk.CTkFrame(dlg, fg_color=CARD, corner_radius=14,
                            border_width=1, border_color=BORDER)
        card.pack(fill="both", expand=True, padx=24, pady=22)
        ctk.CTkLabel(card, text="Add Document", text_color=TEXT,
                     font=("Segoe UI", 21, "bold")).pack(pady=(19, 2))
        ctk.CTkLabel(card, text="Add a record and optionally attach a file.",
                     text_color=MUTED, font=("Segoe UI", 10)).pack(pady=(0, 12))

        name = ctk.CTkEntry(card, width=420, height=42, placeholder_text="Document Name",
                            font=("Segoe UI", 10), border_color="#D7E2ED")
        name.pack(pady=5)
        category = ctk.CTkComboBox(card, width=420, height=42, values=CATEGORIES,
                                   font=("Segoe UI", 10), border_color="#D7E2ED",
                                   button_color="#E8EEF5", button_hover_color="#DCE6F0")
        category.set("Identity")
        category.pack(pady=5)
        expiry = ctk.CTkEntry(card, width=420, height=42,
                      placeholder_text="Expiry Date (YYYY-MM-DD) - optional",
                              font=("Segoe UI", 10), border_color="#D7E2ED")
        expiry.pack(pady=5)

        emergency_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(card, text="Include in Emergency Pack", variable=emergency_var,
                        font=("Segoe UI", 10), checkbox_width=17, checkbox_height=17,
                        border_width=2, corner_radius=4, text_color=TEXT,
                        fg_color=PRIMARY, hover_color=PRIMARY_HOVER).pack(anchor="w", padx=44, pady=7)

        chosen = {"path": None}
        file_label = ctk.CTkLabel(card, text="No file selected", text_color=MUTED,
                      font=("Segoe UI", 9))
        file_label.pack(pady=(4, 7))

        def choose():
            p = filedialog.askopenfilename()
            if p:
                chosen["path"] = p
                file_label.configure(text=Path(p).name, text_color=SUCCESS)

        file_row = ctk.CTkFrame(card, width=420, height=42, fg_color="#FFFFFF",
                    corner_radius=9, border_width=1, border_color="#CBD5E1")
        file_row.pack(pady=4)
        file_row.pack_propagate(False)
        self.app_icon(file_row, "document", color=PRIMARY, background="#FFFFFF",
                  size=19).pack(side="left", padx=(12, 7))
        ctk.CTkButton(file_row, text="Select File", height=36,
                  fg_color="transparent", hover_color="#ECFEFF",
                  text_color=PRIMARY, font=("Segoe UI", 10, "bold"),
                  command=choose).pack(side="left", fill="both", expand=True, padx=3, pady=2)

        ctk.CTkLabel(card, text="Selected attachments are encrypted inside your local vault.",
                 text_color=MUTED, font=("Segoe UI", 9)).pack(pady=(4, 8))

        def save():
            n = name.get().strip()
            cat = category.get()
            exp = expiry.get().strip()
            src = chosen["path"]
            if not n:
                messagebox.showerror("Missing information", "Enter a document name.", parent=dlg)
                return
            if exp:
                try:
                    datetime.strptime(exp, "%Y-%m-%d")
                except ValueError:
                    messagebox.showerror("Invalid date", "Use YYYY-MM-DD.", parent=dlg)
                    return
            try:
                stored_path = ""
                original_name = "No file attached"
                if src:
                    uid_dir = VAULT_DIR / str(self.user["id"])
                    uid_dir.mkdir(exist_ok=True)
                    dst = uid_dir / (secrets.token_hex(10) + ".lvault")
                    encrypt_file(src, dst, self.fernet_key)
                    stored_path = str(dst)
                    original_name = Path(src).name
                self.db.execute("""INSERT INTO documents
                    (user_id,name,category,stored_path,original_name,expiry_date,is_emergency,created_at)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (self.user["id"], n, cat, stored_path, original_name, exp or None,
                     int(emergency_var.get()), now()))
                self.audit("DOCUMENT_ADDED", n)
                dlg.destroy()
                self.show_documents()
            except Exception as e:
                messagebox.showerror("Could not save", str(e), parent=dlg)

        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.pack(fill="x", padx=42, pady=(6, 16))
        ctk.CTkButton(actions, text="Cancel", height=40, fg_color="#F1F5F9",
                  hover_color=BORDER, text_color=TEXT,
                  font=("Segoe UI", 10, "bold"), command=dlg.destroy).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(actions, text="Save Document", height=40, fg_color=PRIMARY,
                  hover_color=PRIMARY_HOVER, font=("Segoe UI", 10, "bold"),
                  command=save).pack(side="left", fill="x", expand=True, padx=(5, 0))

    def open_document(self, rid):
        r = self.db.execute("SELECT * FROM documents WHERE id=? AND user_id=?", (rid, self.user["id"]), fetch=True, one=True)
        if not r:
            messagebox.showerror("Document unavailable", "This document record could not be found.")
            return
        if not r["stored_path"]:
            messagebox.showinfo("No file attached", "This record has no attached file.")
            return
        try:
            suffix = Path(r["original_name"]).suffix or ".bin"
            fd, temp = tempfile.mkstemp(prefix="lifevault_", suffix=suffix, dir=TEMP_DIR)
            os.close(fd)
            decrypt_file(r["stored_path"], temp, self.fernet_key)
            self.temp_files.append(temp)
            self.audit("DOCUMENT_OPENED", r["name"])
            open_path(temp)
        except Exception as e:
            messagebox.showerror("Unable to open", f"The document could not be decrypted.\n\n{e}")

    def delete_document(self, rid):
        r = self.db.execute("SELECT * FROM documents WHERE id=? AND user_id=?", (rid, self.user["id"]), fetch=True, one=True)
        if not r:
            return
        if not messagebox.askyesno("Delete document", f"Delete '{r['name']}' permanently?"):
            return
        try:
            Path(r["stored_path"]).unlink(missing_ok=True)
        except Exception:
            pass
        self.db.execute("DELETE FROM documents WHERE id=? AND user_id=?", (rid, self.user["id"]))
        self.audit("DOCUMENT_DELETED", r["name"])
        self.show_documents()

    # ---------------- CONTACTS ----------------

    def show_contacts(self):
        main = self.page("Emergency Contacts", "Keep trusted contacts ready when needed.")
        toolbar = ctk.CTkFrame(main, fg_color="transparent")
        toolbar.pack(fill="x", padx=24, pady=(8, 10))
        ctk.CTkButton(toolbar, text="Add Contact", height=40, corner_radius=9,
                      fg_color=PRIMARY, hover_color=PRIMARY_HOVER,
                      font=("Segoe UI", 10, "bold"),
                      command=self.add_contact).pack(side="right")
        scroll = ctk.CTkScrollableFrame(main, fg_color="transparent",
                                        scrollbar_button_color="#CBD5E1",
                                        scrollbar_button_hover_color="#94A3B8")
        scroll.pack(fill="both", expand=True, padx=22, pady=(0, 16))
        rows = self.db.execute("SELECT * FROM contacts WHERE user_id=? ORDER BY id DESC", (self.user["id"],), fetch=True)
        if not rows:
            empty = ctk.CTkFrame(scroll, fg_color=CARD, corner_radius=12,
                                 border_width=1, border_color=BORDER)
            empty.pack(fill="x", pady=5)
            ctk.CTkLabel(empty, text="No emergency contacts added yet.",
                         text_color=MUTED, font=("Segoe UI", 11)).pack(pady=26)
        for r in rows:
            card = ctk.CTkFrame(scroll, fg_color=CARD, corner_radius=12,
                                border_width=1, border_color=BORDER)
            card.pack(fill="x", pady=5)
            icon_bg = ctk.CTkFrame(card, width=44, height=44, fg_color="#ECFEFF",
                                   corner_radius=12)
            icon_bg.pack(side="left", padx=(15, 11), pady=12)
            icon_bg.pack_propagate(False)
            self.app_icon(icon_bg, "contacts", color=PRIMARY,
                          background="#ECFEFF", size=22).place(relx=.5, rely=.5, anchor="center")
            details = ctk.CTkFrame(card, fg_color="transparent")
            details.pack(side="left", fill="x", expand=True, pady=10)
            ctk.CTkLabel(details, text=r["name"], text_color=TEXT,
                         font=("Segoe UI", 12, "bold"), anchor="w").pack(anchor="w")
            ctk.CTkLabel(details, text=f"{r['relation'] or 'Contact'}  ·  {r['phone']}",
                         text_color=MUTED, font=("Segoe UI", 10), anchor="w").pack(anchor="w", pady=(2, 0))
            badge = ctk.CTkFrame(details, fg_color="#ECFDF5", corner_radius=6)
            badge.pack(anchor="w", pady=(5, 0))
            ctk.CTkLabel(badge, text="Emergency contact" if r["is_emergency"] else "Contact",
                         text_color="#15803D" if r["is_emergency"] else MUTED,
                         font=("Segoe UI", 8, "bold")).pack(padx=7, pady=2)
            actions = ctk.CTkFrame(card, fg_color="transparent")
            actions.pack(side="right", padx=12)
            ctk.CTkButton(actions, text="Call", width=58, height=32,
                          fg_color="#ECFEFF", hover_color="#CFFAFE",
                          text_color=PRIMARY, font=("Segoe UI", 9, "bold"),
                          command=lambda phone=r["phone"]: self.call_contact(phone)).pack(side="left", padx=2)
            ctk.CTkButton(actions, text="Edit", width=56, height=32,
                          fg_color="#F1F5F9", hover_color=BORDER,
                          text_color=TEXT, font=("Segoe UI", 9, "bold"),
                          command=lambda rid=r["id"]: self.add_contact(rid)).pack(side="left", padx=2)
            ctk.CTkButton(actions, text="Delete", width=58, height=32,
                          fg_color="#FEF2F2", hover_color="#FEE2E2",
                          text_color=DANGER, font=("Segoe UI", 9, "bold"),
                          command=lambda rid=r["id"]: self.delete_contact(rid)).pack(side="left", padx=2)

    def call_contact(self, phone):
        try:
            webbrowser.open(f"tel:{phone}")
        except Exception as exc:
            messagebox.showerror("Unable to open phone action", str(exc))

    def add_contact(self, contact_id=None):
        contact = None
        if contact_id is not None:
            contact = self.db.execute("SELECT * FROM contacts WHERE id=? AND user_id=?",
                                      (contact_id, self.user["id"]), fetch=True, one=True)
            if not contact:
                messagebox.showerror("Contact unavailable", "This contact could not be found.")
                return
        dlg = ctk.CTkToplevel(self)
        dlg.title("Edit Emergency Contact" if contact else "Add Emergency Contact")
        dlg.geometry("520x500")
        dlg.configure(fg_color="#F5F7FB")
        dlg.grab_set()
        card = ctk.CTkFrame(dlg, fg_color=CARD, corner_radius=14,
                    border_width=1, border_color=BORDER)
        card.pack(fill="both", expand=True, padx=24, pady=24)
        ctk.CTkLabel(card, text="Edit emergency contact" if contact else "Add emergency contact",
                 text_color=TEXT, font=("Segoe UI", 20, "bold")).pack(pady=(24, 4))
        ctk.CTkLabel(card, text="Keep important contact details together.",
                 text_color=MUTED, font=("Segoe UI", 10)).pack(pady=(0, 14))
        name = ctk.CTkEntry(card, width=390, height=44, placeholder_text="Name",
                    font=("Segoe UI", 11), border_color="#D7E2ED")
        name.pack(pady=6)
        phone = ctk.CTkEntry(card, width=390, height=44, placeholder_text="Phone number",
                     font=("Segoe UI", 11), border_color="#D7E2ED")
        phone.pack(pady=6)
        relation = ctk.CTkEntry(card, width=390, height=44, placeholder_text="Relationship",
                    font=("Segoe UI", 11), border_color="#D7E2ED")
        relation.pack(pady=6)
        if contact:
            name.insert(0, contact["name"])
            phone.insert(0, contact["phone"])
            relation.insert(0, contact["relation"] or "")

        def save():
            if not name.get().strip() or not phone.get().strip():
                messagebox.showerror("Required", "Name and phone are required.", parent=dlg)
                return
            if contact:
                self.db.execute("UPDATE contacts SET name=?,phone=?,relation=? WHERE id=? AND user_id=?",
                                (name.get().strip(), phone.get().strip(), relation.get().strip(), contact_id, self.user["id"]))
                self.audit("CONTACT_UPDATED", name.get().strip())
            else:
                self.db.execute("INSERT INTO contacts(user_id,name,phone,relation,created_at) VALUES(?,?,?,?,?)",
                                (self.user["id"], name.get().strip(), phone.get().strip(), relation.get().strip(), now()))
                self.audit("CONTACT_ADDED", name.get().strip())
            dlg.destroy()
            self.show_contacts()

        ctk.CTkButton(card, text="Save Contact", width=390, height=44,
                  fg_color=PRIMARY, hover_color=PRIMARY_HOVER,
                  font=("Segoe UI", 11, "bold"), command=save).pack(pady=(18, 24))

    def delete_contact(self, rid):
        r = self.db.execute("SELECT name FROM contacts WHERE id=? AND user_id=?", (rid, self.user["id"]), fetch=True, one=True)
        if not r or not messagebox.askyesno("Delete contact", f"Remove {r['name']}?"):
            return
        self.db.execute("DELETE FROM contacts WHERE id=? AND user_id=?", (rid, self.user["id"]))
        self.audit("CONTACT_DELETED", r["name"])
        self.show_contacts()

    # ---------------- READINESS ----------------

    def show_readiness(self):
        main = self.page("Emergency Readiness", "Track how prepared your LifeVault is.")
        score, checks = self.readiness_score()
        body = ctk.CTkScrollableFrame(main, fg_color="transparent",
                                      scrollbar_button_color="#CBD5E1",
                                      scrollbar_button_hover_color="#94A3B8")
        body.pack(fill="both", expand=True, padx=23, pady=(12, 16))
        score_card = ctk.CTkFrame(body, fg_color=CARD, corner_radius=RADIUS,
                                  border_width=1, border_color=BORDER)
        score_card.pack(fill="x", pady=(0, 13))
        self.ui_card_header(score_card, "Your readiness overview")
        score_row = ctk.CTkFrame(score_card, fg_color="transparent")
        score_row.pack(fill="x", padx=17, pady=(0, 16))
        ring = Canvas(score_row, width=104, height=104, bg=CARD, highlightthickness=0)
        ring.pack(side="left", padx=(3, 18), pady=(0, 2))
        ring.create_oval(8, 8, 96, 96, outline="#E7EEF6", width=9)
        arc = ring.create_arc(8, 8, 96, 96, start=90, extent=0,
                              style="arc", outline=PRIMARY, width=9)
        ring.create_text(52, 52, text=f"{score}%", fill=TEXT,
                         font=("Segoe UI", 17, "bold"))
        score_details = ctk.CTkFrame(score_row, fg_color="transparent")
        score_details.pack(side="left", fill="x", expand=True, pady=(0, 4))
        ctk.CTkLabel(score_details, text="Emergency Readiness", text_color=TEXT,
                     font=CARD_TITLE, anchor="w").pack(anchor="w", fill="x")
        ctk.CTkLabel(score_details, text=f"{sum(1 for _, complete, _ in checks if complete)} of {len(checks)} checks complete",
                     text_color=MUTED, font=BODY_MUTED, anchor="w").pack(
            anchor="w", fill="x", pady=(4, 9)
        )
        progress = ctk.CTkProgressBar(score_details, height=9,
                                      progress_color=PRIMARY, fg_color="#E7EEF6")
        progress.set(score / 100)
        progress.pack(fill="x", pady=(0, 3))
        self.animate_ring(ring, arc, score)

        checklist = ctk.CTkFrame(body, fg_color=CARD, corner_radius=RADIUS,
                                 border_width=1, border_color=BORDER)
        checklist.pack(fill="x", pady=(0, 10))
        self.ui_card_header(checklist, "Readiness checklist", hint="Live status")
        labels = {
            "Emergency contact exists": "Emergency Contact",
            "Insurance information exists": "Insurance Information",
            "Vehicle information exists": "Vehicle Information",
            "Documents exist": "Documents Available",
            "At least one valid document": "Valid Documents",
        }
        for label, complete, _weight in checks:
            row = ctk.CTkFrame(checklist, fg_color=CARD_ALT, corner_radius=9)
            row.pack(fill="x", padx=12, pady=3)
            kind = "readiness" if complete else "alert"
            self.app_icon(row, kind, color=SUCCESS if complete else WARNING,
                          background=CARD_ALT, size=18).pack(side="left", padx=(10, 8), pady=8)
            ctk.CTkLabel(row, text=labels.get(label, label), text_color=TEXT,
                         font=("Segoe UI", 10, "bold")).pack(side="left", pady=8)
            ctk.CTkLabel(row, text="Complete" if complete else "Attention needed",
                         text_color=SUCCESS if complete else WARNING,
                         font=("Segoe UI", 9, "bold")).pack(side="right", padx=11)
        ctk.CTkLabel(checklist,
                     text="Readiness Score is a project-defined indicator based on information available in your LifeVault.",
                     text_color=MUTED, font=CAPTION, wraplength=760,
                     justify="left").pack(anchor="w", padx=17, pady=(11, 14))

    # ---------------- EMERGENCY MODE ----------------

    def show_emergency(self):
        self.audit("EMERGENCY_MODE_OPENED", "Emergency information displayed")
        main = self.page("Emergency Mode", "Show only your pre-selected critical information.")
        scroll = ctk.CTkScrollableFrame(main, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=22, pady=(3, 9))

        profile = self.db.execute("SELECT * FROM profile WHERE user_id=?", (self.user["id"],), fetch=True, one=True)
        contacts = self.db.execute("SELECT * FROM contacts WHERE user_id=? AND is_emergency=1", (self.user["id"],), fetch=True)
        docs = self.db.execute("SELECT * FROM documents WHERE user_id=? AND is_emergency=1", (self.user["id"],), fetch=True)

        identity = ctk.CTkFrame(scroll, fg_color="#ECFEFF", corner_radius=12,
                                border_width=1, border_color="#A5F3FC")
        identity.pack(fill="x", pady=(0, 10))
        identity_row = ctk.CTkFrame(identity, fg_color="transparent")
        identity_row.pack(fill="x", padx=17, pady=14)
        self.app_icon(identity_row, "alert", color=PRIMARY, background="#ECFEFF",
                      size=24).pack(side="left", padx=(0, 11))
        identity_text = ctk.CTkFrame(identity_row, fg_color="transparent")
        identity_text.pack(side="left", fill="x", expand=True)
        display_name = (profile["full_name"] if profile and profile["full_name"] else self.user["name"])
        ctk.CTkLabel(identity_text, text=display_name, text_color=TEXT,
                     font=("Segoe UI", 17, "bold")).pack(anchor="w")
        ctk.CTkLabel(identity_text, text="Emergency information at a glance",
                     text_color=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))

        if profile:
            profile_items = [("Blood group", profile["blood_group"]),
                             ("Allergies", profile["allergies"]),
                             ("Vehicle", profile["vehicle_number"]),
                             ("Insurance", profile["insurance_info"])]
            profile_items = [(label, value) for label, value in profile_items if value]
            if profile_items:
                details_card = ctk.CTkFrame(scroll, fg_color=CARD, corner_radius=12,
                                            border_width=1, border_color=BORDER)
                details_card.pack(fill="x", pady=5)
                self.em_section(details_card, "Personal and Vehicle Details")
                details_grid = ctk.CTkFrame(details_card, fg_color="transparent")
                details_grid.pack(fill="x", padx=14, pady=(0, 12))
                for index, (label, value) in enumerate(profile_items):
                    cell = ctk.CTkFrame(details_grid, fg_color="#F8FAFC", corner_radius=8)
                    cell.grid(row=index // 2, column=index % 2, sticky="ew", padx=4, pady=4)
                    details_grid.grid_columnconfigure(index % 2, weight=1)
                    ctk.CTkLabel(cell, text=label, text_color=MUTED,
                                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=11, pady=(8, 2))
                    ctk.CTkLabel(cell, text=value, text_color=TEXT,
                                 font=("Segoe UI", 11), wraplength=310,
                                 justify="left").pack(anchor="w", padx=11, pady=(0, 8))

        contacts_card = ctk.CTkFrame(scroll, fg_color=CARD, corner_radius=12,
                                     border_width=1, border_color=BORDER)
        contacts_card.pack(fill="x", pady=5)
        self.em_section(contacts_card, "Emergency Contacts")
        if contacts:
            for r in contacts:
                row = ctk.CTkFrame(contacts_card, fg_color="#F8FAFC", corner_radius=8)
                row.pack(fill="x", padx=12, pady=4)
                details = ctk.CTkFrame(row, fg_color="transparent")
                details.pack(side="left", fill="x", expand=True, padx=11, pady=8)
                ctk.CTkLabel(details, text=r["name"], text_color=TEXT,
                             font=("Segoe UI", 11, "bold")).pack(anchor="w")
                ctk.CTkLabel(details, text=f"{r['relation'] or 'Contact'}  ·  {r['phone']}",
                             text_color=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))
                ctk.CTkButton(row, text="Call", width=66, height=32,
                              fg_color=PRIMARY, hover_color=PRIMARY_HOVER,
                              font=("Segoe UI", 9, "bold"),
                              command=lambda phone=r["phone"]: self.call_contact(phone)).pack(side="right", padx=10)
        else:
            ctk.CTkLabel(contacts_card, text="No emergency contacts selected.",
                         text_color=MUTED, font=("Segoe UI", 10)).pack(anchor="w", padx=15, pady=(0, 14))

        documents_card = ctk.CTkFrame(scroll, fg_color=CARD, corner_radius=12,
                                      border_width=1, border_color=BORDER)
        documents_card.pack(fill="x", pady=5)
        self.em_section(documents_card, "Important Documents")
        if docs:
            for r in docs:
                status, _ = self.status(r["expiry_date"])
                status_text = status
                row = ctk.CTkFrame(documents_card, fg_color="#F8FAFC", corner_radius=8)
                row.pack(fill="x", padx=12, pady=4)
                details = ctk.CTkFrame(row, fg_color="transparent")
                details.pack(side="left", fill="x", expand=True, padx=11, pady=8)
                ctk.CTkLabel(details, text=r["name"], text_color=TEXT,
                             font=("Segoe UI", 10, "bold")).pack(anchor="w")
                ctk.CTkLabel(details, text=f"{r['category']}  ·  {r['expiry_date'] or 'No expiry'}  ·  {status_text}",
                             text_color=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))
                ctk.CTkButton(row, text="Open", width=58, height=30,
                              fg_color="#ECFEFF", hover_color="#CFFAFE",
                              text_color=PRIMARY, font=("Segoe UI", 9, "bold"),
                              command=lambda rid=r["id"]: self.open_document(rid)).pack(side="right", padx=10)
        else:
            ctk.CTkLabel(documents_card, text="No documents selected for Emergency Pack.",
                         text_color=MUTED, font=("Segoe UI", 10)).pack(anchor="w", padx=15, pady=(0, 14))

        instruction = (profile["emergency_instructions"] if profile else "") or "No emergency instructions configured."
        if profile and profile["emergency_instructions"]:
            instructions_card = ctk.CTkFrame(scroll, fg_color=CARD, corner_radius=12,
                                             border_width=1, border_color=BORDER)
            instructions_card.pack(fill="x", pady=5)
            self.em_section(instructions_card, "Emergency Instructions")
            ctk.CTkLabel(instructions_card, text=instruction, text_color=TEXT,
                         wraplength=850, justify="left",
                         font=("Segoe UI", 10)).pack(anchor="w", padx=15, pady=(0, 14))

        ctk.CTkButton(main, text="Exit Emergency Mode", width=190, height=40,
                  fg_color="#FFFFFF", hover_color="#CFFAFE", text_color=PRIMARY,
                  font=("Segoe UI", 10, "bold"),
                  command=lambda: self.navigate(self.show_dashboard)).pack(pady=14)

    def em_section(self, parent, title, hint=None):
        head = ctk.CTkFrame(parent, fg_color="transparent")
        head.pack(fill="x", padx=15, pady=(14, 8))
        bar = ctk.CTkFrame(head, width=3, height=14, fg_color=ACCENT,
                           corner_radius=2)
        bar.pack(side="left", padx=(0, 9), pady=1)
        ctk.CTkLabel(head, text=title, font=CARD_TITLE, text_color=TEXT,
                     anchor="w").pack(side="left")
        if hint:
            ctk.CTkLabel(head, text=hint, font=CAPTION, text_color=MUTED,
                         anchor="e").pack(side="right")
        return head

    # ---------------- PACK ----------------

    def show_pack(self):
        main = self.page("Emergency Pack", "Your pre-selected emergency information in one place.")
        body = ctk.CTkScrollableFrame(main, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=22, pady=(3, 15))
        profile = self.db.execute("SELECT * FROM profile WHERE user_id=?", (self.user["id"],), fetch=True, one=True)
        contacts = self.db.execute("SELECT * FROM contacts WHERE user_id=? AND is_emergency=1 ORDER BY id",
                                   (self.user["id"],), fetch=True)
        profile_card = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12,
                                    border_width=1, border_color=BORDER)
        profile_card.pack(fill="x", pady=5)
        self.em_section(profile_card, "Emergency Profile")
        ctk.CTkLabel(profile_card, text=profile["full_name"] if profile and profile["full_name"] else self.user["name"],
                     text_color=TEXT, font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=15, pady=(0, 4))
        if profile:
            for label, value in (("Blood group", profile["blood_group"]),
                                 ("Allergies", profile["allergies"]),
                                 ("Vehicle", profile["vehicle_number"]),
                                 ("Insurance", profile["insurance_info"]),
                                 ("Instructions", profile["emergency_instructions"])):
                if value:
                    ctk.CTkLabel(profile_card, text=f"{label}: {value}", text_color=MUTED,
                                 wraplength=850, justify="left", font=("Segoe UI", 9)).pack(anchor="w", padx=15, pady=2)
        contacts_card = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12,
                                     border_width=1, border_color=BORDER)
        contacts_card.pack(fill="x", pady=5)
        self.em_section(contacts_card, "Emergency Contacts")
        if contacts:
            for contact in contacts:
                row = ctk.CTkFrame(contacts_card, fg_color="#F8FAFC", corner_radius=8)
                row.pack(fill="x", padx=12, pady=3)
                ctk.CTkLabel(row, text=f"{contact['name']}  ·  {contact['relation'] or 'Contact'}  ·  {contact['phone']}",
                             text_color=TEXT, font=("Segoe UI", 10)).pack(side="left", fill="x", expand=True, padx=11, pady=9)
                ctk.CTkButton(row, text="Call", width=60, height=30,
                              fg_color="#ECFEFF", hover_color="#CFFAFE", text_color=PRIMARY,
                              font=("Segoe UI", 9, "bold"),
                              command=lambda phone=contact["phone"]: self.call_contact(phone)).pack(side="right", padx=8)
        else:
            ctk.CTkLabel(contacts_card, text="No emergency contacts added.", text_color=MUTED,
                         font=("Segoe UI", 10)).pack(anchor="w", padx=15, pady=(0, 13))

        rows = self.db.execute("SELECT * FROM documents WHERE user_id=? AND is_emergency=1 ORDER BY id DESC",
                               (self.user["id"],), fetch=True)
        documents_card = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12,
                                      border_width=1, border_color=BORDER)
        documents_card.pack(fill="x", pady=5)
        self.em_section(documents_card, "Selected Documents")
        if rows:
            for document in rows:
                status, _ = self.status(document["expiry_date"])
                status_text = status
                row = ctk.CTkFrame(documents_card, fg_color="#F8FAFC", corner_radius=8)
                row.pack(fill="x", padx=12, pady=3)
                ctk.CTkLabel(row, text=f"{document['name']}  ·  {document['category']}  ·  {status_text}",
                             text_color=TEXT, font=("Segoe UI", 9), anchor="w").pack(side="left", fill="x", expand=True, padx=10, pady=9)
                ctk.CTkButton(row, text="Open", width=58, height=30,
                              fg_color="#ECFEFF", hover_color="#CFFAFE", text_color=PRIMARY,
                              font=("Segoe UI", 9, "bold"),
                              command=lambda rid=document["id"]: self.open_document(rid)).pack(side="right", padx=8)
        else:
            ctk.CTkLabel(documents_card, text="No critical documents selected.",
                         text_color=MUTED, font=("Segoe UI", 10)).pack(anchor="w", padx=15, pady=(0, 13))

        ctk.CTkButton(body, text="Activate Emergency Mode", height=42, width=210,
                      fg_color=DANGER, hover_color="#B91C1C",
                      font=("Segoe UI", 10, "bold"),
                      command=self.show_emergency).pack(anchor="w", pady=(10, 6))

    # ---------------- SETTINGS ----------------

    def show_settings(self):
        main = self.page("Settings", "Manage account details, emergency profile, and local security.")
        scroll = ctk.CTkScrollableFrame(main, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=22, pady=(3, 15))

        profile = self.db.execute("SELECT * FROM profile WHERE user_id=?", (self.user["id"],), fetch=True, one=True)
        if not profile:
            self.db.execute("INSERT INTO profile(user_id, full_name) VALUES(?,?)",
                            (self.user["id"], self.user["name"]))
            profile = self.db.execute("SELECT * FROM profile WHERE user_id=?",
                                      (self.user["id"],), fetch=True, one=True)

        compact = self.content_host.winfo_width() / ctk.ScalingTracker.get_widget_scaling(self) < 760
        top = ctk.CTkFrame(scroll, fg_color="transparent")
        top.pack(fill="x", pady=(0, 8))
        account_card = ctk.CTkFrame(top, fg_color=CARD, corner_radius=12,
                                    border_width=1, border_color=BORDER)
        security_card = ctk.CTkFrame(top, fg_color=CARD, corner_radius=12,
                                     border_width=1, border_color=BORDER)
        if compact:
            account_card.pack(fill="x", pady=(0, 8))
            security_card.pack(fill="x")
        else:
            account_card.pack(side="left", fill="both", expand=True, padx=(0, 6))
            security_card.pack(side="left", fill="both", expand=True, padx=(6, 0))

        self.em_section(account_card, "Account")
        for label, value in (("Name", self.user["name"]), ("Email", self.user["email"])):
            row = ctk.CTkFrame(account_card, fg_color="#F8FAFC", corner_radius=8)
            row.pack(fill="x", padx=12, pady=3)
            ctk.CTkLabel(row, text=label, text_color=MUTED,
                         font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(7, 1))
            ctk.CTkLabel(row, text=value, text_color=TEXT,
                         font=("Segoe UI", 10)).pack(anchor="w", padx=10, pady=(0, 7))

        self.em_section(security_card, "Security")
        ctk.CTkLabel(security_card,
                     text="Master passwords are protected with salted PBKDF2 hashes. Document files are encrypted in your local vault.",
                     text_color=MUTED, font=("Segoe UI", 9), wraplength=380,
                     justify="left").pack(anchor="w", padx=14, pady=(0, 7))
        ctk.CTkLabel(security_card, text="Auto-lock after 15 minutes of inactivity.",
                     text_color=MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=14, pady=(0, 8))
        ctk.CTkLabel(
            security_card,
            text="Password recovery is available from the Login screen with your recovery code.",
            text_color=PRIMARY, font=("Segoe UI", 9, "bold"),
            wraplength=380, justify="left"
        ).pack(anchor="w", padx=13, pady=(0, 12))

        pcard = ctk.CTkFrame(scroll, fg_color=CARD, corner_radius=12,
                             border_width=1, border_color=BORDER)
        pcard.pack(fill="x", pady=5)
        self.em_section(pcard, "Emergency Profile")

        full_name = ctk.CTkEntry(pcard, width=500, height=40, placeholder_text="Full name",
                                 font=("Segoe UI", 10), border_color="#D7E2ED")
        full_name.insert(0, profile["full_name"] or self.user["name"])
        full_name.pack(anchor="w", padx=15, pady=4)

        blood = ctk.CTkEntry(pcard, width=400, height=40, placeholder_text="Blood group",
                             font=("Segoe UI", 10), border_color="#D7E2ED")
        blood.insert(0, profile["blood_group"] or "")
        blood.pack(anchor="w", padx=15, pady=4)

        allergies = ctk.CTkEntry(pcard, width=700, height=40, placeholder_text="Allergies / important medical notes",
                                 font=("Segoe UI", 10), border_color="#D7E2ED")
        allergies.insert(0, profile["allergies"] or "")
        allergies.pack(anchor="w", padx=15, pady=4)

        vehicle = ctk.CTkEntry(pcard, width=500, height=40, placeholder_text="Vehicle registration number",
                               font=("Segoe UI", 10), border_color="#D7E2ED")
        vehicle.insert(0, profile["vehicle_number"] or "")
        vehicle.pack(anchor="w", padx=15, pady=4)

        insurance = ctk.CTkEntry(pcard, width=700, height=40,
                                 placeholder_text="Insurance provider / policy information",
                                 font=("Segoe UI", 10), border_color="#D7E2ED")
        insurance.insert(0, profile["insurance_info"] or "")
        insurance.pack(anchor="w", padx=15, pady=4)

        instructions = ctk.CTkTextbox(pcard, width=800, height=88,
                                      font=("Segoe UI", 10), border_color="#D7E2ED")
        instructions.insert("1.0", profile["emergency_instructions"] or "")
        instructions.pack(anchor="w", padx=15, pady=6)

        def save_profile():
            profile_values = (
                full_name.get().strip(), blood.get().strip(), allergies.get().strip(),
                vehicle.get().strip(), insurance.get().strip(),
                instructions.get("1.0", "end").strip(), self.user["id"]
            )
            self.db.execute(
                "UPDATE profile SET full_name=?, blood_group=?, allergies=?, vehicle_number=?, insurance_info=?, emergency_instructions=? WHERE user_id=?",
                profile_values
            )
            self.audit("PROFILE_UPDATED", "Emergency profile updated")
            messagebox.showinfo("Saved", "Emergency profile updated.")

        ctk.CTkButton(pcard, text="Save Emergency Profile", height=38,
                      fg_color=PRIMARY, hover_color=PRIMARY_HOVER,
                      font=("Segoe UI", 10, "bold"), command=save_profile).pack(
            anchor="w", padx=15, pady=(5, 15)
        )

        controls = ctk.CTkFrame(scroll, fg_color="transparent")
        controls.pack(fill="x", pady=5)
        vault_card = ctk.CTkFrame(controls, fg_color=CARD, corner_radius=12,
                                  border_width=1, border_color=BORDER)
        app_card = ctk.CTkFrame(controls, fg_color=CARD, corner_radius=12,
                                border_width=1, border_color=BORDER)
        if compact:
            vault_card.pack(fill="x", pady=(0, 8))
            app_card.pack(fill="x")
        else:
            vault_card.pack(side="left", fill="both", expand=True, padx=(0, 6))
            app_card.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.em_section(vault_card, "Vault")
        ctk.CTkButton(vault_card, text="Lock Vault", height=36,
                      fg_color="#1E293B", hover_color="#334155",
                      font=("Segoe UI", 9, "bold"),
                      command=self.confirm_lock).pack(fill="x", padx=13, pady=(0, 8))
        ctk.CTkLabel(vault_card,
                     text="Your recovery code is shown once. Keep it stored safely; without it and your password the encrypted vault cannot be recovered.",
                     text_color=MUTED, font=("Segoe UI", 9), wraplength=340,
                     justify="left").pack(anchor="w", padx=13, pady=(0, 13))
        self.em_section(app_card, "Application")
        ctk.CTkLabel(app_card, text="LifeVault · Local document and emergency information manager",
                     text_color=MUTED, font=("Segoe UI", 9), wraplength=340,
                     justify="left").pack(anchor="w", padx=13, pady=(0, 9))
        ctk.CTkButton(app_card, text="Load Demo Data", height=34,
                      fg_color="#ECFEFF", hover_color="#CFFAFE", text_color=PRIMARY,
                      font=("Segoe UI", 9, "bold"),
                      command=self.load_demo_data).pack(anchor="w", padx=13, pady=(0, 7))
        ctk.CTkButton(app_card, text="Reset Local Vault", height=34,
                      fg_color="#FEF2F2", hover_color="#FEE2E2", text_color=DANGER,
                      font=("Segoe UI", 9, "bold"),
                      command=self.reset_local_vault).pack(anchor="w", padx=13, pady=(0, 13))
        ctk.CTkButton(scroll, text="Logout", height=38, width=115,
                      fg_color=DANGER, hover_color="#B91C1C",
                      font=("Segoe UI", 10, "bold"),
                      command=self.confirm_logout).pack(anchor="e", pady=(4, 8))

        acard = ctk.CTkFrame(scroll, fg_color=CARD, corner_radius=18)
        acard.pack(fill="x", pady=5)
        self.em_section(acard, "Recent Activity")
        logs = self.db.execute("SELECT action,details,created_at FROM audit_log WHERE user_id=? ORDER BY id DESC LIMIT 8",
                               (self.user["id"],), fetch=True)
        for r in logs:
            ctk.CTkLabel(acard, text=f"{r['created_at']}  ·  {r['action']}  ·  {r['details'] or ''}",
                         text_color=MUTED, font=("Segoe UI", 9), wraplength=850,
                         justify="left").pack(anchor="w", padx=15, pady=3)
        ctk.CTkLabel(acard, text="College project prototype · local data storage",
                     text_color=MUTED, font=("Segoe UI", 8)).pack(anchor="w", padx=15, pady=(8, 12))

    def reset_local_vault(self):
        if not messagebox.askyesno(
                "Reset local vault",
                "This permanently deletes your account, contacts, profile, activity, and encrypted documents. Continue?"):
            return
        uid = self.user["id"]
        self.db.execute("DELETE FROM users WHERE id=?", (uid,))
        shutil.rmtree(VAULT_DIR / str(uid), ignore_errors=True)
        self.user = None
        self.fernet_key = None
        messagebox.showinfo("Vault deleted", "The local account and its stored documents were deleted.")
        self.show_login()

    def load_demo_data(self):
        if not messagebox.askyesno("Demo data", "Add fictional sample contacts, profile and encrypted document records?"):
            return
        uid = self.user["id"]
        demo_contacts = [
            ("Demo Contact One", "555-0101", "Family"),
            ("Demo Contact Two", "555-0102", "Friend"),
        ]
        for name, phone, relation in demo_contacts:
            exists = self.db.execute("SELECT id FROM contacts WHERE user_id=? AND name=?",
                                     (uid, name), fetch=True, one=True)
            if not exists:
                self.db.execute("INSERT INTO contacts(user_id,name,phone,relation,created_at) VALUES(?,?,?,?,?)",
                                (uid, name, phone, relation, now()))
        self.db.execute("""UPDATE profile SET full_name=?, blood_group=?, allergies=?, vehicle_number=?, insurance_info=?, emergency_instructions=?
                           WHERE user_id=?""",
                        ("Alex Morgan (Demo)", "O+ (Demo)", "None recorded (Demo)", "DEMO-123",
                         "Fictional policy LV-DEMO-2026; insurer details are sample data.",
                         "Demo instructions: contact a trusted person, share your location, and seek appropriate help.", uid))
        demo_dir = VAULT_DIR / str(uid)
        demo_dir.mkdir(exist_ok=True)
        demo_documents = [
            ("Driving Licence (Demo)", "Identity", 420, 1, "Fictional driving licence sample for LifeVault presentation."),
            ("Vehicle Insurance (Demo)", "Insurance", 18, 1, "Fictional insurance policy LV-DEMO-2026. No real personal data."),
            ("Passport (Demo)", "Identity", 1600, 1, "Fictional passport record for LifeVault presentation."),
            ("Vehicle Certificate (Demo)", "Vehicle", None, 1, "Fictional vehicle certificate record for LifeVault presentation."),
        ]
        for name, category, days, critical, contents in demo_documents:
            exists = self.db.execute("SELECT id FROM documents WHERE user_id=? AND name=?",
                                     (uid, name), fetch=True, one=True)
            if exists:
                continue
            source = TEMP_DIR / f"demo_{secrets.token_hex(8)}.txt"
            destination = demo_dir / f"{secrets.token_hex(12)}.lvault"
            try:
                source.write_text(contents + "\n", encoding="utf-8")
                encrypt_file(source, destination, self.fernet_key)
                expiry_date = (date.today() + timedelta(days=days)).isoformat() if days is not None else None
                self.db.execute("""INSERT INTO documents(user_id,name,category,stored_path,original_name,expiry_date,is_emergency,created_at)
                                   VALUES(?,?,?,?,?,?,?,?)""",
                                (uid, name, category, str(destination), name.replace(" ", "_") + ".txt",
                                 expiry_date, critical, now()))
            except Exception as exc:
                destination.unlink(missing_ok=True)
                messagebox.showerror("Demo data error", f"Could not create {name}: {exc}")
                return
            finally:
                source.unlink(missing_ok=True)
        self.audit("DEMO_DATA", "Presentation demo data loaded")
        messagebox.showinfo("Ready", "Fictional demo data is ready. The sample documents are encrypted in the local vault.")
        self.show_dashboard()

    # ---------------- AUDIT ----------------

    def audit(self, action, details=""):
        if self.user:
            self.db.execute("INSERT INTO audit_log(user_id,action,details,created_at) VALUES(?,?,?,?)",
                            (self.user["id"], action, details, now()))


if __name__ == "__main__":
    if Fernet is None:
        print("Missing dependency. Run: pip install customtkinter cryptography")
        raise SystemExit(1)
    app = LifeVault()
    app.mainloop()
