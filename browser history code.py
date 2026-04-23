import sqlite3
import re
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timezone
from pathlib import Path

# ─── Browser profile definitions ───────────────────────────────────────────────
BROWSERS = {
    "Chrome": {
        "icon": "🟡",
        "color": "#f4c430",
        "paths": [
            Path.home() / "AppData/Local/Google/Chrome/User Data/Default/History",
            Path.home() / ".config/google-chrome/Default/History",
            Path.home() / "Library/Application Support/Google/Chrome/Default/History",
        ],
        "db_type": "chromium",
    },
    "Edge": {
        "icon": "🔵",
        "color": "#0078d4",
        "paths": [
            Path.home() / "AppData/Local/Microsoft/Edge/User Data/Default/History",
            Path.home() / ".config/microsoft-edge/Default/History",
            Path.home() / "Library/Application Support/Microsoft Edge/Default/History",
        ],
        "db_type": "chromium",
    },
    "Brave": {
        "icon": "🦁",
        "color": "#fb542b",
        "paths": [
            Path.home() / "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History",
            Path.home() / ".config/BraveSoftware/Brave-Browser/Default/History",
            Path.home() / "Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
        ],
        "db_type": "chromium",
    },
    "Opera": {
        "icon": "🔴",
        "color": "#ff1b2d",
        "paths": [
            Path.home() / "AppData/Roaming/Opera Software/Opera Stable/History",
            Path.home() / ".config/opera/History",
            Path.home() / "Library/Application Support/com.operasoftware.Opera/History",
        ],
        "db_type": "chromium",
    },
    "Firefox": {
        "icon": "🦊",
        "color": "#ff7139",
        "paths": [],          # discovered dynamically
        "db_type": "firefox",
    },
    "Custom…": {
        "icon": "📂",
        "color": "#8b949e",
        "paths": [],
        "db_type": "unknown",
    },
}

def find_firefox_profiles():
    """Return list of Firefox places.sqlite paths across all profiles."""
    candidates = [
        Path.home() / "AppData/Roaming/Mozilla/Firefox/Profiles",
        Path.home() / ".mozilla/firefox",
        Path.home() / "Library/Application Support/Firefox/Profiles",
    ]
    found = []
    for base in candidates:
        if base.is_dir():
            for profile in base.iterdir():
                db = profile / "places.sqlite"
                if db.is_file():
                    found.append(db)
    return found

def auto_detect_path(browser_name: str):
    """Return the first existing history DB path for a browser, or None."""
    info = BROWSERS.get(browser_name, {})
    if browser_name == "Firefox":
        paths = find_firefox_profiles()
    else:
        paths = info.get("paths", [])
    for p in paths:
        if Path(p).is_file():
            return str(p)
    return None

# ─── Chrome epoch helper ───────────────────────────────────────────────────────
def chrome_time_to_dt(chrome_time):
    if not chrome_time:
        return "—"
    try:
        epoch_diff = 11644473600
        ts = chrome_time / 1_000_000 - epoch_diff
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d  %H:%M:%S UTC")
    except Exception:
        return "—"

def firefox_time_to_dt(microseconds):
    """Convert Firefox microseconds-since-epoch to human-readable string."""
    if not microseconds:
        return "—"
    try:
        ts = microseconds / 1_000_000
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d  %H:%M:%S UTC")
    except Exception:
        return "—"

# ─── Core forensic logic ───────────────────────────────────────────────────────
def carve_urls(raw: bytes) -> set:
    urls = re.findall(rb'https?://[^\x00-\x1f\x7f"<> ]{10,}', raw)
    result = set()
    for u in urls:
        try:
            result.add(u.decode("utf-8", errors="ignore"))
        except Exception:
            pass
    return result

def read_chromium_history(db_path: str):
    records = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC"
        )
        for row in cursor.fetchall():
            records.append({
                "url":        row[0] or "",
                "title":      row[1] or "(no title)",
                "visits":     row[2] or 0,
                "last_visit": chrome_time_to_dt(row[3]),
            })
        conn.close()
    except Exception as e:
        records.append({"url": f"ERROR: {e}", "title": "", "visits": 0, "last_visit": "—"})
    return records

def read_firefox_history(db_path: str):
    records = []
    # Firefox keeps places.sqlite locked while running; copy to temp location
    import shutil, tempfile
    tmp = tempfile.mktemp(suffix=".sqlite")
    try:
        shutil.copy2(db_path, tmp)
        conn = sqlite3.connect(tmp)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT p.url, p.title, p.visit_count, p.last_visit_date
            FROM moz_places p
            WHERE p.visit_count > 0
            ORDER BY p.last_visit_date DESC
        """)
        for row in cursor.fetchall():
            records.append({
                "url":        row[0] or "",
                "title":      row[1] or "(no title)",
                "visits":     row[2] or 0,
                "last_visit": firefox_time_to_dt(row[3]),
            })
        conn.close()
    except Exception as e:
        records.append({"url": f"ERROR: {e}", "title": "", "visits": 0, "last_visit": "—"})
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass
    return records

def detect_db_type(db_path: str) -> str:
    """Sniff the DB schema to determine browser type."""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        tables = {r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        if "moz_places" in tables:
            return "firefox"
        if "urls" in tables:
            return "chromium"
    except Exception:
        pass
    return "chromium"  # default fallback

def read_active_history(db_path: str, db_type: str = None):
    if db_type is None:
        db_type = detect_db_type(db_path)
    if db_type == "firefox":
        return read_firefox_history(db_path)
    return read_chromium_history(db_path)

def run_analysis(db_path: str, db_type: str = None):
    with open(db_path, "rb") as f:
        raw = f.read()
    carved = carve_urls(raw)
    active_records = read_active_history(db_path, db_type)
    active_urls = {r["url"] for r in active_records}
    deleted_urls = carved - active_urls
    return active_records, sorted(deleted_urls)

# ─── GUI ───────────────────────────────────────────────────────────────────────
BG_DARK   = "#0d1117"
BG_PANEL  = "#161b22"
BG_CARD   = "#1c2433"
BG_HOVER  = "#21262d"
ACCENT    = "#00c9a7"
ACCENT2   = "#f78166"
BORDER    = "#30363d"
TEXT_PRI  = "#e6edf3"
TEXT_SEC  = "#8b949e"
TEXT_WARN = "#f0883e"
TEXT_INFO = "#58a6ff"
TEXT_DEL  = "#ff7b72"
FONT_MONO = ("Courier New", 10)
FONT_SANS = ("Segoe UI", 10)
FONT_HEAD = ("Segoe UI", 9, "bold")

class ForensicApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BrowseTrace — Browser Forensic Analyser")
        self.configure(bg=BG_DARK)
        self.geometry("1280x820")
        self.minsize(960, 640)
        self._db_path = tk.StringVar()
        self._filter_active = tk.StringVar()
        self._filter_deleted = tk.StringVar()
        self._active_records = []
        self._deleted_urls   = []
        self._selected_browser = tk.StringVar(value="Chrome")
        self._db_type_override = None   # set when user manually picks a file
        self._build_ui()
        self._on_browser_change("Chrome")

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_topbar()
        self._build_browser_bar()
        self._build_statusbar()
        self._build_main()

    def _build_topbar(self):
        bar = tk.Frame(self, bg=BG_PANEL, height=52)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        tk.Label(bar, text="🔍", bg=BG_PANEL, fg=ACCENT,
                 font=("Segoe UI Emoji", 20)).pack(side="left", padx=(16, 6), pady=8)
        tk.Label(bar, text="BrowseTrace", bg=BG_PANEL, fg=TEXT_PRI,
                 font=("Segoe UI", 15, "bold")).pack(side="left")
        tk.Label(bar, text="  Browser Forensic Analyser", bg=BG_PANEL, fg=TEXT_SEC,
                 font=("Segoe UI", 10)).pack(side="left")

        btn_kw = dict(bg=BG_CARD, fg=TEXT_PRI, activebackground=BG_HOVER,
                      activeforeground=TEXT_PRI, relief="flat", bd=0,
                      font=FONT_SANS, cursor="hand2", padx=12, pady=5)

        tk.Button(bar, text="▶  Analyse", command=self._run,
                  **{**btn_kw, "fg": ACCENT}).pack(side="right", padx=(0, 12), pady=8)
        tk.Button(bar, text="📂  Browse…", command=self._browse,
                  **btn_kw).pack(side="right", padx=(0, 4), pady=8)

        entry_frame = tk.Frame(bar, bg=BORDER, bd=0)
        entry_frame.pack(side="right", padx=(12, 4), pady=12)
        tk.Entry(entry_frame, textvariable=self._db_path, width=52,
                 bg=BG_CARD, fg=TEXT_SEC, insertbackground=TEXT_PRI,
                 relief="flat", font=FONT_MONO, bd=6).pack()

        tk.Label(bar, text="History DB:", bg=BG_PANEL, fg=TEXT_SEC,
                 font=FONT_SANS).pack(side="right", padx=(0, 4))

    def _build_browser_bar(self):
        """Row of browser selector buttons."""
        bar = tk.Frame(self, bg=BG_DARK, height=46)
        bar.pack(fill="x", side="top", padx=0, pady=0)
        bar.pack_propagate(False)

        tk.Label(bar, text="Browser:", bg=BG_DARK, fg=TEXT_SEC,
                 font=FONT_SANS).pack(side="left", padx=(16, 8))

        self._browser_btns = {}
        for name, info in BROWSERS.items():
            label = f"{info['icon']}  {name}"
            btn = tk.Button(
                bar, text=label,
                command=lambda n=name: self._on_browser_change(n),
                bg=BG_CARD, fg=TEXT_SEC,
                activebackground=BG_HOVER, activeforeground=TEXT_PRI,
                relief="flat", bd=0, font=FONT_SANS,
                cursor="hand2", padx=10, pady=4,
            )
            btn.pack(side="left", padx=3, pady=6)
            self._browser_btns[name] = btn

        # Status indicator: found / not found
        self._browser_status = tk.Label(bar, text="", bg=BG_DARK, fg=TEXT_SEC,
                                        font=("Segoe UI", 8))
        self._browser_status.pack(side="left", padx=(16, 0))

        # Separator line
        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x", side="top")

    def _on_browser_change(self, name: str):
        self._selected_browser.set(name)
        self._db_type_override = None

        # Update button highlights
        for bname, btn in self._browser_btns.items():
            is_sel = (bname == name)
            info = BROWSERS[bname]
            btn.config(
                fg=info["color"] if is_sel else TEXT_SEC,
                bg=BG_HOVER if is_sel else BG_CARD,
            )

        if name == "Custom…":
            self._browse()
            return

        path = auto_detect_path(name)
        if path:
            self._db_path.set(path)
            self._db_type_override = BROWSERS[name]["db_type"]
            self._browser_status.config(
                text=f"✔  Found at: {path}", fg=ACCENT)
        else:
            self._db_path.set("")
            self._browser_status.config(
                text=f"✘  {name} history not found on this system.", fg=ACCENT2)

        # Show profile chooser for Firefox if multiple profiles exist
        if name == "Firefox":
            profiles = find_firefox_profiles()
            if len(profiles) > 1:
                self._show_firefox_profile_chooser(profiles)

    def _show_firefox_profile_chooser(self, profiles):
        """Popup to choose between multiple Firefox profiles."""
        win = tk.Toplevel(self)
        win.title("Select Firefox Profile")
        win.configure(bg=BG_DARK)
        win.resizable(False, False)
        win.geometry("520x240")
        win.grab_set()

        tk.Label(win, text="Multiple Firefox profiles found — choose one:",
                 bg=BG_DARK, fg=TEXT_PRI, font=FONT_SANS).pack(padx=20, pady=(16, 8), anchor="w")

        frame = tk.Frame(win, bg=BG_DARK)
        frame.pack(fill="both", expand=True, padx=20, pady=4)

        lb = tk.Listbox(frame, bg=BG_CARD, fg=TEXT_PRI, selectbackground=BG_HOVER,
                        relief="flat", bd=0, font=FONT_MONO, height=min(len(profiles), 6))
        sb = tk.Scrollbar(frame, orient="vertical", command=lb.yview,
                          bg=BG_PANEL, troughcolor=BG_PANEL)
        lb.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        lb.pack(side="left", fill="both", expand=True)
        for p in profiles:
            lb.insert(tk.END, str(p))
        if profiles:
            lb.selection_set(0)

        def confirm():
            sel = lb.curselection()
            if sel:
                self._db_path.set(lb.get(sel[0]))
                self._db_type_override = "firefox"
                self._browser_status.config(
                    text=f"✔  Profile: {lb.get(sel[0])}", fg=ACCENT)
            win.destroy()

        btn_kw = dict(bg=BG_CARD, fg=TEXT_PRI, activebackground=BG_HOVER,
                      relief="flat", bd=0, font=FONT_SANS, cursor="hand2", padx=12, pady=5)
        tk.Button(win, text="Use selected profile", command=confirm,
                  **{**btn_kw, "fg": ACCENT}).pack(pady=(8, 16))

    def _build_statusbar(self):
        self._status_var = tk.StringVar(value="Ready — select a browser above or browse to a History DB file.")
        bar = tk.Frame(self, bg=BG_PANEL, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        tk.Label(bar, textvariable=self._status_var, bg=BG_PANEL, fg=TEXT_SEC,
                 font=("Segoe UI", 9), anchor="w").pack(side="left", padx=12)
        self._progress = ttk.Progressbar(bar, mode="indeterminate", length=120)
        self._progress.pack(side="right", padx=12, pady=3)

    def _build_main(self):
        paned = tk.PanedWindow(self, orient="horizontal", bg=BORDER,
                               sashwidth=4, sashrelief="flat")
        paned.pack(fill="both", expand=True)

        left = tk.Frame(paned, bg=BG_DARK)
        paned.add(left, minsize=360, width=420)
        self._build_stat_cards(left)
        self._build_deleted_panel(left)

        right = tk.Frame(paned, bg=BG_DARK)
        paned.add(right, minsize=400)
        self._build_active_panel(right)

    def _build_stat_cards(self, parent):
        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(fill="x", padx=12, pady=(10, 6))

        cards = [
            ("Active URLs",    "active_val",  ACCENT,    "0"),
            ("Deleted URLs",   "deleted_val", ACCENT2,   "0"),
            ("Total Carved",   "carved_val",  TEXT_INFO, "0"),
        ]
        for i, (label, attr, color, default) in enumerate(cards):
            card = tk.Frame(frame, bg=BG_CARD, bd=0)
            card.grid(row=0, column=i, padx=4, sticky="nsew")
            frame.grid_columnconfigure(i, weight=1)
            tk.Label(card, text=label, bg=BG_CARD, fg=TEXT_SEC,
                     font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=10, pady=(8, 0))
            lbl = tk.Label(card, text=default, bg=BG_CARD, fg=color,
                           font=("Segoe UI", 22, "bold"))
            lbl.pack(anchor="w", padx=10, pady=(0, 8))
            setattr(self, f"_{attr}", lbl)

    def _build_deleted_panel(self, parent):
        header = tk.Frame(parent, bg=BG_DARK)
        header.pack(fill="x", padx=12, pady=(8, 0))
        tk.Label(header, text="⚠  DELETED / CARVED URLS", bg=BG_DARK, fg=ACCENT2,
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(header, text="  (in raw bytes, absent from active DB)",
                 bg=BG_DARK, fg=TEXT_SEC, font=("Segoe UI", 8)).pack(side="left")

        sf = tk.Frame(parent, bg=BORDER)
        sf.pack(fill="x", padx=12, pady=4)
        tk.Label(sf, text="Filter:", bg=BG_CARD, fg=TEXT_SEC,
                 font=FONT_SANS).pack(side="left", padx=(6, 4))
        tk.Entry(sf, textvariable=self._filter_deleted, bg=BG_CARD,
                 fg=TEXT_PRI, insertbackground=TEXT_PRI, relief="flat",
                 font=FONT_MONO, bd=4).pack(side="left", fill="x", expand=True, pady=2, padx=(0, 4))
        self._filter_deleted.trace_add("write", lambda *_: self._refresh_deleted())

        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        self._del_list = tk.Listbox(frame, bg=BG_CARD, fg=TEXT_DEL,
                                    selectbackground=BG_HOVER, selectforeground=TEXT_PRI,
                                    relief="flat", bd=0, font=FONT_MONO,
                                    activestyle="none", exportselection=False)
        scroll = tk.Scrollbar(frame, orient="vertical", command=self._del_list.yview,
                              bg=BG_PANEL, troughcolor=BG_PANEL)
        self._del_list.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self._del_list.pack(side="left", fill="both", expand=True)
        self._del_list.bind("<<ListboxSelect>>", self._on_del_select)

        self._del_detail = tk.Label(parent, text="", bg=BG_DARK, fg=TEXT_SEC,
                                    font=("Segoe UI", 8), wraplength=380, justify="left")
        self._del_detail.pack(fill="x", padx=12, pady=(0, 6))

    def _build_active_panel(self, parent):
        header = tk.Frame(parent, bg=BG_DARK)
        header.pack(fill="x", padx=12, pady=(10, 0))
        tk.Label(header, text="✅  ACTIVE HISTORY", bg=BG_DARK, fg=ACCENT,
                 font=("Segoe UI", 10, "bold")).pack(side="left")

        sf = tk.Frame(parent, bg=BORDER)
        sf.pack(fill="x", padx=12, pady=4)
        tk.Label(sf, text="Filter:", bg=BG_CARD, fg=TEXT_SEC,
                 font=FONT_SANS).pack(side="left", padx=(6, 4))
        tk.Entry(sf, textvariable=self._filter_active, bg=BG_CARD,
                 fg=TEXT_PRI, insertbackground=TEXT_PRI, relief="flat",
                 font=FONT_MONO, bd=4).pack(side="left", fill="x", expand=True, pady=2, padx=(0, 4))
        self._filter_active.trace_add("write", lambda *_: self._refresh_active())

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Forensic.Treeview",
                         background=BG_CARD, foreground=TEXT_PRI,
                         fieldbackground=BG_CARD, rowheight=22,
                         font=FONT_MONO, borderwidth=0)
        style.configure("Forensic.Treeview.Heading",
                         background=BG_PANEL, foreground=TEXT_SEC,
                         font=FONT_HEAD, relief="flat")
        style.map("Forensic.Treeview",
                  background=[("selected", BG_HOVER)],
                  foreground=[("selected", TEXT_PRI)])

        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        cols = ("title", "url", "visits", "last_visit")
        self._tree = ttk.Treeview(frame, columns=cols, show="headings",
                                  style="Forensic.Treeview", selectmode="browse")
        self._tree.heading("title",      text="Title",      anchor="w")
        self._tree.heading("url",        text="URL",        anchor="w")
        self._tree.heading("visits",     text="Visits",     anchor="center")
        self._tree.heading("last_visit", text="Last Visit", anchor="w")
        self._tree.column("title",      width=160, stretch=True)
        self._tree.column("url",        width=260, stretch=True)
        self._tree.column("visits",     width=52,  stretch=False, anchor="center")
        self._tree.column("last_visit", width=160, stretch=False)

        vsb = ttk.Scrollbar(frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._tree.pack(side="left", fill="both", expand=True)

        btn = tk.Button(parent, text="💾  Export Active History (TXT)",
                        command=self._export_active,
                        bg=BG_CARD, fg=TEXT_INFO, activebackground=BG_HOVER,
                        activeforeground=TEXT_INFO, relief="flat", bd=0,
                        font=FONT_SANS, cursor="hand2", padx=10, pady=5)
        btn.pack(anchor="e", padx=12, pady=(0, 8))

    # ── Actions ───────────────────────────────────────────────────────────────
    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select browser History / places.sqlite",
            filetypes=[
                ("History databases", "History places.sqlite"),
                ("All files", "*.*"),
            ])
        if path:
            self._db_path.set(path)
            self._db_type_override = detect_db_type(path)
            detected = "firefox" if self._db_type_override == "firefox" else "chromium"
            self._browser_status.config(
                text=f"Custom file — detected as: {detected}", fg=TEXT_INFO)
            # Deselect all browser buttons
            for btn in self._browser_btns.values():
                btn.config(fg=TEXT_SEC, bg=BG_CARD)
            self._browser_btns["Custom…"].config(
                fg=BROWSERS["Custom…"]["color"], bg=BG_HOVER)

    def _run(self):
        path = self._db_path.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("File not found",
                                 "Please select a valid browser history database file.")
            return
        self._status_var.set("Analysing — please wait …")
        self._progress.start(10)
        db_type = self._db_type_override
        threading.Thread(
            target=self._analyse_thread, args=(path, db_type), daemon=True
        ).start()

    def _analyse_thread(self, path, db_type):
        try:
            active, deleted = run_analysis(path, db_type)
            self.after(0, self._display_results, active, deleted, path)
        except Exception as e:
            self.after(0, self._on_error, str(e))

    def _display_results(self, active, deleted, path):
        self._progress.stop()
        self._active_records = active
        self._deleted_urls   = deleted

        carved_total = len(active) + len(deleted)
        self._active_val.config( text=f"{len(active):,}")
        self._deleted_val.config(text=f"{len(deleted):,}")
        self._carved_val.config( text=f"{carved_total:,}")

        self._refresh_active()
        self._refresh_deleted()

        browser = self._selected_browser.get()
        db_name = os.path.basename(path)
        self._status_var.set(
            f"{browser} — {db_name}  |  "
            f"{len(active):,} active  ·  {len(deleted):,} deleted/carved  ·  "
            f"analysed at {datetime.now().strftime('%H:%M:%S')}"
        )

    def _on_error(self, msg):
        self._progress.stop()
        self._status_var.set(f"Error: {msg}")
        messagebox.showerror("Analysis failed", msg)

    def _refresh_active(self, *_):
        q = self._filter_active.get().lower()
        for item in self._tree.get_children():
            self._tree.delete(item)
        for r in self._active_records:
            if q in r["url"].lower() or q in r["title"].lower():
                self._tree.insert("", "end", values=(
                    r["title"][:60],
                    r["url"],
                    r["visits"],
                    r["last_visit"],
                ))

    def _refresh_deleted(self, *_):
        q = self._filter_deleted.get().lower()
        self._del_list.delete(0, tk.END)
        for url in self._deleted_urls:
            if q in url.lower():
                self._del_list.insert(tk.END, url)

    def _on_del_select(self, _event):
        sel = self._del_list.curselection()
        if sel:
            url = self._del_list.get(sel[0])
            self._del_detail.config(text=url)

    def _export_active(self):
        if not self._active_records:
            messagebox.showinfo("Nothing to export", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            initialfile="active_history.txt")
        if not path:
            return
        browser = self._selected_browser.get()
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"BrowseTrace — Active History Export\n")
            f.write(f"Browser:   {browser}\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write("=" * 80 + "\n\n")
            for r in self._active_records:
                f.write(f"Title:      {r['title']}\n")
                f.write(f"URL:        {r['url']}\n")
                f.write(f"Visits:     {r['visits']}\n")
                f.write(f"Last visit: {r['last_visit']}\n")
                f.write("-" * 80 + "\n")
        messagebox.showinfo("Exported", f"Saved to:\n{path}")


if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()
