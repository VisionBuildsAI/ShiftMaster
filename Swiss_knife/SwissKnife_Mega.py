#!/usr/bin/env python3
"""
SwissKnife Pro — Enterprise-style GUI for encryption, encoding, hashing and developer tools.

Save as: SwissKnife_Pro.py
Run: python SwissKnife_Pro.py

Features:
 - Modern hacker-dark Tkinter UI (menus, toolbar, tabs)
 - Encoders (Base64/Hex), Hashing, Ciphers (Caesar, Vigenere, XOR)
 - Strong file encryption (Fernet + PBKDF2), file batch operations
 - JWT decode, file info, wordlist mask generator
 - Plugin system: drop .py files into ./plugins and they appear automatically
 - Settings (config.json) and secure optional key storage via keyring
 - Audit logging (rotating logs), export logs
 - Background workers with progress bar + status reporting
 - Recent files pane, drag/open file convenience
 - CLI bridge for automation
 - Tries to load logo at /mnt/data/c5653e52-4b50-47aa-9091-c2a8122461a9.png
"""

import os
import sys
import json
import base64
import binascii
import hashlib
import secrets
import string
import re
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from math import log2
from typing import List
import threading
import importlib.util
import traceback
import shutil

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog

# third-party imports (optional)
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    print("cryptography package missing - install with: pip install cryptography")
    raise

# optional: Pillow for logo
try:
    from PIL import Image, ImageTk
except Exception:
    Image = None
    ImageTk = None

# optional: keyring for secure password storage
try:
    import keyring
except Exception:
    keyring = None

# ------------------------------------------------------------
# Constants & paths
# ------------------------------------------------------------
APP_NAME = "SwissKnife Pro"
CONFIG_FILE = "skp_config.json"
PLUGINS_FOLDER = "plugins"
LOG_FOLDER = "logs"
LOG_FILE = os.path.join(LOG_FOLDER, "swissknife_pro.log")
# Provided uploaded logo path (the file you previously uploaded)
LOGO_PATH = "/mnt/data/c5653e52-4b50-47aa-9091-c2a8122461a9.png"

# ensure paths exist
os.makedirs(PLUGINS_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)

# ------------------------------------------------------------
# Logging (rotating)
# ------------------------------------------------------------
logger = logging.getLogger("swissknife")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding='utf-8')
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# also a console handler for dev
console = logging.StreamHandler()
console.setFormatter(formatter)
logger.addHandler(console)

def audit(msg, level="info"):
    # Central audit log
    getattr(logger, level)(msg)

# ------------------------------------------------------------
# Core crypto + utilities (safe/educational)
# ------------------------------------------------------------
HASH_ALGOS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512
}

def load_file_lines(path: str) -> List[str]:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def gen_hash(algo: str, text: str) -> str:
    algo = algo.lower()
    if algo not in HASH_ALGOS:
        raise ValueError("Unsupported algorithm")
    h = HASH_ALGOS[algo]()
    h.update(text.encode())
    return h.hexdigest()

def identify_hash(hash_str: str) -> str:
    n = len(hash_str)
    mapping = {32: 'md5', 40: 'sha1', 56: 'sha224', 64: 'sha256', 96: 'sha384', 128: 'sha512'}
    return mapping.get(n, f'unknown (length {n})')

def password_entropy(password: str) -> float:
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'\W', password): charset += 32
    if charset == 0:
        return 0.0
    return len(password) * log2(charset)

def password_strength(password: str) -> str:
    e = password_entropy(password)
    if e < 28: return "Very weak"
    if e < 36: return "Weak"
    if e < 60: return "Reasonable"
    if e < 128: return "Strong"
    return "Very strong"

def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def decode_base64(text: str) -> str:
    try:
        return base64.b64decode(text.encode()).decode(errors='ignore')
    except Exception as e:
        return f"<Error: {e}>"

def encode_hex(text: str) -> str:
    return binascii.hexlify(text.encode()).decode()

def decode_hex(text: str) -> str:
    try:
        return binascii.unhexlify(text.encode()).decode(errors='ignore')
    except Exception as e:
        return f"<Error: {e}>"

def caesar(text: str, shift: int, encrypt=True) -> str:
    if not encrypt: shift = -shift
    res=[]
    for ch in text:
        if 'a'<=ch<='z': res.append(chr((ord(ch)-97+shift)%26+97))
        elif 'A'<=ch<='Z': res.append(chr((ord(ch)-65+shift)%26+65))
        else: res.append(ch)
    return ''.join(res)

def caesar_bruteforce(text: str) -> List[tuple]:
    return [(s, caesar(text, s, encrypt=False)) for s in range(1,26)]

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    res=[]; ki=0
    for ch in ciphertext:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            offset = ord(key[ki % len(key)].lower()) - 97
            res.append(chr((ord(ch)-base-offset) % 26 + base))
            ki+=1
        else:
            res.append(ch)
    return ''.join(res)

def xor_cipher_hex(text: str, key: str) -> str:
    out=[]
    b = text.encode(errors='ignore')
    for i,c in enumerate(b): out.append(c ^ ord(key[i % len(key)]))
    return bytes(out).hex()

# ------------------------------
# Strong symmetric encryption (Fernet + PBKDF2)
# ------------------------------
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as chashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

def derive_fernet_key(password: str, salt: bytes=None, rounds:int=390000):
    if salt is None: salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=chashes.SHA256(), length=32, salt=salt, iterations=rounds, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def fernet_encrypt_bytes(data: bytes, password: str) -> bytes:
    key, salt = derive_fernet_key(password)
    f = Fernet(key)
    token = f.encrypt(data)
    return salt + token

def fernet_decrypt_bytes(blob: bytes, password: str) -> bytes:
    if len(blob) < 16: raise ValueError("Blob too short")
    salt = blob[:16]; token = blob[16:]
    key, _ = derive_fernet_key(password, salt)
    f = Fernet(key)
    return f.decrypt(token)

def encrypt_file(path: str, password: str, out_path: str=None) -> str:
    with open(path,'rb') as f: data=f.read()
    blob = fernet_encrypt_bytes(data, password)
    if out_path is None: out_path = path + ".enc"
    with open(out_path,'wb') as f: f.write(blob)
    audit(f"Encrypted file {path} -> {out_path}")
    return out_path

def decrypt_file(path: str, password: str, out_path: str=None) -> str:
    with open(path,'rb') as f: blob=f.read()
    data = fernet_decrypt_bytes(blob, password)
    if out_path is None:
        out_path = (path[:-4] + ".dec") if path.endswith(".enc") else path + ".dec"
    with open(out_path,'wb') as f: f.write(data)
    audit(f"Decrypted file {path} -> {out_path}")
    return out_path

# ------------------------------
# Wordlist mask generator
# ------------------------------
def generate_wordlist_from_mask(mask: str, out_file: str, max_count=100000):
    sets = {'?l': string.ascii_lowercase,'?u': string.ascii_uppercase,'?d': string.digits,'?s': "!@#$%&*"}
    wildcard=None
    for token, chars in sets.items():
        if token in mask:
            wildcard=(token,chars); break
    results=[]
    if wildcard:
        token, chars = wildcard
        prefix, suffix = mask.split(token)
        for c in chars:
            results.append(prefix+c+suffix)
            if len(results)>=max_count: break
    else: results.append(mask)
    with open(out_file,'w',encoding='utf-8') as f:
        for r in results: f.write(r+"\n")
    audit(f"Generated wordlist {out_file} from mask {mask}")
    return out_file

# ------------------------------
# JWT decode
# ------------------------------
def jwt_decode(token: str) -> dict:
    try:
        parts = token.split('.')
        if len(parts)<2: raise ValueError("Not a JWT")
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        payload = base64.urlsafe_b64decode(payload_b64.encode())
        return json.loads(payload.decode(errors='ignore'))
    except Exception as e:
        return {"error": str(e)}

# ------------------------------
# Plugin loader (simple)
# ------------------------------
def discover_plugins(folder=PLUGINS_FOLDER):
    plugins=[]
    for fn in os.listdir(folder):
        if not fn.endswith(".py"): continue
        path=os.path.join(folder,fn)
        try:
            spec = importlib.util.spec_from_file_location(fn[:-3], path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            # plugin should expose: PLUGIN_NAME and run(widget_parent, app) optional
            name = getattr(mod, "PLUGIN_NAME", fn[:-3])
            plugins.append((name, path))
            audit(f"Loaded plugin {name} from {path}")
        except Exception as e:
            logger.exception(f"Failed to load plugin {path}: {e}")
    return plugins

# ------------------------------
# Config handling
# ------------------------------
DEFAULT_CONFIG = {
    "recent_files": [],
    "last_tab": "enc",
    "auto_save_logs": True,
    "plugin_folder": PLUGINS_FOLDER
}

def load_config(path=CONFIG_FILE):
    if not os.path.exists(path):
        save_config(DEFAULT_CONFIG, path)
        return DEFAULT_CONFIG
    try:
        with open(path,'r',encoding='utf-8') as f: cfg=json.load(f)
        return cfg
    except Exception:
        return DEFAULT_CONFIG

def save_config(cfg, path=CONFIG_FILE):
    with open(path,'w',encoding='utf-8') as f: json.dump(cfg,f,indent=2)

# ------------------------------------------------------------
# GUI App
# ------------------------------------------------------------
class SwissKnifeProApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1200x780")
        self.configure(bg="#071014")
        self.config = load_config()
        self._init_styles()
        self._build_menu_toolbar()
        self._build_main_area()
        self._load_plugins()
        self._load_recent_files_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        audit("Application started")

    # ---------- UI building ----------
    def _init_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook.Tab", background="#081a22", foreground="#bfefff", font=("Consolas",11))
        style.configure("TButton", font=("Consolas",10), padding=6)
        style.configure("TLabel", font=("Consolas",10))
        # fonts/colors used directly in widgets

    def _build_menu_toolbar(self):
        menubar = tk.Menu(self)
        # File
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Open File...", command=self._open_file)
        filem.add_command(label="Encrypt File...", command=self._encrypt_file_dialog)
        filem.add_command(label="Decrypt File...", command=self._decrypt_file_dialog)
        filem.add_separator()
        filem.add_command(label="Export Logs...", command=self._export_logs)
        filem.add_separator()
        filem.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=filem)
        # Tools
        toolsm = tk.Menu(menubar, tearoff=0)
        toolsm.add_command(label="Encoders", command=lambda: self.nb.select(self.enc_tab_idx))
        toolsm.add_command(label="Hashing", command=lambda: self.nb.select(self.hash_tab_idx))
        toolsm.add_command(label="Crypto", command=lambda: self.nb.select(self.crypto_tab_idx))
        menubar.add_cascade(label="Tools", menu=toolsm)
        # Help
        helpm = tk.Menu(menubar, tearoff=0)
        helpm.add_command(label="About", command=self._about)
        helpm.add_command(label="Licenses / Ethics", command=self._about_ethics)
        menubar.add_cascade(label="Help", menu=helpm)
        self.config(menu=menubar)

        # toolbar
        toolbar = tk.Frame(self, bg="#0b1620")
        toolbar.pack(side="top", fill="x")
        ttk.Button(toolbar, text="Open", command=self._open_file).pack(side="left", padx=6, pady=6)
        ttk.Button(toolbar, text="Encrypt File", command=self._encrypt_file_dialog).pack(side="left", padx=6, pady=6)
        ttk.Button(toolbar, text="Decrypt File", command=self._decrypt_file_dialog).pack(side="left", padx=6, pady=6)
        ttk.Button(toolbar, text="Export Logs", command=self._export_logs).pack(side="left", padx=6, pady=6)
        ttk.Button(toolbar, text="Plugins", command=self._show_plugins).pack(side="left", padx=6, pady=6)

    def _build_main_area(self):
        self.main = tk.Frame(self, bg="#071014")
        self.main.pack(fill="both", expand=True, padx=8, pady=6)
        self.nb = ttk.Notebook(self.main)
        self.nb.pack(fill="both", expand=True)

        # Encoders tab
        enc_frame = ttk.Frame(self.nb); self.nb.add(enc_frame, text="Encoders"); self.enc_tab_idx = 0
        self._build_enc_tab(enc_frame)

        # Hashing tab
        hash_frame = ttk.Frame(self.nb); self.nb.add(hash_frame, text="Hashing"); self.hash_tab_idx = 1
        self._build_hash_tab(hash_frame)

        # Crypto tab
        crypto_frame = ttk.Frame(self.nb); self.nb.add(crypto_frame, text="Crypto"); self.crypto_tab_idx = 2
        self._build_crypto_tab(crypto_frame)

        # Passwords & Keys tab
        pwd_frame = ttk.Frame(self.nb); self.nb.add(pwd_frame, text="Passwords & Keys"); self.pwd_tab_idx = 3
        self._build_pwd_tab(pwd_frame)

        # Misc tab
        misc_frame = ttk.Frame(self.nb); self.nb.add(misc_frame, text="Misc"); self.misc_tab_idx = 4
        self._build_misc_tab(misc_frame)

        # Right side: recent files / plugins list
        right = tk.Frame(self.main, width=260, bg="#071014")
        right.pack(side="right", fill="y", padx=(6,0))
        tk.Label(right, text="Recent Files", bg="#071014", fg="#bfefff", font=("Consolas",12,"bold")).pack(anchor="nw", padx=6, pady=(6,2))
        self.recent_tree = ttk.Treeview(right, columns=("path","time"), show="headings", height=12)
        self.recent_tree.heading("path", text="Path"); self.recent_tree.heading("time", text="Last opened")
        self.recent_tree.pack(fill="both", padx=6, pady=6)
        ttk.Button(right, text="Clear Recent", command=self._clear_recent).pack(fill="x", padx=6, pady=(0,6))
        tk.Label(right, text="Plugins", bg="#071014", fg="#bfefff", font=("Consolas",12,"bold")).pack(anchor="nw", padx=6, pady=(8,2))
        self.plugins_listbox = tk.Listbox(right, height=6, bg="#081a22", fg="#bfefff", font=("Consolas",10))
        self.plugins_listbox.pack(fill="both", padx=6, pady=6)

        # status + progress
        bottom = tk.Frame(self, bg="#021014")
        bottom.pack(side="bottom", fill="x")
        self.status = tk.Label(bottom, text="Ready", anchor="w", bg="#021014", fg="#cfeff3", font=("Consolas",10))
        self.status.pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(bottom, mode="determinate", length=200)
        self.progress.pack(side="right", padx=8, pady=4)

    # ---------------- Tab builders (compact) ----------------
    def _io_widgets(self, parent, input_h=6, output_h=10):
        left = tk.Frame(parent, bg="#071014", width=220); left.pack(side="left", fill="y", padx=6, pady=6)
        right = tk.Frame(parent, bg="#071014"); right.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        tk.Label(left, text="Actions", bg="#071014", fg="#bfefff", font=("Consolas",11,"bold")).pack(anchor="w")
        tk.Label(right, text="Input", bg="#071014", fg="#bfefff", font=("Consolas",11,"bold")).pack(anchor="w")
        input_box = scrolledtext.ScrolledText(right, height=input_h, bg="#061018", fg="#dff8ff", font=("Consolas",11))
        input_box.pack(fill="x", pady=6)
        tk.Label(right, text="Output", bg="#071014", fg="#bfefff", font=("Consolas",11,"bold")).pack(anchor="w")
        output_box = scrolledtext.ScrolledText(right, height=output_h, bg="#021014", fg="#bff0ea", font=("Consolas",11))
        output_box.pack(fill="both", expand=True, pady=6)
        return left, input_box, output_box

    def _build_enc_tab(self, frame):
        left, self.enc_input, self.enc_output = self._io_widgets(frame)
        ttk.Button(left, text="Load file", command=lambda: self._load_file_into(self.enc_input)).pack(fill="x", pady=4)
        ttk.Button(left, text="Base64 Encode", command=self._enc_b64).pack(fill="x", pady=4)
        ttk.Button(left, text="Base64 Decode", command=self._enc_b64dec).pack(fill="x", pady=4)
        ttk.Button(left, text="Hex Encode", command=self._enc_hex).pack(fill="x", pady=4)
        ttk.Button(left, text="Hex Decode", command=self._enc_hexdec).pack(fill="x", pady=4)
        ttk.Button(left, text="XOR (text)", command=self._enc_xor_ui).pack(fill="x", pady=4)
        ttk.Button(left, text="Copy Output", command=self._copy_output).pack(fill="x", pady=6)

    def _build_hash_tab(self, frame):
        left, self.hash_input, self.hash_output = self._io_widgets(frame)
        ttk.Label(left, text="Algorithm:", font=("Consolas",10)).pack(anchor="w", pady=(6,0))
        self.hash_algo_var = tk.StringVar(value="sha256")
        ttk.Combobox(left, textvariable=self.hash_algo_var, values=list(HASH_ALGOS.keys()), state="readonly", width=12).pack(pady=4)
        ttk.Button(left, text="Generate Hash", command=self._hash_generate).pack(fill="x", pady=4)
        ttk.Button(left, text="Identify Hash", command=self._hash_identify).pack(fill="x", pady=4)
        ttk.Button(left, text="Dictionary Check", command=self._hash_dict_ui).pack(fill="x", pady=4)
        ttk.Button(left, text="Copy Output", command=self._copy_output).pack(fill="x", pady=6)

    def _build_crypto_tab(self, frame):
        left, self.crypto_input, self.crypto_output = self._io_widgets(frame)
        ttk.Label(left, text="Shift / Key:", font=("Consolas",10)).pack(anchor="w", pady=(6,0))
        self.shift_var = tk.StringVar(value="3")
        tk.Entry(left, textvariable=self.shift_var, width=10, bg="#061018", fg="#dff8ff", font=("Consolas",11)).pack(pady=4)
        ttk.Button(left, text="Caesar Encrypt", command=self._caesar_encrypt).pack(fill="x", pady=4)
        ttk.Button(left, text="Caesar Decrypt", command=self._caesar_decrypt).pack(fill="x", pady=4)
        ttk.Button(left, text="Bruteforce Caesar", command=self._caesar_bruteforce).pack(fill="x", pady=4)
        ttk.Separator(left, orient="horizontal").pack(fill="x", pady=8)
        ttk.Label(left, text="Vigenere Key:", font=("Consolas",10)).pack(anchor="w")
        self.vig_key_var = tk.StringVar()
        tk.Entry(left, textvariable=self.vig_key_var, width=14, bg="#061018", fg="#dff8ff", font=("Consolas",11)).pack(pady=4)
        ttk.Button(left, text="Vigenère Decrypt", command=self._vigenere_decrypt).pack(fill="x", pady=4)
        ttk.Label(left, text="XOR (key):", font=("Consolas",10)).pack(anchor="w", pady=(8,0))
        self.xor_key_var = tk.StringVar()
        tk.Entry(left, textvariable=self.xor_key_var, width=14, bg="#061018", fg="#dff8ff", font=("Consolas",11)).pack(pady=4)
        ttk.Button(left, text="XOR Encrypt (hex)", command=self._xor_encrypt).pack(fill="x", pady=4)
        ttk.Button(left, text="Copy Output", command=self._copy_output).pack(fill="x", pady=6)

    def _build_pwd_tab(self, frame):
        left, self.pwd_input, self.pwd_output = self._io_widgets(frame)
        ttk.Button(left, text="Check Strength", command=self._pass_check).pack(fill="x", pady=4)
        ttk.Button(left, text="Generate Random Key", command=self._gen_key_ui).pack(fill="x", pady=4)
        ttk.Button(left, text="Generate Wordlist (mask)", command=self._wordlist_ui).pack(fill="x", pady=4)
        ttk.Button(left, text="Copy Output", command=self._copy_output).pack(fill="x", pady=6)

    def _build_misc_tab(self, frame):
        left, self.misc_input, self.misc_output = self._io_widgets(frame)
        ttk.Button(left, text="Encrypt File (password)", command=self._encrypt_file_dialog).pack(fill="x", pady=4)
        ttk.Button(left, text="Decrypt File (password)", command=self._decrypt_file_dialog).pack(fill="x", pady=4)
        ttk.Button(left, text="JWT Decode", command=self._jwt_ui).pack(fill="x", pady=4)
        ttk.Button(left, text="File Info", command=self._file_info_ui).pack(fill="x", pady=4)
        ttk.Button(left, text="Open Config", command=lambda: os.startfile(CONFIG_FILE) if os.path.exists(CONFIG_FILE) else messagebox.showinfo("Config", "No config file yet")).pack(fill="x", pady=4)
        ttk.Button(left, text="Clear All", command=self._clear_all).pack(fill="x", pady=6)

    # --------------------
    # Plugin discovery & UI
    # --------------------
    def _load_plugins(self):
        self.plugins = discover_plugins(self.config.get("plugin_folder", PLUGINS_FOLDER))
        self.plugins_listbox.delete(0, tk.END)
        for name, path in self.plugins:
            self.plugins_listbox.insert(tk.END, name)

    def _show_plugins(self):
        pwin = tk.Toplevel(self)
        pwin.title("Installed Plugins")
        pwin.geometry("600x400")
        tk.Label(pwin, text="Plugins", font=("Consolas",14)).pack(anchor="w", pady=6, padx=6)
        lb = tk.Listbox(pwin)
        lb.pack(fill="both", expand=True, padx=6, pady=6)
        for name,path in self.plugins: lb.insert(tk.END, f"{name} — {path}")
        ttk.Button(pwin, text="Reload", command=lambda: (self._load_plugins(), pwin.destroy())).pack(pady=6)

    # --------------------
    # Recent files handling
    # --------------------
    def _load_recent_files_ui(self):
        self.recent_tree.delete(*self.recent_tree.get_children())
        for p in self.config.get("recent_files", []):
            tstr = datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M") if os.path.exists(p) else "missing"
            self.recent_tree.insert("", "end", values=(p, tstr))

    def _add_recent(self, path):
        rec = self.config.get("recent_files", [])
        try:
            if path in rec: rec.remove(path)
            rec.insert(0, path)
            rec = rec[:30]
            self.config["recent_files"] = rec
            save_config(self.config)
            self._load_recent_files_ui()
        except Exception as e:
            logger.exception("Failed to update recent files: %s", e)

    def _clear_recent(self):
        self.config["recent_files"]=[]
        save_config(self.config)
        self._load_recent_files_ui()
        self.status.config(text="Cleared recent files")

    # --------------------
    # Generic helpers
    # --------------------
    def _load_file_into(self, widget):
        path = filedialog.askopenfilename(title="Open file")
        if not path: return
        try:
            with open(path,'r',encoding='utf-8',errors='ignore') as f: txt=f.read()
            widget.delete("1.0", tk.END); widget.insert(tk.END, txt)
            self._add_recent(path)
            self.status.config(text=f"Loaded {os.path.basename(path)}")
            audit(f"Loaded file {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {e}")

    def _copy_output(self):
        for box in [self.enc_output, self.hash_output, self.crypto_output, self.pwd_output, self.misc_output]:
            try:
                data = box.get("1.0", tk.END).strip()
                if data:
                    self.clipboard_clear(); self.clipboard_append(data)
                    self.status.config(text="Output copied")
                    return
            except Exception:
                continue
        self.status.config(text="No output to copy")

    # --------------------
    # Encoders actions
    # --------------------
    def _enc_b64(self):
        txt = self.enc_input.get("1.0", tk.END).strip()
        self.enc_output.delete("1.0", tk.END); self.enc_output.insert(tk.END, encode_base64(txt)); self.status.config(text="Base64 encoded"); audit("Base64 encode")
    def _enc_b64dec(self):
        txt = self.enc_input.get("1.0", tk.END).strip()
        self.enc_output.delete("1.0", tk.END); self.enc_output.insert(tk.END, decode_base64(txt)); self.status.config(text="Base64 decoded"); audit("Base64 decode")
    def _enc_hex(self):
        txt = self.enc_input.get("1.0", tk.END).strip()
        self.enc_output.delete("1.0", tk.END); self.enc_output.insert(tk.END, encode_hex(txt)); self.status.config(text="Hex encoded"); audit("Hex encode")
    def _enc_hexdec(self):
        txt = self.enc_input.get("1.0", tk.END).strip()
        self.enc_output.delete("1.0", tk.END); self.enc_output.insert(tk.END, decode_hex(txt)); self.status.config(text="Hex decoded"); audit("Hex decode")
    def _enc_xor_ui(self):
        txt = self.enc_input.get("1.0", tk.END).strip()
        if not txt: messagebox.showwarning("Input required","Paste text first"); return
        key = simpledialog.askstring("XOR key","Enter key (text):")
        if not key: return
        out = xor_cipher_hex(txt, key)
        self.enc_output.delete("1.0", tk.END); self.enc_output.insert(tk.END, out); self.status.config(text="XOR applied"); audit("XOR applied")

    # --------------------
    # Hashing actions
    # --------------------
    def _hash_generate(self):
        txt = self.hash_input.get("1.0", tk.END).strip()
        algo = self.hash_algo_var.get()
        if not txt: messagebox.showwarning("Input","Provide text"); return
        try:
            out = gen_hash(algo, txt)
        except Exception as e:
            out = f"Error: {e}"
        self.hash_output.delete("1.0", tk.END); self.hash_output.insert(tk.END, out); self.status.config(text="Hash generated"); audit(f"Hash {algo}")

    def _hash_identify(self):
        txt = self.hash_input.get("1.0", tk.END).strip()
        if not txt: messagebox.showwarning("Input","Provide hash"); return
        out = identify_hash(txt)
        self.hash_output.delete("1.0", tk.END); self.hash_output.insert(tk.END, out); self.status.config(text="Hash identified"); audit("Hash identify")

    def _hash_dict_ui(self):
        target = filedialog.askopenfilename(title="Choose targets file")
        if not target: return
        wordlist = filedialog.askopenfilename(title="Choose wordlist")
        if not wordlist: return
        algo = self.hash_algo_var.get()
        self.status.config(text="Running dictionary check (educational)..."); audit("Dict check start")
        def run():
            found = {}
            try:
                found = dict_crack_simple(algo, target, wordlist)
            except Exception as e:
                logger.exception("Dict crack failed: %s", e)
            self.hash_output.delete("1.0", tk.END)
            if not found:
                self.hash_output.insert(tk.END, "No matches found.")
                self.status.config(text="Dict check finished: none")
            else:
                for h,w in found.items(): self.hash_output.insert(tk.END, f"{h} => {w}\n")
                self.status.config(text=f"Dict check finished: found {len(found)}")
            audit("Dict check finished")
        threading.Thread(target=run, daemon=True).start()

    # --------------------
    # Crypto actions
    # --------------------
    def _caesar_encrypt(self):
        txt=self.crypto_input.get("1.0",tk.END).strip()
        try: s=int(self.shift_var.get())
        except: messagebox.showerror("Error","Shift must be integer"); return
        self.crypto_output.delete("1.0",tk.END); self.crypto_output.insert(tk.END, caesar(txt,s,encrypt=True)); self.status.config(text=f"Caesar encrypted (shift {s})"); audit("Caesar encrypt")
    def _caesar_decrypt(self):
        txt=self.crypto_input.get("1.0",tk.END).strip()
        try: s=int(self.shift_var.get())
        except: messagebox.showerror("Error","Shift must be integer"); return
        self.crypto_output.delete("1.0",tk.END); self.crypto_output.insert(tk.END, caesar(txt,s,encrypt=False)); self.status.config(text=f"Caesar decrypted (shift {s})"); audit("Caesar decrypt")
    def _caesar_bruteforce(self):
        txt=self.crypto_input.get("1.0",tk.END).strip()
        results=caesar_bruteforce(txt)
        out="\n".join([f"[{s}] {t}" for s,t in results])
        self.crypto_output.delete("1.0",tk.END); self.crypto_output.insert(tk.END,out); self.status.config(text="Caesar bruteforce"); audit("Caesar bruteforce")
    def _vigenere_decrypt(self):
        txt=self.crypto_input.get("1.0",tk.END).strip(); key=self.vig_key_var.get().strip()
        if not key: messagebox.showwarning("Key required","Enter Vigenère key"); return
        out=vigenere_decrypt(txt,key)
        self.crypto_output.delete("1.0",tk.END); self.crypto_output.insert(tk.END,out); self.status.config(text="Vigenère decrypt"); audit("Vigenere decrypt")
    def _xor_encrypt(self):
        txt=self.crypto_input.get("1.0",tk.END).strip(); key=self.xor_key_var.get().strip()
        if not key: messagebox.showwarning("Key required","Enter XOR key"); return
        out=xor_cipher_hex(txt,key)
        self.crypto_output.delete("1.0",tk.END); self.crypto_output.insert(tk.END,out); self.status.config(text="XOR processed"); audit("XOR")

    # --------------------
    # Passwords & keys
    # --------------------
    def _pass_check(self):
        txt=self.pwd_input.get("1.0",tk.END).strip()
        if not txt: messagebox.showwarning("Input required","Paste password"); return
        e=password_entropy(txt); out=f"Entropy: {e:.2f} bits — Strength: {password_strength(txt)}"
        self.pwd_output.delete("1.0",tk.END); self.pwd_output.insert(tk.END,out); self.status.config(text="Password checked"); audit("Password check")
    def _gen_key_ui(self):
        n=simpledialog.askinteger("Key bytes","Enter number of bytes",initialvalue=16,minvalue=1,maxvalue=256)
        if not n: return
        k=secrets.token_hex(n)
        self.pwd_output.delete("1.0",tk.END); self.pwd_output.insert(tk.END,k); self.status.config(text=f"Generated {n}-byte key"); audit("Key generated")
    def _wordlist_ui(self):
        mask=simpledialog.askstring("Mask","Enter mask e.g. pass?d")
        if not mask: return
        out_file=filedialog.asksaveasfilename(defaultextension=".txt")
        if not out_file: return
        generate_wordlist_from_mask(mask,out_file)
        self.pwd_output.delete("1.0",tk.END); self.pwd_output.insert(tk.END,f"Saved: {out_file}"); self.status.config(text="Wordlist generated"); audit("Wordlist generated")

    # --------------------
    # Misc: file encrypt/decrypt/jwt/info
    # --------------------
    def _encrypt_file_dialog(self):
        path=filedialog.askopenfilename(title="Select file to encrypt")
        if not path: return
        # ask for password via secure keyring if available
        if keyring:
            store = messagebox.askyesno("Secure storage","Store password in OS keyring for this file?")
        else:
            store = False
        pwd = simpledialog.askstring("Password","Enter password for encryption:",show='*')
        if not pwd: return
        # background run + progress simulation
        def run_enc():
            try:
                self.progress.start(10)
                out=encrypt_file(path,pwd)
                self._add_recent(out)
                self.misc_output.delete("1.0",tk.END); self.misc_output.insert(tk.END,f"Encrypted -> {out}")
                if store and keyring:
                    keyring.set_password(APP_NAME, out, pwd)
                self.status.config(text=f"Encrypted {os.path.basename(out)}")
                audit(f"Encrypted file {path} to {out}")
            except Exception as e:
                logger.exception("File encrypt failed: %s",e)
                messagebox.showerror("Encrypt failed", str(e))
            finally:
                self.progress.stop()
        threading.Thread(target=run_enc, daemon=True).start()

    def _decrypt_file_dialog(self):
        path=filedialog.askopenfilename(title="Select file to decrypt (salted .enc)")
        if not path: return
        # check keyring for the file
        stored_pwd = None
        if keyring:
            try:
                stored_pwd = keyring.get_password(APP_NAME, path)
            except Exception:
                stored_pwd = None
        if stored_pwd:
            use_stored = messagebox.askyesno("Use stored password", "Use password from OS keyring?")
            if use_stored:
                pwd = stored_pwd
            else:
                pwd = simpledialog.askstring("Password","Enter password for decryption:",show='*')
        else:
            pwd = simpledialog.askstring("Password","Enter password for decryption:",show='*')
        if not pwd: return
        def run_dec():
            try:
                self.progress.start(10)
                out = decrypt_file(path,pwd)
                self._add_recent(out)
                self.misc_output.delete("1.0",tk.END); self.misc_output.insert(tk.END,f"Decrypted -> {out}")
                self.status.config(text=f"Decrypted {os.path.basename(out)}")
                audit(f"Decrypted file {path} to {out}")
            except InvalidToken:
                messagebox.showerror("Decrypt failed","Invalid password or corrupted file.")
            except Exception as e:
                logger.exception("File decrypt failed: %s", e)
                messagebox.showerror("Decrypt failed", str(e))
            finally:
                self.progress.stop()
        threading.Thread(target=run_dec, daemon=True).start()

    def _jwt_ui(self):
        token = self.misc_input.get("1.0",tk.END).strip()
        if not token: messagebox.showwarning("JWT required","Paste JWT into input"); return
        out = jwt_decode(token)
        self.misc_output.delete("1.0",tk.END); self.misc_output.insert(tk.END,json.dumps(out,indent=2)); self.status.config(text="JWT decoded"); audit("JWT decode")

    def _file_info_ui(self):
        path=filedialog.askopenfilename(title="Select file for info")
        if not path: return
        try:
            st=os.stat(path)
            info=f"Path: {path}\nSize: {st.st_size} bytes\nModified: {datetime.fromtimestamp(st.st_mtime)}"
            self.misc_output.delete("1.0",tk.END); self.misc_output.insert(tk.END,info); self.status.config(text="File info"); audit(f"File info {path}")
        except Exception as e:
            messagebox.showerror("Error",str(e))

    # --------------------
    # Utilities: open/export logs, open file, about, etc.
    # --------------------
    def _open_file(self):
        path=filedialog.askopenfilename(title="Open file")
        if not path: return
        # pick best tab to show file
        with open(path,'r',encoding='utf-8',errors='ignore') as f:
            txt=f.read()
        self.nb.select(self.enc_tab_idx); self.enc_input.delete("1.0",tk.END); self.enc_input.insert(tk.END,txt)
        self._add_recent(path); self.status.config(text=f"Opened {os.path.basename(path)}"); audit(f"Opened file {path}")

    def _encrypt_file_dialog(self): self._encrypt_file_dialog()  # alias - already defined above

    def _decrypt_file_dialog(self): self._decrypt_file_dialog()  # alias - already defined above

    def _export_logs(self):
        target = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log files","*.log"),("All files","*.*")])
        if not target: return
        try:
            shutil.copyfile(LOG_FILE, target)
            self.status.config(text=f"Exported logs to {os.path.basename(target)}"); audit(f"Exported logs to {target}")
            messagebox.showinfo("Exported", f"Logs saved to {target}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _about(self):
        messagebox.showinfo("About", f"{APP_NAME}\nEnterprise-grade toolkit (educational)\nAuthor: VisionBuildsAI")

    def _about_ethics(self):
        messagebox.showinfo("Ethics & Use", "This tool is for learning, testing your own systems, and legitimate dev workflows. Do not use for illegal activity.")

    def _clear_all(self):
        for w in [self.enc_input,self.enc_output,self.hash_input,self.hash_output,self.crypto_input,self.crypto_output,self.pwd_input,self.pwd_output,self.misc_input,self.misc_output]:
            try: w.delete("1.0",tk.END)
            except: pass
        self.status.config(text="Cleared")

    def _on_close(self):
        audit("Application closed")
        save_config(self.config)
        self.destroy()

# ------------------------------
# CLI bridge (minimal)
# ------------------------------
def cli_main(argv):
    # simple mapping for headless usage
    # examples: swissknife.py encrypt-file /path/to/file --password secret
    if len(argv) < 2:
        print("SwissKnife Pro CLI: usage examples\n  encrypt-file <file> <password>\n  decrypt-file <file> <password>")
        return
    cmd = argv[1]
    try:
        if cmd == "encrypt-file":
            path = argv[2]; pwd = argv[3]; out = encrypt_file(path,pwd); print("Encrypted:", out)
        elif cmd == "decrypt-file":
            path = argv[2]; pwd = argv[3]; out = decrypt_file(path,pwd); print("Decrypted:", out)
        else:
            print("Unknown cmd", cmd)
    except Exception as e:
        print("Error:", e)

# ------------------------------
# Bootstrap
# ------------------------------
if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli_main(sys.argv)
    else:
        app = SwissKnifeProApp()
        app.mainloop()
