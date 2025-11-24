#!/usr/bin/env python3
"""
Swiss Knife - Full GUI (Grouped Sections)

Save as: SwissKnifeGUI_full.py
Run: python SwissKnifeGUI_full.py

Requirements:
- Python 3.x
- Pillow (optional, for logo) -> pip install pillow

This GUI wraps a set of safe, educational utilities:
- Base64 / Hex encode-decode
- Hash generation (md5, sha1, sha256, sha512, ...)
- Hash identification (by length heuristic)
- Dictionary "crack" demo (educational)
- Caesar cipher (enc/dec/bruteforce)
- Vigenere decrypt (requires key)
- Password entropy & strength
- Key generator
- Wordlist generator (simple mask)
- JWT decode (no verification)
- File info inspector

ETHICS: For learning only. Do not use on systems/accounts you do not own.
"""

import os
import sys
import base64
import binascii
import hashlib
import json
import re
import secrets
import string
from datetime import datetime
from math import log2
from typing import List
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

# Path to uploaded logo image (the file you uploaded). We'll try to show it.
LOGO_PATH = "/mnt/data/c5653e52-4b50-47aa-9091-c2a8122461a9.png"

# ---------------------------
# Core helpers (ported from CLI)
# ---------------------------

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

def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def decode_base64(text: str) -> str:
    try:
        return base64.b64decode(text.encode()).decode(errors='ignore')
    except Exception as e:
        return f"<decode error: {e}>"

def encode_hex(text: str) -> str:
    return binascii.hexlify(text.encode()).decode()

def decode_hex(text: str) -> str:
    try:
        return binascii.unhexlify(text.encode()).decode(errors='ignore')
    except Exception as e:
        return f"<decode error: {e}>"

def gen_hash(algo: str, text: str) -> str:
    algo = algo.lower()
    if algo not in HASH_ALGOS:
        raise ValueError("Unsupported algorithm.")
    h = HASH_ALGOS[algo]()
    h.update(text.encode())
    return h.hexdigest()

def identify_hash(hash_str: str) -> str:
    n = len(hash_str)
    mapping = {32: 'md5', 40: 'sha1', 56: 'sha224', 64: 'sha256', 96: 'sha384', 128: 'sha512'}
    return mapping.get(n, f'unknown (length {n})')

def dict_crack(algo: str, target_hashes_file: str, wordlist_file: str, case_insensitive=False):
    targets = set([x.lower() if case_insensitive else x for x in load_file_lines(target_hashes_file)])
    words = load_file_lines(wordlist_file)
    found = {}
    for w in words:
        candidate = w.strip()
        candidate_to_hash = candidate.lower() if case_insensitive else candidate
        h = gen_hash(algo, candidate_to_hash)
        if h in targets:
            found[h] = candidate
    return found

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
    if e < 28:
        return "Very weak"
    if e < 36:
        return "Weak"
    if e < 60:
        return "Reasonable"
    if e < 128:
        return "Strong"
    return "Very strong"

def gen_key(bytes_len: int) -> str:
    return secrets.token_hex(bytes_len)

def generate_wordlist_from_mask(mask: str, out_file: str, max_count=100000):
    sets = {
        '?l': string.ascii_lowercase,
        '?u': string.ascii_uppercase,
        '?d': string.digits,
        '?s': "!@#$%&*"
    }
    wildcard = None
    for token, chars in sets.items():
        if token in mask:
            wildcard = (token, chars)
            break
    results = []
    if wildcard:
        token, chars = wildcard
        prefix, suffix = mask.split(token)
        for c in chars:
            results.append(prefix + c + suffix)
            if len(results) >= max_count: break
    else:
        results.append(mask)
    with open(out_file, 'w', encoding='utf-8') as f:
        for r in results:
            f.write(r + "\n")
    return out_file

def caesar(text: str, shift: int, encrypt=True) -> str:
    if not encrypt:
        shift = -shift
    res = []
    for ch in text:
        if 'a' <= ch <= 'z':
            res.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            res.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            res.append(ch)
    return ''.join(res)

def caesar_bruteforce(ciphertext: str):
    out = []
    for s in range(1, 26):
        out.append((s, caesar(ciphertext, s, encrypt=False)))
    return out

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    res = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            offset = ord(key[ki % len(key)].lower()) - ord('a')
            res.append(chr((ord(ch) - ord(base) - offset) % 26 + ord(base)))
            ki += 1
        else:
            res.append(ch)
    return ''.join(res)

def jwt_decode(token: str) -> dict:
    try:
        parts = token.split('.')
        if len(parts) < 2:
            raise ValueError("Not a JWT")
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        payload = base64.urlsafe_b64decode(payload_b64.encode())
        return json.loads(payload.decode(errors='ignore'))
    except Exception as e:
        return {"error": str(e)}

# ---------------------------
# GUI
# ---------------------------

class SwissKnifeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ShiftMaster — Swiss Knife")
        self.geometry("1000x700")
        self.configure(bg="#071014")
        self.create_style()
        self.create_layout()
        self.set_default_values()

    def create_style(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure("TFrame", background="#071014")
        style.configure("TLabel", background="#071014", foreground="#aee8ff", font=("Consolas", 11))
        style.configure("TButton", background="#0f2b3a", foreground="#c7f0ff", font=("Consolas", 10))
        style.configure("TNotebook", background="#071014", tabposition="n")
        style.configure("TNotebook.Tab", background="#0b1b22", foreground="#bfefff", font=("Consolas", 10))

    def create_layout(self):
        top = tk.Frame(self, bg="#071014")
        top.pack(side="top", fill="x", padx=10, pady=8)
        # Logo or title
        logo_shown = False
        try:
            from PIL import Image, ImageTk
            if os.path.exists(LOGO_PATH):
                img = Image.open(LOGO_PATH).convert("RGBA")
                img = img.resize((220, 100), Image.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                lbl = tk.Label(top, image=photo, bg="#071014")
                lbl.image = photo
                lbl.pack(side="left", padx=(0,12))
                logo_shown = True
        except Exception:
            logo_shown = False
        if not logo_shown:
            title = tk.Label(top, text="ShiftMaster — Swiss Knife", fg="#9de7ff", bg="#071014", font=("Consolas", 20, "bold"))
            title.pack(side="left", padx=(6,12))

        right_hint = tk.Label(top, text="Ethics: educational use only", fg="#b4dbe6", bg="#071014", font=("Consolas", 10, "italic"))
        right_hint.pack(side="right", padx=8)

        # Main notebook with grouped tabs
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=6)

        # Encoders tab
        enc_frame = ttk.Frame(nb)
        nb.add(enc_frame, text="Encoders")

        # Hashing tab
        hash_frame = ttk.Frame(nb)
        nb.add(hash_frame, text="Hashing")

        # Crypto tab
        crypto_frame = ttk.Frame(nb)
        nb.add(crypto_frame, text="Crypto")

        # Password & Keys tab
        pass_frame = ttk.Frame(nb)
        nb.add(pass_frame, text="Passwords & Keys")

        # Misc tab
        misc_frame = ttk.Frame(nb)
        nb.add(misc_frame, text="Misc Tools")

        # ========== Encoders UI ==========
        self._build_encoders(enc_frame)

        # ========== Hashing UI ==========
        self._build_hashing(hash_frame)

        # ========== Crypto UI ==========
        self._build_crypto(crypto_frame)

        # ========== Password & Keys UI ==========
        self._build_password(pass_frame)

        # ========== Misc UI ==========
        self._build_misc(misc_frame)

        # Footer status
        self.status = tk.Label(self, text="Ready", anchor="w", bg="#021014", fg="#cfeff3", font=("Consolas", 10))
        self.status.pack(side="bottom", fill="x")

    def set_default_values(self):
        self.input_text.insert("1.0", "")
        self.shift_var.set("3")
        self.hash_algo_var.set("sha256")

    # ---------------- UI pieces for each tab ----------------
    def _common_io_widgets(self, parent):
        # returns references for input area and output area (placed inside parent)
        top = tk.Frame(parent, bg="#071014")
        top.pack(fill="x", pady=6)
        tk.Label(top, text="Input", font=("Consolas", 11, "bold")).pack(anchor="w")
        input_box = scrolledtext.ScrolledText(top, height=6, bg="#061018", fg="#dff8ff", font=("Consolas", 11))
        input_box.pack(fill="x", padx=4, pady=6)

        bottom = tk.Frame(parent, bg="#071014")
        bottom.pack(fill="both", expand=True, pady=6)
        tk.Label(bottom, text="Output", font=("Consolas", 11, "bold")).pack(anchor="w")
        output_box = scrolledtext.ScrolledText(bottom, height=10, bg="#021014", fg="#bff0ea", font=("Consolas", 11))
        output_box.pack(fill="both", expand=True, padx=4, pady=6)

        return input_box, output_box

    def _build_encoders(self, frame):
        # Left controls
        ctrl = tk.Frame(frame, bg="#071014")
        ctrl.pack(side="left", fill="y", padx=8, pady=8)
        tk.Label(ctrl, text="Encoders", font=("Consolas", 12, "bold")).pack(anchor="w", pady=(0,6))

        ttk.Button(ctrl, text="Load from file", command=self._enc_load_file).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Base64 Encode", command=self._enc_b64).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Base64 Decode", command=self._enc_b64dec).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Hex Encode", command=self._enc_hex).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Hex Decode", command=self._enc_hexdec).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Copy Output", command=self._copy_output).pack(fill="x", pady=6)

        # Right I/O
        right = tk.Frame(frame, bg="#071014")
        right.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        self.input_text, self.output_text = self._common_io_widgets(right)

    def _build_hashing(self, frame):
        ctrl = tk.Frame(frame, bg="#071014")
        ctrl.pack(side="left", fill="y", padx=8, pady=8)
        tk.Label(ctrl, text="Hashing", font=("Consolas", 12, "bold")).pack(anchor="w", pady=(0,6))

        tk.Label(ctrl, text="Algorithm:", font=("Consolas",10)).pack(anchor="w")
        self.hash_algo_var = tk.StringVar(value="sha256")
        algo_menu = ttk.Combobox(ctrl, textvariable=self.hash_algo_var, values=list(HASH_ALGOS.keys()), state="readonly", width=12)
        algo_menu.pack(pady=4)

        ttk.Button(ctrl, text="Generate Hash", command=self._hash_generate).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Identify Hash", command=self._hash_identify).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Dictionary Crack (file)", command=self._dict_crack_ui).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Copy Output", command=self._copy_output).pack(fill="x", pady=6)

        right = tk.Frame(frame, bg="#071014")
        right.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        self.hash_input, self.hash_output = self._common_io_widgets(right)

    def _build_crypto(self, frame):
        ctrl = tk.Frame(frame, bg="#071014")
        ctrl.pack(side="left", fill="y", padx=8, pady=8)
        tk.Label(ctrl, text="Crypto", font=("Consolas", 12, "bold")).pack(anchor="w", pady=(0,6))

        tk.Label(ctrl, text="Shift / Key:", font=("Consolas",10)).pack(anchor="w")
        self.shift_var = tk.StringVar(value="3")
        shift_entry = tk.Entry(ctrl, textvariable=self.shift_var, width=8, bg="#061018", fg="#dff8ff", font=("Consolas",11))
        shift_entry.pack(pady=4)

        ttk.Button(ctrl, text="Caesar Encrypt", command=self._caesar_encrypt).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Caesar Decrypt", command=self._caesar_decrypt).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Caesar Bruteforce", command=self._caesar_bruteforce).pack(fill="x", pady=4)

        tk.Label(ctrl, text="Vigenère Key:", font=("Consolas",10)).pack(anchor="w", pady=(10,0))
        self.vig_key_var = tk.StringVar()
        vig_entry = tk.Entry(ctrl, textvariable=self.vig_key_var, width=16, bg="#061018", fg="#dff8ff", font=("Consolas",11))
        vig_entry.pack(pady=4)
        ttk.Button(ctrl, text="Vigenère Decrypt", command=self._vigenere_decrypt).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Copy Output", command=self._copy_output).pack(fill="x", pady=6)

        right = tk.Frame(frame, bg="#071014")
        right.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        self.crypto_input, self.crypto_output = self._common_io_widgets(right)

    def _build_password(self, frame):
        ctrl = tk.Frame(frame, bg="#071014")
        ctrl.pack(side="left", fill="y", padx=8, pady=8)
        tk.Label(ctrl, text="Passwords & Keys", font=("Consolas", 12, "bold")).pack(anchor="w", pady=(0,6))

        ttk.Button(ctrl, text="Check Password Strength", command=self._pass_check).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Generate Random Key (bytes)", command=self._gen_key_ui).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Generate wordlist from mask", command=self._wordlist_ui).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Copy Output", command=self._copy_output).pack(fill="x", pady=6)

        right = tk.Frame(frame, bg="#071014")
        right.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        self.pass_input, self.pass_output = self._common_io_widgets(right)

    def _build_misc(self, frame):
        ctrl = tk.Frame(frame, bg="#071014")
        ctrl.pack(side="left", fill="y", padx=8, pady=8)
        tk.Label(ctrl, text="Misc Tools", font=("Consolas", 12, "bold")).pack(anchor="w", pady=(0,6))

        ttk.Button(ctrl, text="JWT Decode", command=self._jwt_ui).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Load File Info", command=self._file_info_ui).pack(fill="x", pady=4)
        ttk.Button(ctrl, text="Clear All Inputs", command=self._clear_all).pack(fill="x", pady=6)
        ttk.Button(ctrl, text="Copy Output", command=self._copy_output).pack(fill="x", pady=6)

        right = tk.Frame(frame, bg="#071014")
        right.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        self.misc_input, self.misc_output = self._common_io_widgets(right)

    # ----------------- UI action handlers -----------------

    def _enc_load_file(self):
        path = filedialog.askopenfilename(title="Choose input file", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not path: return
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                txt = f.read()
            self.input_text.delete("1.0", tk.END); self.input_text.insert(tk.END, txt)
            self.status.config(text=f"Loaded {os.path.basename(path)} into input.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load: {e}")

    def _enc_b64(self):
        txt = self.input_text.get("1.0", tk.END).strip()
        self.output_text.delete("1.0", tk.END); self.output_text.insert(tk.END, encode_base64(txt))
        self.status.config(text="Base64 encoded.")

    def _enc_b64dec(self):
        txt = self.input_text.get("1.0", tk.END).strip()
        self.output_text.delete("1.0", tk.END); self.output_text.insert(tk.END, decode_base64(txt))
        self.status.config(text="Base64 decoded.")

    def _enc_hex(self):
        txt = self.input_text.get("1.0", tk.END).strip()
        self.output_text.delete("1.0", tk.END); self.output_text.insert(tk.END, encode_hex(txt))
        self.status.config(text="Hex encoded.")

    def _enc_hexdec(self):
        txt = self.input_text.get("1.0", tk.END).strip()
        self.output_text.delete("1.0", tk.END); self.output_text.insert(tk.END, decode_hex(txt))
        self.status.config(text="Hex decoded.")

    def _hash_generate(self):
        txt = self.hash_input.get("1.0", tk.END).strip()
        algo = self.hash_algo_var.get()
        try:
            out = gen_hash(algo, txt)
        except Exception as e:
            out = f"Error: {e}"
        self.hash_output.delete("1.0", tk.END); self.hash_output.insert(tk.END, out)
        self.status.config(text=f"{algo} generated.")

    def _hash_identify(self):
        txt = self.hash_input.get("1.0", tk.END).strip()
        out = identify_hash(txt)
        self.hash_output.delete("1.0", tk.END); self.hash_output.insert(tk.END, out)
        self.status.config(text="Hash type identified (naive).")

    def _dict_crack_ui(self):
        target = filedialog.askopenfilename(title="Choose target-hash file", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not target:
            return
        wordlist = filedialog.askopenfilename(title="Choose wordlist file", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not wordlist:
            return
        algo = self.hash_algo_var.get()
        self.status.config(text="Running dictionary check (educational)...")
        found = dict_crack(algo, target, wordlist)
        self.hash_output.delete("1.0", tk.END)
        if not found:
            self.hash_output.insert(tk.END, "No matches found (educational).")
            self.status.config(text="Dictionary check complete: none found.")
        else:
            for h, w in found.items():
                self.hash_output.insert(tk.END, f"{h} => {w}\n")
            self.status.config(text=f"Found {len(found)} matches (educational).")

    def _caesar_encrypt(self):
        txt = self.crypto_input.get("1.0", tk.END).strip()
        try:
            s = int(self.shift_var.get())
        except:
            messagebox.showerror("Error", "Shift must be an integer.")
            return
        self.crypto_output.delete("1.0", tk.END); self.crypto_output.insert(tk.END, caesar(txt, s, encrypt=True))
        self.status.config(text=f"Caesar encrypted with shift {s}.")

    def _caesar_decrypt(self):
        txt = self.crypto_input.get("1.0", tk.END).strip()
        try:
            s = int(self.shift_var.get())
        except:
            messagebox.showerror("Error", "Shift must be an integer.")
            return
        self.crypto_output.delete("1.0", tk.END); self.crypto_output.insert(tk.END, caesar(txt, s, encrypt=False))
        self.status.config(text=f"Caesar decrypted with shift {s}.")

    def _caesar_bruteforce(self):
        txt = self.crypto_input.get("1.0", tk.END).strip()
        lines = caesar_bruteforce(txt)
        out = "\n".join([f"[{s}] {t}" for s,t in lines])
        self.crypto_output.delete("1.0", tk.END); self.crypto_output.insert(tk.END, out)
        self.status.config(text="Caesar brute-force complete.")

    def _vigenere_decrypt(self):
        txt = self.crypto_input.get("1.0", tk.END).strip()
        key = self.vig_key_var.get().strip()
        if not key:
            messagebox.showwarning("Key required", "Please provide a Vigenère key.")
            return
        self.crypto_output.delete("1.0", tk.END); self.crypto_output.insert(tk.END, vigenere_decrypt(txt, key))
        self.status.config(text="Vigenère decrypt attempted.")

    def _pass_check(self):
        txt = self.pass_input.get("1.0", tk.END).strip()
        e = password_entropy(txt)
        out = f"Entropy: {e:.2f} bits — Strength: {password_strength(txt)}"
        self.pass_output.delete("1.0", tk.END); self.pass_output.insert(tk.END, out)
        self.status.config(text="Password check done.")

    def _gen_key_ui(self):
        d = tk.simpledialog.askinteger("Key length", "Enter number of bytes for key (e.g., 16):", minvalue=1, maxvalue=256)
        if d is None:
            return
        k = gen_key(d)
        self.pass_output.delete("1.0", tk.END); self.pass_output.insert(tk.END, k)
        self.status.config(text=f"Generated {d}-byte key.")

    def _wordlist_ui(self):
        mask = tk.simpledialog.askstring("Mask", "Enter mask (e.g., pass?d or hello?l):")
        if not mask:
            return
        out_file = filedialog.asksaveasfilename(title="Save wordlist as", defaultextension=".txt", filetypes=[("Text files","*.txt")])
        if not out_file:
            return
        generate_wordlist_from_mask(mask, out_file)
        self.pass_output.delete("1.0", tk.END); self.pass_output.insert(tk.END, f"Saved: {out_file}")
        self.status.config(text=f"Wordlist generated ({out_file}).")

    def _jwt_ui(self):
        token = self.misc_input.get("1.0", tk.END).strip()
        if not token:
            messagebox.showwarning("JWT required", "Paste a JWT token into input first.")
            return
        out = jwt_decode(token)
        self.misc_output.delete("1.0", tk.END); self.misc_output.insert(tk.END, json.dumps(out, indent=2))
        self.status.config(text="JWT decoded (no verification).")

    def _file_info_ui(self):
        path = filedialog.askopenfilename(title="Select a file")
        if not path:
            return
        try:
            st = os.stat(path)
            info = f"Path: {path}\nSize: {st.st_size} bytes\nModified: {datetime.fromtimestamp(st.st_mtime)}"
            self.misc_output.delete("1.0", tk.END); self.misc_output.insert(tk.END, info)
            self.status.config(text=f"File info for {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _copy_output(self):
        # copy currently visible output (prioritize active tab outputs)
        for box in [self.output_text, self.hash_output, self.crypto_output, self.pass_output, self.misc_output]:
            try:
                data = box.get("1.0", tk.END).strip()
                if data:
                    self.clipboard_clear(); self.clipboard_append(data)
                    self.status.config(text="Output copied to clipboard")
                    return
            except Exception:
                continue
        self.status.config(text="No output to copy")

    def _clear_all(self):
        for b in [self.input_text, self.output_text, self.hash_input, self.hash_output,
                  self.crypto_input, self.crypto_output, self.pass_input, self.pass_output,
                  self.misc_input, self.misc_output]:
            try:
                b.delete("1.0", tk.END)
            except Exception:
                pass
        self.status.config(text="Cleared all inputs & outputs.")

# ---------------------------
# Run the app
# ---------------------------

def main():
    app = SwissKnifeApp()
    app.mainloop()

if __name__ == "__main__":
    main()
