import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

# -----------------------------
# Encryption Functions
# -----------------------------

def caesar_cipher(text, shift, encrypt=True):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    shift = shift if encrypt else -shift
    result = ""
    for char in text:
        if char.lower() in alphabet:
            idx = (alphabet.index(char.lower()) + shift) % 26
            new_char = alphabet[idx]
            result += new_char.upper() if char.isupper() else new_char
        else:
            result += char
    return result

def aes_encrypt(text, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def aes_decrypt(data, key):
    data = base64.b64decode(data)
    key = hashlib.sha256(key.encode()).digest()
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def base64_encrypt(text):
    return base64.b64encode(text.encode()).decode()

def base64_decrypt(text):
    return base64.b64decode(text).decode()

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


# -----------------------------
# GUI Logic
# -----------------------------

def process_action():
    method = method_choice.get()
    mode = mode_choice.get()
    text = input_box.get("1.0", tk.END).strip()
    key = key_entry.get()

    try:
        if method == "Caesar Cipher":
            shift = int(caesar_shift.get())
            result = caesar_cipher(text, shift, encrypt=(mode == "Encrypt"))

        elif method == "AES (Advanced Encryption)":
            if not key:
                return messagebox.showerror("Error", "AES requires a key")
            result = aes_encrypt(text, key) if mode == "Encrypt" else aes_decrypt(text, key)

        elif method == "Base64":
            result = base64_encrypt(text) if mode == "Encrypt" else base64_decrypt(text)

        elif method == "SHA-256 Hash":
            if mode == "Decrypt":
                return messagebox.showwarning("Note", "Hashes cannot be decrypted.")
            result = sha256_hash(text)

        else:
            result = "Invalid Option"

        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, result)

    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{e}")


# -----------------------------
# Main GUI
# -----------------------------

root = tk.Tk()
root.title("ShiftMaster PRO — Encryption Suite")
root.geometry("850x600")
root.config(bg="#0e0e0e")

# Title
title = tk.Label(root, text="SHIFTMASTER PRO", fg="#00ffea",
                 bg="#0e0e0e", font=("Consolas", 28, "bold"))
title.pack(pady=10)

# Frame
main_frame = tk.Frame(root, bg="#0e0e0e")
main_frame.pack(fill="both", expand=True)

# Method Picker
method_label = tk.Label(main_frame, text="Encryption Method:", bg="#0e0e0e", fg="#ccc")
method_label.grid(row=0, column=0, sticky="w", padx=10, pady=5)

method_choice = ttk.Combobox(main_frame, values=[
    "AES (Advanced Encryption)",
    "Caesar Cipher",
    "Base64",
    "SHA-256 Hash"
], width=30)
method_choice.current(0)
method_choice.grid(row=0, column=1, padx=10, pady=5)

# Mode Picker
mode_choice = ttk.Combobox(main_frame, values=["Encrypt", "Decrypt"], width=15)
mode_choice.current(0)
mode_choice.grid(row=0, column=2, padx=10)

# Key entry (only needed for some methods)
key_label = tk.Label(main_frame, text="Key (AES / Optional):", bg="#0e0e0e", fg="#ccc")
key_label.grid(row=1, column=0, sticky="w", padx=10)

key_entry = tk.Entry(main_frame, width=40, bg="#1e1e1e", fg="white")
key_entry.grid(row=1, column=1, pady=5)

# Caesar shift
caesar_shift = tk.Entry(main_frame, width=10, bg="#1e1e1e", fg="white")
caesar_shift.insert(0, "3")
caesar_shift.grid(row=1, column=2)

# Input box
input_label = tk.Label(main_frame, text="Input Text:", bg="#0e0e0e", fg="#ccc")
input_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

input_box = scrolledtext.ScrolledText(main_frame, width=80, height=10, bg="#1a1a1a", fg="#00ffea")
input_box.grid(row=3, column=0, columnspan=3, padx=10)

# Output box
output_label = tk.Label(main_frame, text="Output:", bg="#0e0e0e", fg="#ccc")
output_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")

output_box = scrolledtext.ScrolledText(main_frame, width=80, height=10, bg="#1a1a1a", fg="#00ffea")
output_box.grid(row=5, column=0, columnspan=3, padx=10)

# Process Button
process_btn = tk.Button(root, text="RUN", command=process_action,
                        bg="#00ffea", fg="black", font=("Consolas", 18, "bold"),
                        width=20)
process_btn.pack(pady=20)

root.mainloop()
