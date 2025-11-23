import tkinter as tk
from tkinter import messagebox

#-----------------------
# Caesar Cipher Core Logic
#-----------------------

def caesar(text, shift=3, encrypt=True):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    upper_alphabet = alphabet.upper()
    if not encrypt:
        shift = -shift
    result = ''
    for char in text:
        if char in alphabet:
            index = (alphabet.index(char) + shift) % 26
            result += alphabet[index]
        elif char in upper_alphabet:
            index = (upper_alphabet.index(char) + shift) % 26
            result += upper_alphabet[index]
        else:
            result += char
    return result

def encrypt():
    try:
        shift = int(shift_entry.get())
        text = input_text.get("1.0", tk.END)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, caesar(text, shift, True))
    except:
        messagebox.showerror("Error", "Shift must be an integer!.")
def decrypt():
    try:
        shift = int(shift_entry.get())
        text = input_text.get("1.0", tk.END)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, caesar(text, shift, False))
    except:
        messagebox.showerror("Error", "Shift must be an integer!.")

#-----------------------
# GUI Setup
#-----------------------
root = tk.Tk()
root.title("ShiftMaster - Caesar Cipher")
root.geometry("500x600")
root.config(bg="#1a1a1a")

title_label = tk.Label(root, text="ShiftMaster - Caesar Cipher", font=("Helvetica", 18, "bold"), bg="#1a1a1a", fg="white")
title_label.pack(pady=10)

# Input Text
input_label = tk.Label(root, text="Enter your Text:", font=("Helvetica", 14), bg="#1a1a1a", fg="white")
input_label.pack()
input_text = tk.Text(root, height=10, width=50, font=("Helvetica", 12), bg="#222", fg="white")
input_text.pack(pady=5)

# Shift
shift_label = tk.Label(root, text="Shift (1–25):", fg="white", bg="#1a1a1a")
shift_label.pack()
shift_entry = tk.Entry(root, width=10, bg="#222", fg="white")
shift_entry.insert(0, "3")
shift_entry.pack(pady=5)

# Buttons
btn_frame = tk.Frame(root, bg="#1a1a1a")
btn_frame.pack(pady=10)

encrypt_btn = tk.Button(btn_frame, text="Encrypt", width=12, command=encrypt, bg="#0077ff", fg="white")
encrypt_btn.grid(row=0, column=0, padx=10)

decrypt_btn = tk.Button(btn_frame, text="Decrypt", width=12, command=decrypt, bg="#0077ff", fg="white")
decrypt_btn.grid(row=0, column=1, padx=10)

# Output
output_label = tk.Label(root, text="Output:", fg="white", bg="#1a1a1a")
output_label.pack()
output_text = tk.Text(root, height=8, width=50, bg="#222", fg="white")
output_text.pack(pady=5)

root.mainloop()