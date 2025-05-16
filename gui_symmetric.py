import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from Crypto.Cipher import AES, Salsa20
from Crypto.Random import get_random_bytes
import base64

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def encrypt_AES(text, key):
    key = key.encode('utf-8').ljust(16, b'0')[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(text).encode())
    return base64.b64encode(ciphertext).decode()

def decrypt_AES(ciphertext, key):
    key = key.encode('utf-8').ljust(16, b'0')[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext)).decode().rstrip()
    return decrypted

def encrypt_salsa20(text, key):
    key = key.encode('utf-8').ljust(32, b'0')[:32]
    cipher = Salsa20.new(key=key)
    msg = cipher.nonce + cipher.encrypt(text.encode())
    return base64.b64encode(msg).decode()

def decrypt_salsa20(ciphertext, key):
    key = key.encode('utf-8').ljust(32, b'0')[:32]
    raw = base64.b64decode(ciphertext)
    nonce = raw[:8]
    cipher = Salsa20.new(key=key, nonce=nonce)
    return cipher.decrypt(raw[8:]).decode()

def open_symmetric_window():
    win = tk.Toplevel()
    win.title("Symmetric Encryption")
    win.geometry("600x600")
    win.configure(bg="#1e1e1e")

    tk.Label(win, text="SYMMETRIC ENCRYPTION", font=("Helvetica", 18, "bold"), fg="cyan", bg="#1e1e1e").pack(pady=10)

    # Texte à chiffrer
    tk.Label(win, text="Text to encrypt:", fg="white", bg="#1e1e1e").pack()
    input_entry = tk.Entry(win, width=50, font=("Arial", 12))
    input_entry.pack(pady=5)

    # Texte chiffré (pour déchiffrement)
    tk.Label(win, text="Encrypted text to decrypt:", fg="white", bg="#1e1e1e").pack()
    encrypted_entry = tk.Entry(win, width=50, font=("Arial", 12))
    encrypted_entry.pack(pady=5)

    # Clé
    tk.Label(win, text="Enter key (max 32 chars):", fg="white", bg="#1e1e1e").pack()
    key_entry = tk.Entry(win, width=30, font=("Arial", 12), show="*")
    key_entry.pack(pady=5)

    # Méthode
    tk.Label(win, text="Select algorithm:", fg="white", bg="#1e1e1e").pack()
    algo_var = tk.StringVar()
    algo_menu = ttk.Combobox(win, textvariable=algo_var, state="readonly", width=20)
    algo_menu['values'] = ['AES', 'Salsa20']
    algo_menu.pack(pady=5)

    result_label = tk.Label(win, text="", fg="lightgreen", bg="#1e1e1e", font=("Consolas", 10), wraplength=550)
    result_label.pack(pady=10)

    def encrypt_action():
        text = input_entry.get()
        key = key_entry.get()
        algo = algo_var.get()
        if not text or not key or not algo:
            messagebox.showwarning("Missing info", "Please fill in all fields.")
            return
        try:
            if algo == "AES":
                result = encrypt_AES(text, key)
            else:
                result = encrypt_salsa20(text, key)
            result_label.config(text=f"Encrypted:\n{result}")
            encrypted_entry.delete(0, tk.END)
            encrypted_entry.insert(0, result)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_action():
        text = encrypted_entry.get()
        key = key_entry.get()
        algo = algo_var.get()
        if not text or not key or not algo:
            messagebox.showwarning("Missing info", "Please fill in all fields.")
            return
        try:
            if algo == "AES":
                result = decrypt_AES(text, key)
            else:
                result = decrypt_salsa20(text, key)
            result_label.config(text=f"Decrypted:\n{result}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    tk.Button(win, text="Encrypt", command=encrypt_action, bg="#2e2e2e", fg="white", width=20).pack(pady=10)
    tk.Button(win, text="Decrypt", command=decrypt_action, bg="#444444", fg="white", width=20).pack(pady=5)