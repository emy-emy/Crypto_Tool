import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from hashlib import sha512
import base64
import random

# RSA Functions
def rsa_generate_keys():
    key = RSA.generate(2048)
    return key, key.publickey()

def rsa_encrypt(public_key, plaintext):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext)).decode()
    return decrypted

def rsa_sign(private_key, message):
    hash_val = int.from_bytes(sha512(message.encode()).digest(), byteorder='big')
    signature = pow(hash_val, private_key.d, private_key.n)
    return str(signature)

def rsa_verify(public_key, message, signature):
    hash_val = int.from_bytes(sha512(message.encode()).digest(), byteorder='big')
    signature_val = int(signature)
    hash_from_signature = pow(signature_val, public_key.e, public_key.n)
    return hash_val == hash_from_signature

# ElGamal Functions
def elgamal_generate_keys():
    p = getPrime(256)
    g = random.randint(2, p - 1)
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y, x)

def elgamal_encrypt(p, g, y, message):
    m = bytes_to_long(message.encode())
    k = random.randint(1, p - 2)
    a = pow(g, k, p)
    b = (pow(y, k, p) * m) % p
    return (a, b)

def elgamal_decrypt(p, x, a, b):
    s = pow(a, x, p)
    m = (b * inverse(s, p)) % p
    return long_to_bytes(m).decode()

# GUI
def open_asymmetric_window():
    win = tk.Toplevel()
    win.title("Asymmetric Encryption")
    win.geometry("650x600")
    win.configure(bg="#1e1e1e")

    tk.Label(win, text="ASYMMETRIC ENCRYPTION", font=("Helvetica", 20, "bold"), fg="cyan", bg="#1e1e1e").pack(pady=10)

    tk.Label(win, text="Enter text:", fg="white", bg="#1e1e1e").pack()
    input_entry = tk.Entry(win, width=60, font=("Arial", 12))
    input_entry.pack(pady=5)

    tk.Label(win, text="Select algorithm:", fg="white", bg="#1e1e1e").pack()
    algo_var = tk.StringVar()
    algo_menu = ttk.Combobox(win, textvariable=algo_var, state="readonly", width=20)
    algo_menu['values'] = ['RSA', 'ElGamal']
    algo_menu.pack(pady=5)

    tk.Label(win, text="Select action:", fg="white", bg="#1e1e1e").pack()
    action_var = tk.StringVar()
    action_menu = ttk.Combobox(win, textvariable=action_var, state="readonly", width=20)
    action_menu.pack(pady=5)

    def update_actions(*args):
        algo = algo_var.get()
        if algo == "RSA":
            action_menu['values'] = ['Encrypt', 'Sign']
            action_menu.current(0)
        elif algo == "ElGamal":
            action_menu['values'] = ['Encrypt']
            action_menu.current(0)

    algo_menu.bind("<<ComboboxSelected>>", update_actions)

    result_label = tk.Label(win, text="", fg="cyan", bg="#1e1e1e", font=("Consolas", 10), wraplength=600, justify="left")
    result_label.pack(pady=10)

    keys = {}

    def perform_action():
        text = input_entry.get()
        algo = algo_var.get()
        action = action_var.get()

        if not text or not algo or not action:
            messagebox.showwarning("Input Missing", "Please fill all fields.")
            return

        try:
            if algo == "RSA":
                private_key, public_key = rsa_generate_keys()
                keys['rsa_priv'] = private_key
                keys['rsa_pub'] = public_key
                if action == "Encrypt":
                    ciphertext = rsa_encrypt(public_key, text)
                    keys['last_cipher'] = ciphertext
                    result_label.config(text=f"[RSA Encryption]\n{ciphertext}")
                elif action == "Sign":
                    signature = rsa_sign(private_key, text)
                    keys['last_signature'] = signature
                    keys['original_msg'] = text
                    result_label.config(text=f"[RSA Signature]\n{signature}")
            elif algo == "ElGamal":
                p, g, y, x = elgamal_generate_keys()
                a, b = elgamal_encrypt(p, g, y, text)
                keys['elgamal'] = (p, g, y, x, a, b)
                ciphertext = f"{a}:{b}"
                keys['last_cipher_elgamal'] = ciphertext
                result_label.config(text=f"[ElGamal Encryption]\nEncrypted = {ciphertext}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_or_verify():
        algo = algo_var.get()
        action = action_var.get()

        try:
            if algo == "RSA":
                if action == "Encrypt":
                    ciphertext = keys.get('last_cipher', '')
                    if 'rsa_priv' not in keys or not ciphertext:
                        raise ValueError("No data to decrypt.")
                    decrypted = rsa_decrypt(keys['rsa_priv'], ciphertext)
                    result_label.config(text=f"[RSA Decryption]\n{decrypted}")
                elif action == "Sign":
                    valid = rsa_verify(keys['rsa_pub'], keys['original_msg'], keys['last_signature'])
                    result_label.config(text=f"[RSA Signature Verification]\nValid: {valid}")
            elif algo == "ElGamal":
                if 'elgamal' not in keys:
                    raise ValueError("No ElGamal data found.")
                p, g, y, x, a, b = keys['elgamal']
                decrypted = elgamal_decrypt(p, x, a, b)
                result_label.config(text=f"[ElGamal Decryption]\n{decrypted}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    tk.Button(win, text="Execute", command=perform_action, bg="#444", fg="white", width=20).pack(pady=5)
    tk.Button(win, text="Decrypt / Verify", command=decrypt_or_verify, bg="#444", fg="white", width=20).pack(pady=5)
