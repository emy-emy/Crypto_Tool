import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import hashlib

def hash_text(text, method):
    h = hashlib.new(method)
    h.update(text.encode())
    return h.hexdigest()

def open_hashing_window():
    window = tk.Toplevel()
    window.title("Hashing")
    window.geometry("500x400")
    window.configure(bg="#1e1e1e")

    tk.Label(window, text="HASHING", font=("Helvetica", 20, "bold"), fg="cyan", bg="#1e1e1e").pack(pady=10)

    # Input texte
    tk.Label(window, text="Enter your text:", fg="white", bg="#1e1e1e", font=("Arial", 12)).pack()
    input_entry = tk.Entry(window, font=("Arial", 12), width=40)
    input_entry.pack(pady=10)

    # Méthode hashing
    tk.Label(window, text="Choose hash method:", fg="white", bg="#1e1e1e", font=("Arial", 12)).pack()
    method_var = tk.StringVar()
    method_menu = ttk.Combobox(window, textvariable=method_var, state="readonly", width=20)
    method_menu['values'] = ['md5', 'sha1', 'sha256', 'sha512']
    method_menu.pack(pady=5)

    # Résultat
    result_label = tk.Label(window, text="", fg="lightgreen", bg="#1e1e1e", font=("Consolas", 10), wraplength=450, justify="left")
    result_label.pack(pady=15)

    def hash_action():
        text = input_entry.get()
        method = method_var.get()
        if not text or not method:
            messagebox.showwarning("Input Missing", "Please enter text and select a hash method.")
            return
        try:
            result = hash_text(text, method)
            result_label.config(text=f"{method}:\n{result}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # Bouton
    hash_btn = tk.Button(window, text="Generate Hash", command=hash_action,
                         bg="#2e2e2e", fg="white", font=("Arial", 12), width=20)
    hash_btn.pack(pady=10)
