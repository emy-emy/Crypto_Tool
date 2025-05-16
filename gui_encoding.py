import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from Encoding import Encoding  

def open_encoding_window():
    enc_window = tk.Toplevel()
    enc_window.title("Encoding")
    enc_window.geometry("500x500")
    enc_window.configure(bg="#1e1e1e")

    # Label titre
    tk.Label(enc_window, text="ENCODING", font=("Helvetica", 20, "bold"), fg="cyan", bg="#1e1e1e").pack(pady=10)

    # Zone input
    tk.Label(enc_window, text="Enter your text:", fg="white", bg="#1e1e1e", font=("Arial", 12)).pack()
    input_entry = tk.Entry(enc_window, font=("Arial", 12), width=40)
    input_entry.pack(pady=10)

    # Choix méthode
    tk.Label(enc_window, text="Choose encoding method:", fg="white", bg="#1e1e1e", font=("Arial", 12)).pack()
    method_var = tk.StringVar()
    method_menu = ttk.Combobox(enc_window, textvariable=method_var, state="readonly", width=20)
    method_menu['values'] = ['utf8', 'ascii', 'base16', 'base32', 'base64', 'custom']
    method_menu.pack(pady=5)

    # Résultat
    result_label = tk.Label(enc_window, text="", fg="lightgreen", bg="#1e1e1e", font=("Consolas", 12))
    result_label.pack(pady=15)

    # Résultat du décryptage
    decode_result_label = tk.Label(enc_window, text="", fg="orange", bg="#1e1e1e", font=("Consolas", 12))
    decode_result_label.pack()

    def encode_action():
        data = input_entry.get()
        method = method_var.get()
        if not data or not method:
            messagebox.showwarning("Input Missing", "Please enter text and select a method.")
            return
        try:
            encoded = Encoding.encode(data, method)
            result_label.config(text=f"Encoded: {encoded}")

            def decode_action():
                decoded = Encoding.decode(encoded, method)
                decode_result_label.config(text=f"Decoded: {decoded}")

            decode_btn = tk.Button(enc_window, text="Decode", command=decode_action,
                                   bg="#444", fg="white", font=("Arial", 11))
            decode_btn.pack(pady=10)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    # Bouton Encode
    encode_btn = tk.Button(enc_window, text="Encode", command=encode_action,
                           bg="#2e2e2e", fg="white", font=("Arial", 12), width=20)
    encode_btn.pack(pady=10)
