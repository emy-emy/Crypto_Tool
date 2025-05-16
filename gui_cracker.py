import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib

def crack_password(hash_input, wordlist_path, algo='md5'):
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for word in f:
            word = word.strip()
            h = hashlib.new(algo)
            h.update(word.encode())
            if h.hexdigest() == hash_input:
                return word
    return None

def open_cracker_window():
    win = tk.Toplevel()
    win.title("Password Cracker")
    win.geometry("600x400")
    win.configure(bg="#1e1e1e")

    tk.Label(win, text="PASSWORD CRACKER", font=("Helvetica", 20, "bold"), fg="cyan", bg="#1e1e1e").pack(pady=10)

    # Hash input
    tk.Label(win, text="Enter Hash:", fg="white", bg="#1e1e1e").pack()
    hash_entry = tk.Entry(win, width=60)
    hash_entry.pack(pady=5)

    # Hash algorithm
    tk.Label(win, text="Select algorithm:", fg="white", bg="#1e1e1e").pack()
    algo_var = tk.StringVar(value="md5")
    algo_menu = tk.OptionMenu(win, algo_var, "md5", "sha1", "sha256")
    algo_menu.pack(pady=5)

    # Result
    result_label = tk.Label(win, text="", fg="cyan", bg="#1e1e1e")
    result_label.pack(pady=10)

    def browse_wordlist():
        path = filedialog.askopenfilename(title="Select Wordlist")
        if path:
            wordlist_path.set(path)

    wordlist_path = tk.StringVar()
    tk.Button(win, text="Select Wordlist", command=browse_wordlist, bg="#444", fg="white").pack()
    tk.Label(win, textvariable=wordlist_path, fg="gray", bg="#1e1e1e").pack(pady=5)

    def start_cracking():
        hash_val = hash_entry.get()
        path = wordlist_path.get()
        algo = algo_var.get()
        if not hash_val or not path:
            messagebox.showwarning("Missing", "Please enter hash and select wordlist.")
            return
        result = crack_password(hash_val, path, algo)
        if result:
            result_label.config(text=f"Password found: {result}")
        else:
            result_label.config(text="Password not found in wordlist.")

    tk.Button(win, text="Crack Password", command=start_cracking, bg="#666", fg="white").pack(pady=10)
