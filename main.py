import tkinter as tk
from SymmetricEncryption import SymmetricEncryption
from AsymmetricEncryption import AsymmetricEncryption
from Hashing import Hashing
from gui_encoding import open_encoding_window  
from gui_hashing import open_hashing_window
from gui_symmetric import open_symmetric_window
from gui_asymmetric import open_asymmetric_window
from gui_cracker import open_cracker_window
def hashing_window():
    open_hashing_window()

def pwd_cracker_window():
    open_cracker_window()

def symmetric_encrypt_window():
    open_symmetric_window()

def asymmetric_encrypt_window():
    open_asymmetric_window()

def encoding_window():
    open_encoding_window() 
    
# Fenêtre principale
root = tk.Tk()
root.title("CryptoTool Imen Ouled Belgacem ")
root.geometry("400x450")
root.configure(bg="#1e1e1e")  

# Titre
title = tk.Label(root, text="CryptoTool", font=("Helvetica", 14,"bold"), fg="cyan", bg="#1e1e1e")
title.pack(pady=20)

buttons = [
    ("Hashing", hashing_window),
    ("Password Cracker", pwd_cracker_window),
    ("Symmetric Encryption", symmetric_encrypt_window),
    ("Encoding", encoding_window),  
    ("Asymmetric Encryption", asymmetric_encrypt_window),
    ("Quit", root.quit)
]


for text, command in buttons:
    btn = tk.Button(
        root, text=text, command=command,
        font=("Consolas", 12), bg="#2e2e2e", fg="white",
        activebackground="#3e3e3e", width=25, pady=5
    )
    btn.pack(pady=5)

root.mainloop()
