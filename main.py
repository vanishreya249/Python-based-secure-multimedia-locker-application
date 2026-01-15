import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os, hashlib, base64
from cryptography.fernet import Fernet

# ===== CONFIG =====
USERNAME = os.getenv("APP_USERNAME")
PASSWORD = os.getenv("APP_PASSWORD")
UPLOAD_DIR = "secure_uploads"

os.makedirs(UPLOAD_DIR, exist_ok=True)

# ===== ENCRYPTION KEY =====
def key_from_password(password):
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode()).digest()
    )

# ===== LOGIN WINDOW =====
def login():
    user = username_entry.get()
    pwd = password_entry.get()

    if user == USERNAME and pwd == PASSWORD:
        login_window.destroy()
        open_main_window()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

# ===== FILE UPLOAD + ENCRYPT =====
def upload_and_encrypt():
    file_path = filedialog.askopenfilename(
        title="Select File to Encrypt",
        filetypes=[("All Files", "*.*")]
    )

    if not file_path:
        return

    file_password = simpledialog.askstring(
        "File Encryption Password",
        "Enter password to encrypt this file:",
        show="*"
    )

    if not file_password:
        messagebox.showerror("Error", "Encryption password is required")
        return

    with open(file_path, "rb") as f:
        data = f.read()

    cipher = Fernet(key_from_password(file_password))
    encrypted_data = cipher.encrypt(data)

    filename = os.path.basename(file_path)
    save_path = os.path.join(UPLOAD_DIR, filename + ".enc")

    with open(save_path, "wb") as f:
        f.write(encrypted_data)

    messagebox.showinfo(
        "Success",
        "File encrypted and securely stored.\n\n"
        f"Location:\n{save_path}"
    )

# ===== MAIN WINDOW =====
def open_main_window():
    main = tk.Tk()
    main.title("Secure Multimedia Locker")
    main.geometry("420x240")

    tk.Label(
        main,
        text="Secure Multimedia Locker",
        font=("Arial", 14, "bold")
    ).pack(pady=20)

    tk.Label(
        main,
        text="Upload & encrypt audio, video, images, text, PDFs, and more",
        wraplength=380
    ).pack(pady=5)

    tk.Button(
        main,
        text="Upload & Encrypt File",
        width=25,
        height=2,
        command=upload_and_encrypt
    ).pack(pady=25)

    tk.Button(
        main,
        text="Exit",
        width=15,
        command=main.destroy
    ).pack(pady=10)

    main.mainloop()

# ===== LOGIN UI =====
login_window = tk.Tk()
login_window.title("Login")
login_window.geometry("350x220")

tk.Label(
    login_window,
    text="Secure Multimedia Locker Login",
    font=("Arial", 14, "bold")
).pack(pady=15)

tk.Label(login_window, text="Username").pack()
username_entry = tk.Entry(login_window)
username_entry.pack()

tk.Label(login_window, text="Password").pack()
password_entry = tk.Entry(login_window, show="*")
password_entry.pack()

tk.Button(
    login_window,
    text="Login",
    width=15,
    command=login
).pack(pady=20)

login_window.mainloop()
