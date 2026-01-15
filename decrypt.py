import os
import hashlib
import base64
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.fernet import Fernet


def key_from_password(password):
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode()).digest()
    )


def decrypt_file():
    root = tk.Tk()
    root.withdraw()

    enc_file = filedialog.askopenfilename(
        title="Select Encrypted File",
        initialdir="secure_uploads",
        filetypes=[("Encrypted Files", "*.enc")]
    )

    if not enc_file:
        messagebox.showerror("Error", "No encrypted file selected")
        root.destroy()
        return

    password = simpledialog.askstring(
        "Decryption Password",
        "Enter password:",
        show="*",
        parent=root
    )

    if not password:
        messagebox.showerror("Error", "Password is required")
        root.destroy()
        return

    try:
        with open(enc_file, "rb") as f:
            encrypted_data = f.read()

        cipher = Fernet(key_from_password(password))
        decrypted_data = cipher.decrypt(encrypted_data)

        # HASH CHECK
        decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()
        print("DECRYPTED FILE HASH:", decrypted_hash)

        original_name = os.path.basename(enc_file).replace(".enc", "")
        os.makedirs("decrypted_output", exist_ok=True)
        
        output_path = os.path.join("decrypted_output", original_name)

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        messagebox.showinfo(
            "Success",
            f"Decryption successful!\n\nSaved at:\n{output_path}"
        )

    except Exception:
        messagebox.showerror(
            "Decryption Failed",
            "Wrong password or corrupted file"
        )

    root.destroy()


decrypt_file()
