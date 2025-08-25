from file_encryptor import encrypt_file, decrypt_file
import tkinter as tk
from tkinter import filedialog, messagebox

def select_file():
    path = filedialog.askopenfilename()
    entry_file.delete(0, tk.END)
    entry_file.insert(0, path)

def run_action():
    file_path = entry_file.get()
    password = entry_pass.get()
    mode = action_var.get()

    if not file_path or not password:
        messagebox.showerror("Error", "Select a file and enter a password.")
        return

    try:
        if mode == "Encrypt":
            encrypt_file(file_path, password)
            messagebox.showinfo("Success", "File encrypted successfully!")
        else:
            decrypt_file(file_path, password)
            messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

root = tk.Tk()
root.title("AES File Encryptor")
root.geometry("500x200")

tk.Label(root, text="File:").grid(row=0, column=0)
entry_file = tk.Entry(root, width=40)
entry_file.grid(row=0, column=1)
tk.Button(root, text="Browse", command=select_file).grid(row=0, column=2)

tk.Label(root, text="Password:").grid(row=1, column=0)
entry_pass = tk.Entry(root, show="*", width=40)
entry_pass.grid(row=1, column=1)

action_var = tk.StringVar(value="Encrypt")
tk.Radiobutton(root, text="Encrypt", variable=action_var, value="Encrypt").grid(row=2, column=0)
tk.Radiobutton(root, text="Decrypt", variable=action_var, value="Decrypt").grid(row=2, column=1)

tk.Button(root, text="Run", command=run_action).grid(row=3, column=1, pady=10)

root.mainloop()
