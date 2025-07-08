import importlib.util
import os
import re
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
from main_internship import add, view, search, update_entry, delete, export_entries, export_passwords, import_passwords

# Dynamically load breach_checker.py (helps with PyInstaller packaging)
spec = importlib.util.spec_from_file_location("breach_checker", os.path.join(os.path.dirname(__file__), "breach_checker.py"))
breach_checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(breach_checker)

check_pwned_password = breach_checker.check_pwned_password


root = tk.Tk()
root.title('Password Manager')
root.geometry('600x500')

last_activity = time.time()

account_label = tk.Label(root, text='Account:')
account_label.pack()
account_entry = tk.Entry(root, width=50)
password_label = tk.Label(root, text='Password:')
password_label.pack()
account_entry.pack()

username_label = tk.Label(root, text='Username:')
username_label.pack()
username_entry = tk.Entry(root, width=50)
username_entry.pack()

password_entry = tk.Entry(root, width=50, show='*')
password_entry.pack()

show_password_var = tk.BooleanVar()
def toggle_password():
    if show_password_var.get():
        password_entry.config(show='')
    else:
        password_entry.config(show='*')
tk.Checkbutton(root, text="Show Password", variable=show_password_var, command=toggle_password).pack()

status_label = tk.Label(root, text='', fg='green')
status_label.pack()

output = scrolledtext.ScrolledText(root, height=10, width=70)
output.pack(pady=10)

def reset_timer():
    global last_activity
    last_activity = time.time()
    root.after(60000, check_timeout)

def check_timeout():
    global last_activity
    if time.time() - last_activity > 300:  # 5 minutes
        messagebox.showinfo("Session Timeout", "App locked due to inactivity.")
        root.destroy()
    else:
        reset_timer()

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False
    return True


def gui_add():
    acc = account_entry.get()
    user = username_entry.get()
    pwd = password_entry.get()
    if acc and user and pwd:
        if not is_strong_password(pwd):
            messagebox.showwarning('Weak Password',
                                   'Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character.')
            return
        add(acc, user, pwd)
        messagebox.showinfo('Success', 'Password added successfully.')
        account_entry.delete(0, tk.END)
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
    else:
        messagebox.showwarning('Input Error', 'All fields are required.')
    reset_timer()

def gui_view():
    output.delete(1.0, tk.END)
    try:
        with open('passwords.txt', 'r') as f:
            for line in f:
                account, user, enc_pwd = line.strip().split('|')
                output.insert(tk.END, f'{account} | {user} | (encrypted)\n')
    except FileNotFoundError:
        output.insert(tk.END, 'No password file found.\n')
    reset_timer()

def gui_search():
    acc = simpledialog.askstring('Search', 'Enter account to search')
    if acc:
        output.delete(1.0, tk.END)
        try:
            with open('passwords.txt', 'r') as f:
                found = False
                for line in f:
                    account, user, enc_pwd = line.strip().split('|')
                    if acc.lower() == account.lower():
                        output.insert(tk.END, f'Account: {account}\nUsername')
                        found = True
                if not found:
                    output.insert(tk.END, 'Account not found.\n')
        except FileNotFoundError:
            output.insert(tk.END, 'Password file not found.\n')
    reset_timer()

def gui_delete():
    acc = simpledialog.askstring('Delete', 'Enter account to delete:')
    if acc:
        delete(acc)
        messagebox.showinfo('Delete', f'Attempted to delete: {acc}')
    reset_timer()

def copy_to_clipboard():
    selected = output.get(tk.SEL_FIRST, tk.SEL_LAST)
    if selected:
        pyperclip.copy(selected)
        status_label.config(text='Copied to clipboard (clears in 15 seconds)')
        root.after(15000, lambda: pyperclip.copy(''))

def gui_export():
    filename = simpledialog.askstring('Export', 'Enter filename to export (e.g., backup.txt:)')
    if filename:
        try:
            with open('passwords.txt', 'r') as original, open(filename, 'w') as backup:
                backup.write(original.read())
            messagebox.showinfo('Export', f'Passwords exported to {filename}')
        except FileNotFoundError:
            messagebox.showerror('Error', 'No password file found to export')


def gui1_export():
    success = export_passwords()
    if success:
        messagebox.showinfo("Export", "Passwords exported to backup_passwords.txt")
    else:
        messagebox.showerror("Export Failed", "No passwords to export.")


def gui_import():
    filename = simpledialog.askstring('Import', 'Enter filename to import (e.g., backup.txt):')
    if filename:
        try:
            with open(filename, 'r') as src, open('passwords.txt', 'a') as dest:
                dest.write(src.read())
            messagebox.showinfo('Import', f'Passwords imported from {filename}')
        except FileNotFoundError:
            messagebox.showerror('Error', f'{filename} not found.')


def gui1_import():
    success = import_passwords()
    if success:
        messagebox.showinfo("Import", "Passwords imported from backup_passwords.txt")
    else:
        messagebox.showerror("Import Failed", "No backup file found.")

copy_btn = tk.Button(root, text='Copy Selected Text', command=copy_to_clipboard)
copy_btn.pack(pady=2)

tk.Button(root, text='Add Password', command=gui_add).pack(pady=2)
tk.Button(root, text='View All', command=gui_view).pack(pady=2)
tk.Button(root, text='Search', command=gui_search).pack(pady=2)
tk.Button(root, text='Delete', command=gui_delete).pack(pady=2)
tk.Button(root, text='Export', command=gui_export).pack(pady=2)
tk.Button(root, text='Import', command=gui_import).pack(pady=2)
tk.Button(root, text='Export Passwords', command=gui_export).pack(pady=2)
tk.Button(root, text='Import Passwords', command=gui_import).pack(pady=2)
reset_timer()
root.mainloop()
