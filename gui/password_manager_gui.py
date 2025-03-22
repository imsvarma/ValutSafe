# gui/password_manager_gui.py
import os
import json
import time
import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk, ImageEnhance, ImageFilter

from constants import USER_FILE, SESSION_TIMEOUT
from utils.encryption import hash_password, generate_key_from_password, encrypt_password, decrypt_password
from utils.file_utils import load_passwords, save_passwords
from utils.password_utils import generate_password, check_password_strength

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Vault Safe")
        self.root.geometry("900x600")
        self.root.configure(bg="#f0f4f8")  # Light background for modern look

        self.master_key = None
        self.username = None

        # Set background image (adjust path as needed)
        self.image_path = "C:/Users/imani/cyber.jpg"
        self.load_background_image(self.image_path)

        # Create persistent output area
        self.create_output_area()

        # Session timeout management
        self.last_activity_time = time.time()
        self.root.bind_all("<KeyPress>", self.reset_timer)
        self.root.bind_all("<Button-1>", self.reset_timer)
        self.check_session_timeout()

        # Start with the login/register screen
        self.create_login_register_screen()

    def load_background_image(self, image_path):
        try:
            image = Image.open(image_path)
            image = image.resize((900, 600), Image.Resampling.LANCZOS)
            image = image.filter(ImageFilter.GaussianBlur(4))
            enhancer = ImageEnhance.Brightness(image)
            image = enhancer.enhance(0.6)
            self.background_image = ImageTk.PhotoImage(image)
            self.background_label = tk.Label(self.root, image=self.background_image)
            self.background_label.place(x=0, y=0, relwidth=1, relheight=1)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {e}")

    def create_output_area(self):
        self.output_frame = ttk.Frame(self.root, padding="10")
        self.output_frame.place(x=50, y=450, width=0, height=0)
        self.output_area = tk.Text(self.output_frame, wrap="word", font=('Arial', 12), bg="#ffffff", relief="solid", borderwidth=1)
        self.output_area.pack(fill=tk.BOTH, expand=True)
        self.output_area.config(state=tk.DISABLED)

    def clear_window(self):
        for widget in self.root.winfo_children():
            if widget not in [self.background_label, self.output_frame]:
                widget.destroy()

    def create_login_register_screen(self):
        self.clear_window()
        self.root.geometry("900x600")
        self.root.resizable(False, False)
        frame = tk.Frame(self.root, bg="#1f1f2e", padx=20, pady=20)
        frame.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        title_label = tk.Label(frame, text="Login/Register", font=('Courier New', 20, 'bold'), fg="lime", bg="#1f1f2e")
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        tk.Label(frame, text="Username:", font=('Courier New', 14), fg="white", bg="#1f1f2e").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_entry = tk.Entry(frame, font=('Courier New', 14), bg="#333344", fg="white", insertbackground="white", relief=tk.FLAT)
        self.username_entry.grid(row=1, column=1, pady=5)

        tk.Label(frame, text="Master Password:", font=('Courier New', 14), fg="white", bg="#1f1f2e").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_entry = tk.Entry(frame, show="*", font=('Courier New', 14), bg="#333344", fg="white", insertbackground="white", relief=tk.FLAT)
        self.password_entry.grid(row=2, column=1, pady=5)

        button_frame = tk.Frame(frame, bg="#1f1f2e")
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        tk.Button(button_frame, text="Login", font=('Courier New', 12, 'bold'), fg="black", bg="lime", relief=tk.RAISED, width=10, command=self.login_user).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Register", font=('Courier New', 12, 'bold'), fg="black", bg="#5bc0de", relief=tk.RAISED, width=10, command=self.register_user_screen).pack(side=tk.LEFT, padx=5)

    def register_user_screen(self):
        register_window = tk.Toplevel(self.root)
        register_window.title("Register New User")
        register_window.geometry("400x400")

        tk.Label(register_window, text="Name:").pack(pady=5)
        name_entry = tk.Entry(register_window)
        name_entry.pack(pady=5)

        tk.Label(register_window, text="Username:").pack(pady=5)
        username_entry = tk.Entry(register_window)
        username_entry.pack(pady=5)

        tk.Label(register_window, text="Password:").pack(pady=5)
        password_entry = tk.Entry(register_window, show="*")
        password_entry.pack(pady=5)

        tk.Label(register_window, text="Confirm Password:").pack(pady=5)
        confirm_password_entry = tk.Entry(register_window, show="*")
        confirm_password_entry.pack(pady=5)

        tk.Button(register_window, text="Register", command=lambda: self.register_user(name_entry, username_entry, password_entry, confirm_password_entry, register_window)).pack(pady=10)

    def register_user(self, name_entry, username_entry, password_entry, confirm_password_entry, window):
        name = name_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()

        if not (name and username and password and confirm_password):
            messagebox.showerror("Error", "All fields are required.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        hashed_password = hash_password(password)
        try:
            with open(USER_FILE, 'r') as file:
                users = json.load(file)
        except FileNotFoundError:
            users = {}

        if username in users:
            messagebox.showerror("Error", "Username already exists!")
        else:
            users[username] = hashed_password
            with open(USER_FILE, 'w') as file:
                json.dump(users, file)
            messagebox.showinfo("Success", f"User '{username}' registered successfully!")
            window.destroy()

    def login_user(self):
        username = self.username_entry.get()
        master_password = self.password_entry.get()
        hashed_password = hash_password(master_password)

        try:
            with open(USER_FILE, 'r') as file:
                users = json.load(file)
        except FileNotFoundError:
            users = {}

        if username in users and users[username] == hashed_password:
            self.username = username
            self.master_key = generate_key_from_password(master_password)
            self.output_area.config(state=tk.NORMAL)
            self.output_area.delete("1.0", tk.END)
            self.output_area.insert(tk.END, f"User '{username}' logged in successfully!")
            self.output_area.config(state=tk.DISABLED)
            self.create_password_management_screen()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def create_password_management_screen(self):
        self.clear_window()
        header_frame = tk.Frame(self.root, bg="#1f1f2e", padx=10, pady=5)
        header_frame.pack(side="top", fill="x")
        tk.Button(header_frame, text="⚙️", font=('Helvetica', 12, 'bold'), fg="white", bg="#0275d8", relief=tk.FLAT, command=self.create_change_password_screen).pack(side=tk.LEFT, padx=5)
        tk.Label(header_frame, text="Vault Safe", font=('Helvetica', 24, 'bold'), fg="lime", bg="#1f1f2e").pack(side=tk.LEFT)
        tk.Button(header_frame, text="Logout", font=('Helvetica', 12, 'bold'), fg="white", bg="#d9534f", relief=tk.FLAT, command=self.create_login_register_screen).pack(side=tk.RIGHT, padx=10)

        button_frame = tk.Frame(self.root, bg="#1f1f2e", pady=10)
        button_frame.pack(side="top", fill="x")
        tk.Button(button_frame, text="Add New", font=('Helvetica', 12, 'bold'), fg="white", bg="#5cb85c", relief=tk.FLAT, command=self.create_add_new_screen).pack(side="left", padx=10)
        tk.Button(button_frame, text="Generate Random Password", font=('Helvetica', 12, 'bold'), fg="white", bg="#0275d8", relief=tk.FLAT, command=self.create_generate_password_screen).pack(side="left")

        list_frame = tk.Frame(self.root, bg="#1f1f2e")
        list_frame.pack(side="top", fill="both", expand=True, padx=10, pady=10)
        canvas = tk.Canvas(list_frame, bg="#1f1f2e", highlightthickness=0)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        self.scrollable_frame = tk.Frame(canvas, bg="#1f1f2e")
        self.scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        header_row = tk.Frame(self.scrollable_frame, bg="#1f1f2e")
        header_row.pack(fill="x", pady=0.5)
        tk.Label(header_row, text="Accounts", font=('Helvetica', 14, 'bold'), fg="lime", bg="#1f1f2e").pack(pady=0.5, side="left")

        passwords = load_passwords(self.username)
        if not passwords:
            tk.Label(self.scrollable_frame, text="No stored passwords found.", font=('Helvetica', 14, 'italic'), fg="white", bg="#1f1f2e").pack(pady=10)
        else:
            for i, (account, encrypted_data) in enumerate(passwords.items(), start=1):
                row_frame = tk.Frame(self.scrollable_frame, bg="#333344", pady=5, padx=5)
                row_frame.pack(fill="x", pady=5, padx=5)
                tk.Label(row_frame, text=f"{i}", font=('Helvetica', 12), fg="white", bg="#333344", width=5, anchor='w').pack(side="left", padx=5)
                tk.Label(row_frame, text=f"{account}", font=('Helvetica', 12), fg="white", bg="#333344", anchor='w').pack(side="left", padx=50, expand=True, fill="x")
                tk.Button(row_frame, text="Show Details", font=('Helvetica', 10, 'bold'), fg="black", bg="lime", relief=tk.FLAT, command=lambda acc=account: self.show_details_screen(acc)).pack(side="right", padx=500)

    def create_add_new_screen(self):
        self.clear_window()
        header_frame = tk.Frame(self.root, bg="#1f1f2e", padx=10, pady=5)
        header_frame.place(relx=0.5, rely=0.02, anchor=tk.CENTER, relwidth=1)
        tk.Label(header_frame, text="Add New Account", font=('Helvetica', 24, 'bold'), fg="lime", bg="#1f1f2e").pack(side=tk.LEFT)
        tk.Button(header_frame, text="Back", font=('Helvetica', 12, 'bold'), fg="white", bg="#d9534f", relief=tk.FLAT, command=self.create_password_management_screen).pack(side=tk.RIGHT, padx=10)

        form_frame = tk.Frame(self.root, bg="#2a2a3b", padx=20, pady=20)
        form_frame.place(relx=0.5, rely=0.15, anchor=tk.N, relwidth=0.6)

        label_style = {'font': ('Helvetica', 14, 'bold'), 'fg': 'lime', 'bg': '#2a2a3b'}
        entry_style = {'font': ('Helvetica', 12), 'bg': '#3e3e4f', 'fg': 'white', 'relief': tk.FLAT, 'insertbackground': 'white'}

        tk.Label(form_frame, text="Account Name:", **label_style).grid(row=0, column=0, sticky='w', pady=5)
        account_entry = tk.Entry(form_frame, **entry_style)
        account_entry.grid(row=0, column=1, pady=5, sticky='ew')

        tk.Label(form_frame, text="Username:", **label_style).grid(row=1, column=0, sticky='w', pady=5)
        username_entry = tk.Entry(form_frame, **entry_style)
        username_entry.grid(row=1, column=1, pady=5, sticky='ew')

        tk.Label(form_frame, text="Website:", **label_style).grid(row=2, column=0, sticky='w', pady=5)
        website_entry = tk.Entry(form_frame, **entry_style)
        website_entry.grid(row=2, column=1, pady=5, sticky='ew')

        tk.Label(form_frame, text="Password:", **label_style).grid(row=3, column=0, sticky='w', pady=5)
        password_entry = tk.Entry(form_frame, show="*", **entry_style)
        password_entry.grid(row=3, column=1, pady=5, sticky='ew')

        tk.Label(form_frame, text="Re-enter Password:", **label_style).grid(row=4, column=0, sticky='w', pady=5)
        reenter_password_entry = tk.Entry(form_frame, show="*", **entry_style)
        reenter_password_entry.grid(row=4, column=1, pady=5, sticky='ew')

        tk.Button(form_frame, text="Save", font=('Helvetica', 14, 'bold'), fg="white", bg="#5cb85c", relief=tk.RAISED, width=15,
                  command=lambda: self.save_new_account(account_entry, username_entry, website_entry, password_entry, reenter_password_entry)).grid(row=5, column=0, columnspan=2, pady=15)
        form_frame.columnconfigure(1, weight=1)

    def save_new_account(self, account_entry, username_entry, website_entry, password_entry, reenter_password_entry):
        account = account_entry.get()
        username = username_entry.get()
        website = website_entry.get()
        password = password_entry.get()
        reentered_password = reenter_password_entry.get()

        if not (account and username and website and password and reentered_password):
            messagebox.showerror("Error", "All fields are required.")
            return

        if password != reentered_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        strength = check_password_strength(password)
        if strength == "Weak":
            messagebox.showwarning("Weak Password", "Your password is weak. Please use a stronger password.")
            return

        encrypted_password = encrypt_password(self.master_key, password)
        passwords = load_passwords(self.username)
        passwords[account] = {"username": username, "website": website, "password": encrypted_password}
        save_passwords(self.username, passwords)
        messagebox.showinfo("Success", f"Account '{account}' has been added.")
        self.create_password_management_screen()

    def show_details_screen(self, account):
        self.clear_window()
        header_frame = tk.Frame(self.root, bg="#1f1f2e", padx=10, pady=5)
        header_frame.place(relx=0.5, rely=0.05, anchor=tk.CENTER, relwidth=1)
        tk.Label(header_frame, text=f"Details for {account}", font=('Helvetica', 24, 'bold'), fg="#00bcd4", bg="#1f1f2e").pack(side=tk.LEFT, padx=10)
        tk.Button(header_frame, text="Back", font=('Helvetica', 12, 'bold'), fg="white", bg="#d9534f", relief=tk.FLAT, command=self.create_password_management_screen).pack(side=tk.RIGHT, padx=10)

        passwords = load_passwords(self.username)
        details = passwords.get(account, None)
        if details and isinstance(details, dict):
            try:
                decrypted_password = decrypt_password(self.master_key, details.get("password"))
                details_frame = tk.Frame(self.root, bg="#222233", padx=20, pady=20, relief=tk.RIDGE, bd=2)
                details_frame.place(relx=0.5, rely=0.25, anchor=tk.N, width=500)
                tk.Label(details_frame, text="Account:", font=('Helvetica', 14, 'bold'), fg="#00bcd4", bg="#222233").grid(row=0, column=0, sticky='e', pady=5)
                tk.Label(details_frame, text=account, font=('Helvetica', 14), fg="white", bg="#222233").grid(row=0, column=1, sticky='w', pady=5)
                tk.Label(details_frame, text="Username:", font=('Helvetica', 14, 'bold'), fg="white", bg="#222233").grid(row=1, column=0, sticky='e', pady=5)
                tk.Label(details_frame, text=details.get('username', 'N/A'), font=('Helvetica', 14), fg="white", bg="#222233").grid(row=1, column=1, sticky='w', pady=5)
                tk.Label(details_frame, text="Password:", font=('Helvetica', 14, 'bold'), fg="white", bg="#222233").grid(row=2, column=0, sticky='e', pady=5)
                tk.Label(details_frame, text=decrypted_password, font=('Helvetica', 14), fg="white", bg="#222233").grid(row=2, column=1, sticky='w', pady=5)
                tk.Label(details_frame, text="Website:", font=('Helvetica', 14, 'bold'), fg="white", bg="#222233").grid(row=3, column=0, sticky='e', pady=5)
                tk.Label(details_frame, text=details.get('website', 'N/A'), font=('Helvetica', 14), fg="white", bg="#222233").grid(row=3, column=1, sticky='w', pady=5)
                button_frame = tk.Frame(details_frame, bg="#222233")
                button_frame.grid(row=4, column=0, columnspan=2, pady=10)
                tk.Button(button_frame, text="Change", font=('Helvetica', 12, 'bold'), fg="white", bg="#f0ad4e", relief=tk.FLAT, command=lambda: self.change_account(account)).pack(side=tk.LEFT, padx=10)
                tk.Button(button_frame, text="Delete", font=('Helvetica', 12, 'bold'), fg="white", bg="#d9534f", relief=tk.FLAT, command=lambda: self.delete_account(account)).pack(side=tk.LEFT, padx=10)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt password for '{account}'. Error: {e}")
        else:
            messagebox.showerror("Error", f"No details found for '{account}' or invalid data structure.")

    def change_account(self, account):
        self.clear_window()
        header_frame = tk.Frame(self.root, bg="#1f1f2e", padx=10, pady=5)
        header_frame.place(relx=0.5, rely=0.05, anchor=tk.CENTER, relwidth=1)
        tk.Label(header_frame, text=f"Change Details for {account}", font=('Helvetica', 24, 'bold'), fg="white", bg="#1f1f2e").pack(side=tk.LEFT, padx=10)
        tk.Button(header_frame, text="Back", font=('Helvetica', 12, 'bold'), fg="white", bg="#d9534f", relief=tk.FLAT, command=lambda: self.show_details_screen(account)).pack(side=tk.RIGHT, padx=10)

        form_frame = tk.Frame(self.root, bg="#222233", padx=20, pady=20, relief=tk.RIDGE, bd=2)
        form_frame.place(relx=0.5, rely=0.25, anchor=tk.N, width=650)
        passwords = load_passwords(self.username)
        details = passwords.get(account, {})
        decrypted_password = decrypt_password(self.master_key, details.get("password")) if "password" in details else ""
        tk.Label(form_frame, text="Username:", font=('Helvetica', 14, 'bold'), fg="#00bcd4", bg="#222233").pack(pady=5, anchor='w')
        username_entry = tk.Entry(form_frame, font=('Helvetica', 12), width=45)
        username_entry.insert(0, details.get("username", ""))
        username_entry.pack(pady=5)
        tk.Label(form_frame, text="Website:", font=('Helvetica', 14, 'bold'), fg="#00bcd4", bg="#222233").pack(pady=5, anchor='w')
        website_entry = tk.Entry(form_frame, font=('Helvetica', 12), width=45)
        website_entry.insert(0, details.get("website", ""))
        website_entry.pack(pady=5)
        tk.Label(form_frame, text="Password:", font=('Helvetica', 14, 'bold'), fg="#00bcd4", bg="#222233").pack(pady=5, anchor='w')
        password_entry = tk.Entry(form_frame, font=('Helvetica', 12), show="*", width=45)
        password_entry.insert(0, decrypted_password)
        password_entry.pack(pady=5)
        def save_changes():
            username = username_entry.get()
            website = website_entry.get()
            password = password_entry.get()
            if not (username and website and password):
                messagebox.showerror("Error", "All fields are required.")
                return
            if check_password_strength(password) == "Weak":
                messagebox.showwarning("Weak Password", "Your password is weak. Please use a stronger password.")
                return
            encrypted_password = encrypt_password(self.master_key, password)
            passwords[account] = {"username": username, "website": website, "password": encrypted_password}
            save_passwords(self.username, passwords)
            messagebox.showinfo("Success", f"Details for '{account}' have been updated.")
            self.show_details_screen(account)
        tk.Button(form_frame, text="Save Changes", font=('Helvetica', 14, 'bold'), fg="white", bg="#5cb85c", relief=tk.RAISED, width=20, command=save_changes).pack(pady=15)

    def delete_account(self, account):
        result = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the account '{account}'?")
        if result:
            passwords = load_passwords(self.username)
            if account in passwords:
                del passwords[account]
                save_passwords(self.username, passwords)
                messagebox.showinfo("Deleted", f"The account '{account}' has been deleted.")
                self.create_password_management_screen()
            else:
                messagebox.showerror("Error", f"Account '{account}' not found.")

    def create_change_password_screen(self):
        self.clear_window()
        change_frame = tk.Frame(self.root, bg="#1f1f2e", padx=20, pady=20)
        change_frame.pack(expand=True)
        tk.Label(change_frame, text="Change Password", font=('Helvetica', 24, 'bold'), fg="lime", bg="#1f1f2e").pack(pady=10)
        tk.Label(change_frame, text="New Password:", font=('Helvetica', 14), fg="white", bg="#1f1f2e").pack(anchor='w')
        new_password_entry = tk.Entry(change_frame, font=('Helvetica', 14), show='*')
        new_password_entry.pack(fill='x', pady=5)
        tk.Label(change_frame, text="Confirm Password:", font=('Helvetica', 14), fg="white", bg="#1f1f2e").pack(anchor='w')
        confirm_password_entry = tk.Entry(change_frame, font=('Helvetica', 14), show='*')
        confirm_password_entry.pack(fill='x', pady=5)
        def save_new_password():
            new_password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()
            if new_password and new_password == confirm_password:
                hashed_password = hash_password(new_password)
                try:
                    with open(USER_FILE, 'r') as file:
                        users = json.load(file)
                except FileNotFoundError:
                    users = {}
                users[self.username] = hashed_password
                with open(USER_FILE, 'w') as file:
                    json.dump(users, file)
                new_master_key = generate_key_from_password(new_password)
                passwords = load_passwords(self.username)
                re_encrypted_passwords = {}
                for account, data in passwords.items():
                    if isinstance(data, dict):
                        re_encrypted_passwords[account] = {
                            "username": data.get("username", ""),
                            "website": data.get("website", ""),
                            "password": encrypt_password(new_master_key, decrypt_password(self.master_key, data.get('password', '')))
                        }
                    else:
                        messagebox.showerror("Error", f"Invalid data structure for account '{account}'. Skipping...")
                save_passwords(self.username, re_encrypted_passwords)
                self.master_key = new_master_key
                messagebox.showinfo("Success", "Password changed and accounts re-encrypted successfully.")
                self.create_password_management_screen()
            else:
                messagebox.showerror("Error", "Passwords do not match or are empty.")
        tk.Button(change_frame, text="Save", font=('Helvetica', 14, 'bold'), fg="white", bg="#5cb85c", command=save_new_password).pack(pady=10)
        tk.Button(change_frame, text="Back", font=('Helvetica', 14, 'bold'), fg="white", bg="#d9534f", command=self.create_password_management_screen).pack()

    def create_generate_password_screen(self):
        self.clear_window()
        header_frame = tk.Frame(self.root, bg="#1f1f2e", padx=10, pady=5)
        header_frame.place(relx=0.5, rely=0.05, anchor=tk.CENTER, relwidth=1)
        tk.Label(header_frame, text="Generate Random Password", font=('Helvetica', 24, 'bold'), fg="white", bg="#1f1f2e").pack(side=tk.LEFT)
        tk.Button(header_frame, text="Back", font=('Helvetica', 12, 'bold'), fg="white", bg="#d9534f", relief=tk.FLAT, command=self.create_password_management_screen).pack(side=tk.RIGHT, padx=10)
        gen_frame = tk.Frame(self.root, bg="#222233", padx=20, pady=20, relief=tk.RIDGE, bd=2)
        gen_frame.place(relx=0.5, rely=0.25, anchor=tk.N, width=600)
        tk.Label(gen_frame, text="Password Length:", font=('Helvetica', 14), fg="white", bg="#222233").pack(pady=5, anchor='w')
        length_entry = tk.Entry(gen_frame, font=('Helvetica', 12), width=10)
        length_entry.pack(pady=5)
        tk.Label(gen_frame, text="Generated Password:", font=('Helvetica', 14), fg="white", bg="#222233").pack(pady=10, anchor='w')
        result_entry = tk.Entry(gen_frame, font=('Helvetica', 12), width=45, state='readonly')
        result_entry.pack(pady=5)
        def generate():
            try:
                length = int(length_entry.get())
                if length < 6:
                    messagebox.showerror("Error", "Password length must be at least 6 characters.")
                    return
                pwd = generate_password(length)
                result_entry.config(state='normal')
                result_entry.delete(0, tk.END)
                result_entry.insert(0, pwd)
                result_entry.config(state='readonly')
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number.")
        tk.Button(gen_frame, text="Generate", font=('Helvetica', 14, 'bold'), fg="white", bg="#5cb85c", relief=tk.RAISED, command=generate).pack(pady=15)
        def copy_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append(result_entry.get())
            self.root.update()
            messagebox.showinfo("Copied", "Password copied to clipboard.")
        tk.Button(gen_frame, text="Copy to Clipboard", font=('Helvetica', 12, 'bold'), fg="white", bg="#0275d8", relief=tk.FLAT, command=copy_to_clipboard).pack(pady=5)

    def reset_timer(self, event=None):
        self.last_activity_time = time.time()

    def check_session_timeout(self):
        if time.time() - self.last_activity_time > SESSION_TIMEOUT:
            messagebox.showinfo("Session Timeout", "You have been logged out due to inactivity.")
            self.create_login_register_screen()
        else:
            self.root.after(1000, self.check_session_timeout)
