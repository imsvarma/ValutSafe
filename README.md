# VaultSafe

VaultSafe is a simple password manager built with Python and Tkinter. It helps you safely store your passwords, generate strong random passwords, and manage your account information—all in an easy-to-use interface.

## What It Does

- **Secure Storage:** Encrypts your passwords to keep them safe.
- **User Accounts:** Lets you register and log in using a master password.
- **Manage Passwords:** Add, view, update, or delete your account passwords.
- **Password Generator:** Create strong, random passwords quickly.

## How to Get Started

1. **Install Required Packages:**

   Open your terminal and run:
   ```bash
   pip install cryptography Pillow




Run the Application:

In your terminal, start the program with:


python main.py




Use VaultSafe:

Register a new user or log in with your master password.

Add and manage your account passwords as needed.


VaultSafe/
├── main.py                   # Main program entry point
├── constants.py              # Project settings and constants
├── gui/
│   └── password_manager_gui.py  # The graphical user interface code
└── utils/
    ├── encryption.py         # Handles encryption and decryption
    ├── file_utils.py         # Loads and saves password data
    └── password_utils.py     # Generates passwords and checks strength


Important Notes
User details are stored in users.json.

Each user’s passwords are saved in a file named passwords_<username>.json.

The background image is set in the GUI file (password_manager_gui.py). Change the image path if needed.

Enjoy using VaultSafe!! :)
