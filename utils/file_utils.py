# utils/file_utils.py
import os
import json
from constants import USER_FILE, PASSWORD_FILE_TEMPLATE

def load_passwords(username: str) -> dict:
    """Load the passwords for a given username."""
    password_file = PASSWORD_FILE_TEMPLATE.format(username)
    if not os.path.exists(password_file):
        return {}
    with open(password_file, 'r') as file:
        return json.load(file)

def save_passwords(username: str, passwords: dict):
    """Save the passwords for a given username."""
    password_file = PASSWORD_FILE_TEMPLATE.format(username)
    with open(password_file, 'w') as file:
        json.dump(passwords, file)
