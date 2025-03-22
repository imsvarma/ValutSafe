# utils/password_utils.py
import random
import string
import re

def generate_password(length: int = 16) -> str:
    """Generate a random password of a given length."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def check_password_strength(password: str) -> str:
    """Check and return the strength of the given password."""
    if len(password) < 8:
        return "Weak"
    elif (re.search(r'[A-Z]', password) and 
          re.search(r'[a-z]', password) and 
          re.search(r'[0-9]', password) and 
          re.search(r'[\W_]', password)):
        return "Strong"
    elif re.search(r'[A-Za-z]', password) and re.search(r'[0-9]', password):
        return "Medium"
    else:
        return "Weak"
