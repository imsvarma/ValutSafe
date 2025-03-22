# utils/encryption.py
import hashlib
import base64
from cryptography.fernet import Fernet

def hash_password(password: str) -> str:
    """Return SHA-256 hash of the given password."""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_key_from_password(password: str) -> bytes:
    """Generate a Fernet key from the provided password."""
    password_bytes = password.encode('utf-8')
    key = hashlib.sha256(password_bytes).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_password(key: bytes, password: str) -> str:
    """Encrypt the password using the provided key."""
    cipher = Fernet(key)
    return cipher.encrypt(password.encode()).decode('utf-8')

def decrypt_password(key: bytes, encrypted_password: str) -> str:
    """Decrypt the encrypted password using the provided key."""
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_password.encode()).decode('utf-8')
