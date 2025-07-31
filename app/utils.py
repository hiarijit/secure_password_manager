import os
import base64
import hashlib
from cryptography.fernet import Fernet

def generate_salt():
    return os.urandom(16).hex()

def derive_key(password, salt):
    # Use PBKDF2HMAC to derive a 32-byte key for Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(salt),
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_password(password, key):
    f = Fernet(key)
    if isinstance(password, str):
        password = password.encode()
    return f.encrypt(password)

def decrypt_password(token, key):
    f = Fernet(key)
    decrypted = f.decrypt(token)
    return decrypted.decode()
