# file_encryptor.py
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from password+salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_file(input_path: str, password: str):
    """
    Encrypt input_path -> creates input_path + '.enc' and input_path + '.key'
    Returns (enc_path, key_path)
    """
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Generate random symmetric key for file and encrypt file
    file_key = Fernet.generate_key()
    f_file = Fernet(file_key)
    ciphertext = f_file.encrypt(plaintext)

    enc_path = input_path + ".enc"
    with open(enc_path, "wb") as f:
        f.write(ciphertext)

    # Wrap file_key with password-derived key + salt
    salt = os.urandom(16)
    wrap_key = _derive_key_from_password(password, salt)
    f_wrap = Fernet(wrap_key)
    encrypted_file_key = f_wrap.encrypt(file_key)

    key_path = input_path + ".key"
    with open(key_path, "wb") as f:
        f.write(salt + encrypted_file_key)  # store salt(16) + encrypted key

    return enc_path, key_path

def decrypt_file(enc_path: str, password: str, key_path: str):
    """
    Decrypt enc_path using password and key file at key_path.
    Returns path to decrypted file.
    """
    # Read keyfile
    with open(key_path, "rb") as f:
        keyfile_bytes = f.read()
    if len(keyfile_bytes) < 17:
        raise ValueError("Invalid key file.")

    salt = keyfile_bytes[:16]
    encrypted_file_key = keyfile_bytes[16:]

    wrap_key = _derive_key_from_password(password, salt)
    f_wrap = Fernet(wrap_key)
    try:
        file_key = f_wrap.decrypt(encrypted_file_key)
    except Exception:
        raise ValueError("Incorrect password or corrupted key file.")

    # read ciphertext and decrypt
    with open(enc_path, "rb") as f:
        ciphertext = f.read()

    f_file = Fernet(file_key)
    try:
        plaintext = f_file.decrypt(ciphertext)
    except Exception:
        raise ValueError("Decryption failed: corrupted file or wrong key.")

    # output filename: remove ".enc" or add ".dec"
    if enc_path.endswith(".enc"):
        out_path = enc_path[:-4]
    else:
        out_path = enc_path + ".dec"

    with open(out_path, "wb") as f:
        f.write(plaintext)

    return out_path
