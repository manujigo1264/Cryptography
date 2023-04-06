# encryption.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import urandom
import base64

def derive_key(password, salt, key_length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_aes(plaintext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def main():
    password = input("Enter a password for encryption: ")

    salt = urandom(16)
    iv = urandom(16)
    key = derive_key(password, salt)

    plaintext = input("Enter the message you want to encrypt: ")
    ciphertext = encrypt_aes(plaintext, key, iv)

    print("\nEncrypted message:")
    encrypted_message = base64.b64encode(salt + iv + ciphertext).decode()
    print(encrypted_message)

if __name__ == "__main__":
    main()
