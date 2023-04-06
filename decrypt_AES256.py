# decryption.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def derive_key(password, salt, key_length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def decrypt_aes(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded_data) + unpadder.finalize()).decode()

def main():
    password = input("Enter the password used for encryption: ")
    encrypted_message = input("Enter the encrypted message: ")

    decoded_message = base64.b64decode(encrypted_message)
    recovered_salt = decoded_message[:16]
    recovered_iv = decoded_message[16:32]
    recovered_ciphertext = decoded_message[32:]

    recovered_key = derive_key(password, recovered_salt)
    decrypted_message = decrypt_aes(recovered_ciphertext, recovered_key, recovered_iv)

    print("\nDecrypted message:")
    print(decrypted_message)

if __name__ == "__main__":
    main()
