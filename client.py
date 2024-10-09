import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os

def derive_key(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def encrypt_license(license_key: str, passphrase: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_license = encryptor.update(license_key.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted_license)

def main():
    license_key = "your_license_key"  # Replace with your actual license key
    passphrase = "your-secure-passphrase"  # Replace with your passphrase

    encrypted_license = encrypt_license(license_key, passphrase)
    print("Encrypted license created.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('127.0.0.1', 8000))
        
        # Send the length of the encrypted license first
        license_length = len(encrypted_license)
        client_socket.sendall(license_length.to_bytes(4, byteorder='big'))  # Send as 4 bytes
        client_socket.sendall(encrypted_license)  # Send the encrypted license
        print("Encrypted license sent.")

        # Send the passphrase length and then the passphrase
        passphrase_encoded = passphrase.encode()
        passphrase_length = len(passphrase_encoded)
        client_socket.sendall(passphrase_length.to_bytes(4, byteorder='big'))  # Send length as 4 bytes
        client_socket.sendall(passphrase_encoded)  # Send the passphrase
        print("Passphrase sent.")

if __name__ == "__main__":
    main()
