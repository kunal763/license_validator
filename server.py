import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

valid_licenses = {
    "valid_license_key_1": "User1",
    "valid_license_key_2": "User2",
}
def derive_key(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def decrypt_license(encrypted_data: bytes, passphrase: str):
    # Extract salt, IV, and encrypted license from the received data
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_license = encrypted_data[32:]

    key = derive_key(passphrase, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_license = decryptor.update(encrypted_license) + decryptor.finalize()
    return decrypted_license.decode('utf-8')

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('127.0.0.1', 8000))
        server_socket.listen()
        print("Server listening on port 8000...")

        client_socket, addr = server_socket.accept()
        with client_socket:
            print(f"Connection from {addr} has been established!")

            # Receive length of the encrypted license
            license_length_data = client_socket.recv(4)
            license_length = int.from_bytes(license_length_data, byteorder='big')
            encrypted_license_data = client_socket.recv(license_length)
            print("Encrypted license received.")

            # Receive length of the passphrase
            passphrase_length_data = client_socket.recv(4)
            passphrase_length = int.from_bytes(passphrase_length_data, byteorder='big')
            passphrase = client_socket.recv(passphrase_length).decode()
            print("Passphrase received.")

            # Decrypt the license
            decrypted_license = decrypt_license(base64.b64decode(encrypted_license_data), passphrase)
            if decrypted_license in valid_licenses:
                response = {"status": "valid", "user": valid_licenses[decrypted_license]}
            else:
                response = {"status": "invalid"}
            print (response)
            print("Decrypted license:", decrypted_license)

if __name__ == "__main__":
    main()
