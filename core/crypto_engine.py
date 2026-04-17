from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

class CryptoEngine:
    KEY_SIZE = 32   # 256 bits
    NONCE_SIZE = 12  # 96 bits (GCM standard)
    TAG_SIZE = 16   # 128 bits

    def encrypt_file(self, input_path: str, key: bytes) -> str:
        """Encrypts a file using AES-256-GCM. Returns path to encrypted file."""
        nonce = get_random_bytes(self.NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        with open(input_path, 'rb') as f:
            plaintext = f.read()

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        output_path = input_path + '.enc'
        with open(output_path, 'wb') as f:
            # File structure: [nonce (12)] + [tag (16)] + [ciphertext]
            f.write(nonce + tag + ciphertext)

        return output_path

    def decrypt_file(self, input_path: str, key: bytes) -> str:
        """Decrypts a .enc file. Returns path to decrypted file."""
        with open(input_path, 'rb') as f:
            data = f.read()

        nonce = data[:self.NONCE_SIZE]
        tag = data[self.NONCE_SIZE:self.NONCE_SIZE + self.TAG_SIZE]
        ciphertext = data[self.NONCE_SIZE + self.TAG_SIZE:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError("Decryption failed — file may be tampered or key is incorrect.")

        output_path = input_path.replace('.enc', '.decrypted')
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        return output_path