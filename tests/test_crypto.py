import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto_engine import CryptoEngine
from core.key_manager import KeyManager

def test_encrypt_decrypt():
    engine = CryptoEngine()
    km = KeyManager()

    # Create a dummy test file
    test_file = 'tests/test_sample.txt'
    with open(test_file, 'w') as f:
        f.write("Sensitive data: this should be encrypted.")

    key = km.generate_key()

    # Encrypt
    enc_path = engine.encrypt_file(test_file, key)
    print(f"Encrypted: {enc_path}")

    # Decrypt
    dec_path = engine.decrypt_file(enc_path, key)
    with open(dec_path, 'r') as f:
        result = f.read()

    assert result == "Sensitive data: this should be encrypted."
    print("Test passed — encrypt/decrypt cycle works correctly.")

def test_tamper_detection():
    engine = CryptoEngine()
    km = KeyManager()

    test_file = 'tests/test_tamper.txt'
    with open(test_file, 'w') as f:
        f.write("Original content.")

    key = km.generate_key()
    enc_path = engine.encrypt_file(test_file, key)

    # Tamper with the encrypted file
    with open(enc_path, 'r+b') as f:
        f.seek(30)
        f.write(b'\x00\x00\x00\x00')

    try:
        engine.decrypt_file(enc_path, key)
        print("FAIL — tamper was not detected.")
    except ValueError as e:
        print(f"Test passed — tampering detected: {e}")

if __name__ == '__main__':
    test_encrypt_decrypt()
    test_tamper_detection()