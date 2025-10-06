from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

BLOCK_SIZE = 16  # AES block size

def encrypt_file(file_path: str, key: bytes) -> str:
    with open(file_path, 'rb') as f:
        data = f.read()
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE))
    out_path = file_path + ".enc"
    with open(out_path, 'wb') as f:
        f.write(iv + ciphertext)
    print(f"File encrypted successfully as {out_path}")
    return out_path

def decrypt_file(enc_file_path: str, key: bytes) -> str:
    with open(enc_file_path, 'rb') as f:
        iv = f.read(BLOCK_SIZE)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    except ValueError:
        raise ValueError("Decryption failed: wrong key or corrupted data (bad padding).")
    out_path = enc_file_path[:-4] + ".dec" if enc_file_path.endswith(".enc") else enc_file_path + ".dec"
    with open(out_path, 'wb') as f:
        f.write(plaintext)
    print(f"File decrypted successfully as {out_path}")
    return out_path

def main():
    print("Advanced Encryption Tool\n")
    operation = input("Choose operation (encrypt/decrypt): ").strip().lower()
    file_path = input("Enter path of the file: ").strip()
    key_str = input("Enter 32-byte encryption key (exactly 32 characters): ")
    key = key_str.encode("utf-8")
    if len(key) != 32:
        print("Encryption key must be exactly 32 bytes long.")
        return
    if operation == "encrypt":
        encrypt_file(file_path, key)
    elif operation == "decrypt":
        decrypt_file(file_path, key)
    else:
        print("Invalid operation selected.")

if __name__ == "__main__":
    main()
