from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_file(input_path, output_path, password):
    # Read data
    with open(input_path, "rb") as f:
        data = f.read()
    
    # Derive 256-bit key from password
    key = SHA256.new(password.encode("utf-8")).digest()
    
    # Generate random IV
    iv = get_random_bytes(16)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data))
    
    # Write IV + ciphertext
    with open(output_path, "wb") as f:
        f.write(iv + ciphertext)
    
    print(f"Encrypted {input_path} -> {output_path}")

def decrypt_file(input_path, output_path, password):
    with open(input_path, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()
    
    key = SHA256.new(password.encode("utf-8")).digest()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext))
    
    with open(output_path, "wb") as f:
        f.write(decrypted)
    
    print(f"Decrypted {input_path} -> {output_path}")

if __name__ == "__main__":
    import sys
    # if len(sys.argv) != 5:
    #     print("Usage:")
    #     print("  python aes_zip.py encrypt input.zip output.zip.enc MySecretKey")
    #     print("  python aes_zip.py decrypt input.zip.enc output.zip MySecretKey")
    #     sys.exit(1)

    #cmd, inp, outp, pwd = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    cmd="encrypt"
    if cmd == "encrypt":
        encrypt_file("./file.zip", "./file.zip.enc", "Mypassword")
    elif cmd == "decrypt":
        decrypt_file(inp, outp, pwd)
    else:
        print("Invalid command. Use 'encrypt' or 'decrypt'.")

