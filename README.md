# Android_Assets_AssetExtractor
Android Assets Extractor
# 🔐 AssetExtractor for Android (Java + Pyjnius)

A secure utility to extract **plain or AES-encrypted ZIP files** from Android APK assets using Java and call it from Python with [Pyjnius](https://github.com/kivy/pyjnius). Works seamlessly with Kivy + Buildozer apps.

---

## ✨ Features

- 🔓 **Decrypt AES-encrypted ZIPs** using AES/CBC/PKCS5Padding from APK assets.
- 📦 **Extract plain ZIPs** from assets without encryption.
- 🧩 Fully usable from Python via **Pyjnius**.
- 🛡️ Password-based decryption using SHA-256 derived key.
- 🧠 Designed to be used inside Android Kivy apps.

---

## 🧠 Java Functionality

### `decryptAndExtractZip(Context context, String assetPath, String outputPath, String password)`

> Decrypts an AES-encrypted ZIP file and extracts its contents to a specified path.

- AES key is SHA-256 hash of password.
- IV is expected to be the first 16 bytes of the encrypted file.
- Output directory must be writable by the app.

### `extractZipFromAssets(Context context, String assetPath, String outputPath)`

> Extracts a normal, unencrypted ZIP file from the APK assets.

---

## 📜 Pyjnius Usage Example (`main.py`)

```python
from jnius import autoclass
from android import mActivity

context = mActivity.getApplicationContext()

# Load Java class
AssetExtractor = autoclass('org.kivy.utils.AssetExtractor')

# Decrypt and extract
AssetExtractor.decryptAndExtractZip(
    context,
    "encrypted_assets/data.zip",
    context.getFilesDir().getAbsolutePath(),
    "your-password"
)

# Or extract plain zip
# AssetExtractor.extractZipFromAssets(context, "plain_assets/data.zip", context.getFilesDir().getAbsolutePath())

# buildozer.spec
android.add_src = java_code


# Using Python
Use this for build encrypted 

```python
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

```


## Note 
# 🔐 AssetExtractor for Android (Java + Pyjnius + Python Encryption)

Securely extract and decrypt **AES-encrypted ZIP files** inside your Android APK using Java, and trigger it via **Pyjnius from Python** in a Kivy app. Use the provided Python script to encrypt your ZIP assets before bundling.

---

## 📌 Project Summary

- 🔒 Use **Python (PyCryptodome)** to AES-encrypt your ZIP files.
- 📦 Place encrypted `.zip.enc` files in `assets/` so Buildozer bundles them in the APK.
- 🔓 On Android, use **Java** + **Pyjnius** to decrypt and extract at runtime.
- ✅ Fully offline, no internet or Firebase required.

---

## ✅ Workflow

1. ✅ **Zip** your asset files (`file.zip`)
2. ✅ **Encrypt** them using the provided Python script (`file.zip.enc`)
3. ✅ **Copy to `assets/`**
4. ✅ Build APK with Buildozer (includes `file.zip.enc`)
5. ✅ At runtime, call `AssetExtractor.decryptAndExtractZip()` from Python using Pyjnius

---

## 📦 Python Encryption Script

Use this Python code to encrypt ZIP files before adding them to your Android project:

```python
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def encrypt_file(input_path, output_path, password):
    with open(input_path, "rb") as f:
        data = f.read()
    key = SHA256.new(password.encode("utf-8")).digest()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data))
    with open(output_path, "wb") as f:
        f.write(iv + ciphertext)
    print(f"Encrypted {input_path} -> {output_path}")

# Example:
encrypt_file("file.zip", "file.zip.enc", "Mypassword")


# In kivy app side 
```python
  from jnius import autoclass
  from android import mActivity
  
  context = mActivity.getApplicationContext()
  
  # Load Java class
  AssetExtractor = autoclass('org.kivy.utils.AssetExtractor')
  
  # Decrypt and extract
  AssetExtractor.decryptAndExtractZip(
      context,
      "encrypted_assets/data.zip",
      context.getFilesDir().getAbsolutePath(),
      "your-password"
  )
  
  

```
