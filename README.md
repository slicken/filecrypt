# filecrypt2: Secure File Encryption Tool

**filecrypt2** is a command-line file encryption tool written in Go, designed for robust security and ease of use. It uses strong encryption algorithms and provides flexibility to customize key cryptographic parameters.

---

## 🚀 Features:

- **Strong Encryption**: Implements AES-GCM for secure file encryption.
- **Customizable Security Settings**: Adjust salt size, iteration count, and key size for tailored protection.
- **Password Validation**: Enforces strong password policies, requiring uppercase letters, digits, and special characters.
- **Built-in Integrity Protection**: Ensures file authenticity and prevents tampering.
- **Cross-Platform**: Compatible with major operating systems (Linux, macOS, Windows).
- **Encrypted Output**: Generates secure encrypted files for easy handling.
- **Safe Password Handling**: Implements password masking during input and secure memory cleanup.
- **Version Agnostic Decryption**: Reads file salt, nonce, and ciphertext for seamless decryption.

---

## 🔒 Encryption Methods:

### 1. **PBKDF2 (Password-Based Key Derivation Function 2)**  
**Purpose**: Derives a secure encryption key from a user-provided password.  

**Key Features**:  
- **Memory and Time-Intensive**: Uses a high iteration count to slow down brute-force attacks.  
- **Key Size**: Supports adjustable key size to balance security and performance.
- **Secure Salt**: Uses a unique, randomly generated salt to prevent rainbow table attacks.
- **Strong Security**: Suitable for protecting sensitive data with a reasonable computational cost.  

---

### 2. **AES-GCM (Advanced Encryption Standard with Galois/Counter Mode)**  
**Purpose**: Provides authenticated encryption for secure data storage.  

**Key Features**:  
- **Authenticated Encryption**: Ensures confidentiality and verifies file integrity.  
- **Nonce Size**: Uses a fixed 12-byte nonce, as recommended by NIST.  
- **Key Size**: Employs a default 32-byte key for 256-bit security.  

---

## ⚙️ Usage:

```bash
# Encrypt a file
filecrypt2 -e file.txt file.enc

# Decrypt a file
filecrypt2 -d file.enc file.txt

# Customize settings (e.g., salt size, iteration count, or key size)
filecrypt2 --salt=64 --iter=20000000 --key=64 -e file.txt file.enc
```

## Help:
```
Usage: ./filecrypt2 [<settings>] [option] <input_file> [<output_file>]

Advanced Settings:
  -s, --salt SIZE    Salt size (default: %d bytes)
  -i, --iter COUNT   Iteration count (default: %d)
  -k, --key SIZE     Key size (default: %d bytes)

  Options:
  -e, --encrypt      Encrypt the input file
  -d, --decrypt      Decrypt the input file
  -b, --binary       Output in binary format (raw data)
  -p, --print        Print result to stdout
  -h, --help         Show help menu

Note:
If no option is provided, default action will decrypt and print
result to stdout without modifying input_file.

If output_file or the print option is used, input_file will not be modified.

Examples:
  Encrypt a file: ./filecrypt2 -e file.txt file.enc
  Decrypt a file: ./filecrypt2 -d file.enc file.txt
  Print decrypted file: ./filecrypt2 -d file.enc -p or ./filecrypt2 file.enc
```
