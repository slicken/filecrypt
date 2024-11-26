# filecrypt2: Secure File Encryption Tool

**filecrypt2** is a command-line file encryption tool written in Go, designed for robust security and ease of use. It uses strong encryption algorithms and provides flexibility to customize key cryptographic parameters.

---

## 🚀 Features:

- **Strong Encryption**: Implements Argon2 and AES-GCM to ensure high levels of security.
- **Customizable Security Settings**: Adjust salt size, iteration count, and key size for tailored protection.
- **Password Validation**: Enforces strong password policies, requiring uppercase letters, digits, and special characters.
- **Built-in Integrity Protection**: Ensures file authenticity and prevents tampering.
- **Cross-Platform**: Compatible with major operating systems (Linux, macOS, Windows).
- **Encrypted Output**: Generates secure Base64-encoded encrypted files for easy handling.
- **Safe Password Handling**: Implements password masking during input and secure memory cleanup.
- **Version Agnostic Decryption**: Reads file salt, nonce, and ciphertext for seamless decryption.

---

## 🔒 Encryption Methods:

### 1. **Argon2 (argon2id variant)**  
**Purpose**: Derives a secure encryption key from a user-provided password.  

**Key Features**:  
- **Memory-Intensive**: Uses 128 MB of memory to defend against hardware-based attacks.  
- **Parallelism**: Executes 4 parallel threads for increased computational cost to attackers.  
- **Iteration Count**: Defaults to 4 iterations for enhanced security.  
- Resistant to GPU and side-channel attacks.  

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
filecrypt2 --salt=64 --iter=6 --key=64 -e file.txt file.enc
```

## Help:
```
Usage: ./filecrypt2 [<settings>] [option] <input_file> [<output_file>]

Advanced Settings:
  -s, --salt SIZE    Salt size (default: %d bytes, fixed minimum)
  -i, --iter COUNT   Iteration count for Argon2 (default: %d, minimum: %d)
  -k, --key SIZE     Key size (default: %d bytes, fixed minimum)

Options:
  -e, --encrypt      Encrypt the input file
  -d, --decrypt      Decrypt the input file
  -p, --print        Print result to stdout
  -h, --help         Show help menu

Note:
If no option is provided, default action will decrypt and print
result to stdout without modifying input_file.

If output_file or the print option is used, input_file will not be modified.

Examples:
  Encrypt a file: ./filecrypt2 -e file.txt file.enc
  Decrypt a file: ./filecrypt2 -d file.enc file.txt
  Print decrypted file: ./filecrypt2 -d file.enc -p or %s file.enc
```
