# filecrypt2: Secure File Encryption (Under Development)

**filecrypt2** is a file encryption tool written in Go, designed to provide robust security for your sensitive data.

## Encryption Methods:

**filecrypt2** uses the following encryption algorithms:

1. **Argon2** (argon2id variant):  
   - **Purpose:** Key derivation function (KDF) used to securely derive the encryption key from a user-provided password.  
   - **Key Features:**  
     - Memory-intensive (128 MB) and CPU-intensive (4 parallel threads) for increased security.  
     - **Iteration count** (4 iterations by default) adds another layer of security, making brute-force attacks significantly harder.  
   
2. **AES-GCM**:  
   - **Purpose:** Symmetric encryption algorithm (AES) in Galois/Counter Mode (GCM) used for the actual encryption/decryption of files.  
   - **Key Features:**  
     - Provides both confidentiality (encryption) and integrity (authenticated encryption), ensuring the file's data is safe from tampering.

**Features:**

* **Strong Encryption:** Employs advanced encryption algorithms for maximum protection.
* **User-Friendly Interface:** Offers a highly intuitive and easy-to-use experience.
* **Configurable Encryption settings:** Change encryption variables like Salt size, Nonce size and more for better security

## Usage:
```
Usage: ./filecrypt2 [<settings>] [option] <input_file> [<output_file>]

Advanced Settings:
  -s, --salt SIZE    Salt size (default: 32)
  -i, --iter COUNT   Iteration count (default: 4)
  -k, --key SIZE     Key size (default: 32 bytes)
  -n, --nonce SIZE   Nonce size (default: 12 bytes)

Options:
  -e, --encrypt      Encrypt the input_file
  -d, --decrypt      Decrypt the input_file
  -p, --print        Print to stdout
  -h, --help         Show help menu

Note: If no option is provided, the default action is to print the decrypted file content (using --print).

Examples:
  Encrypt a file: ./filecrypt2 -e file.txt file.enc
  Decrypt a file: ./filecrypt2 -d file.enc file.txt
  Print decrypted file: ./filecrypt2 -d file.enc -p or ./filecrypt2 file.enc

If output_file or the print option is used, the input_file will not be modified.
```
