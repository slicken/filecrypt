# filecrypt2: Secure File Encryption (Under Development)

**filecrypt2** is a file encryption tool written in Go, designed to provide robust security for your sensitive data.

**Features:**

* **Strong Encryption:** Employs advanced encryption algorithms for maximum protection.
* **User-Friendly Interface:** Offers a highly intuitive and easy-to-use experience.
* **Configurable Encryption settings:** Change encryption variables like Salt size, Nonce size and more for better security

```
Usage: filecrypt2 [<settings>] [option] <input_file> [<output_file>]

Encryption Settings:
  -s, --salt         Salt size (default: 16)
  -k, --key          Key size (default: 32)
  -n, --nonce        Nonce size (default: 12)
  -i, --iter         Iteration count (default: 100000)

Option:
  -e, --encrypt      Encrypt the input_file
  -d, --decrypt      Decrypt the input_file
  -p, --print        Decrypt and print to stdout
                     without changing input_file
  (default: no option will use --print)

If output_file is provided, option data will be written
without altering the input_file.
```
