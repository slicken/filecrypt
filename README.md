# filecrypt2

Simple file Encrypter/Decrypter written in Go

Here's a summary of the improvements made from my "filecrypt"

- **Nonce Generation and Usage:** In the final code, a nonce is generated for each encryption operation, ensuring that each ciphertext is unique even when encrypting the same plaintext multiple times with the same key. This prevents certain cryptographic attacks.

- **Salt Usage:** The final code incorporates the use of a salt during key derivation, which strengthens the security of the encryption process by making it computationally infeasible to precompute hashes for common passwords.

- **Password Confirmation:** The `setPassword` function now includes a step for confirming the entered password, ensuring that users input their password correctly and reducing the risk of unintended password errors.

- **Error Handling:** Error handling is improved throughout the codebase to provide more informative error messages and to handle potential errors more gracefully.

- **Input Validation:** The minimum password length is enforced in the `setPassword` function, ensuring that users provide passwords that meet certain security requirements.

Overall, these improvements enhance the security, robustness, and usability of the encryption and decryption process.

Usage: `filecrypt [option] /path/to/anyfile`

Options:
- `-e,--encrypt`
- `-d,--decrypt`
(no option reads encrypted file)


<br>
Usage: filecrypt [option] /path/to/anyfile<br>
<br>
Options:<br>
 -e,--encrypt<br>
 -d,--decrypt<br>
(no option reads encrypted file)
 <br>

