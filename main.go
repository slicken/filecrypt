package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	minPasswordLength = 8
	saltSize          = 16
	keySize           = 32
	nonceSize         = 12
	iterationCount    = 100000
)

func printHelp() {
	_, app := filepath.Split(os.Args[0])
	fmt.Printf("Usage: %s [option] /path/filename\n", app)
	fmt.Println()
	fmt.Printf("Option:\n")
	fmt.Printf(" -e,--encrypt\n")
	fmt.Printf(" -d,--decrypt\n")
	fmt.Printf("(no option reads file)\n")
	fmt.Println()
}

func main() {
	var mode, file string

	for _, v := range os.Args[1:] {
		switch v {
		case "-e", "--encrypt":
			mode = "Encrypt"
		case "-d", "--decrypt":
			mode = "Decrypt"
		default:
			file = v
		}
	}

	if file == "" {
		printHelp()
		return
	}

	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Printf("%s does not exist. try again\n", file)
		return
	}

	var output []byte
	content, err := os.ReadFile(file)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	if mode == "Encrypt" {
		password, err := setPassword(minPasswordLength) // Ensures minimum password length
		if err != nil {
			fmt.Println(err)
			return
		}
		output, err = encrypt(content, password)
		if err != nil {
			fmt.Println("Encryption error:", err)
			return
		}
	} else if mode == "Decrypt" || mode == "" {
		password, err := prompt("Enter password: ")
		if err != nil {
			fmt.Println(err)
			return
		}
		output, err = decrypt(content, password)
		if err != nil {
			fmt.Println("Error decryption:", err)
			return
		}
	}

	if mode == "" {
		fmt.Printf("%s", output)
	} else {
		if err = os.WriteFile(file, output, 0600); err != nil { // Sets file permissions to 0600
			fmt.Println("Error writing file:", err)
			return
		}
		fmt.Printf("Successfully %sed %s\n", mode, file)
	}
}

func generateNonce() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func deriveKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterationCount, keySize, sha256.New)
}

func encrypt(data, passphrase []byte) ([]byte, error) {
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}
	key := deriveKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := generateNonce() // Generate a new nonce for each encryption
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return []byte(base64.URLEncoding.EncodeToString(append(salt, ciphertext...))), nil
}

func decrypt(data, passphrase []byte) ([]byte, error) {
	rawData, err := base64.URLEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	if len(rawData) < saltSize+nonceSize {
		return nil, errors.New("malformed ciphertext")
	}
	salt, ciphertext := rawData[:saltSize], rawData[saltSize:]
	key := deriveKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func setPassword(minLength int) ([]byte, error) {
	for { // Ensures minimum password length
		password, err := prompt("Enter password: ")
		if err != nil {
			return nil, fmt.Errorf("password error: %s", err)
		}
		if len(password) < minLength {
			fmt.Printf("Password must contain at least %d characters\n", minLength)
			continue
		}
		confirm, err := prompt("Confirm password: ")
		if err != nil {
			return nil, fmt.Errorf("confirmation error: %s", err)
		}
		if !bytes.Equal(password, confirm) {
			fmt.Println("Passwords did not match. Try again.")
			continue
		}
		return password, nil
	}
}

func prompt(input string) ([]byte, error) {
	defer fmt.Println()
	fmt.Print(input)

	return term.ReadPassword(int(syscall.Stdin))
}
