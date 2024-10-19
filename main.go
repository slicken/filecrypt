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
	"log"
	"os"
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

func printHelp(code int) {
	fmt.Printf(`Usage: %s [option] <input_file> [<output_file>]

Option:
  -e, --encrypt      Encrypt the input_file
  -d, --decrypt      Decrypt the input_file
  -p, --print        Print to stdout without changing input_file"
  (default: no option prints to stdout)
`, os.Args[0])
	os.Exit(code)
}

func main() {
	var option, file, outfile string

	for _, v := range os.Args[1:] {
		switch v {
		case "-e", "-enc", "--encrypt":
			option = "Encrypt"
		case "-d", "-dec", "--decrypt":
			option = "Decrypt"
		case "-p", "--print":
			option = "Print"
		default:
			if file == "" {
				file = v
				outfile = v
			} else if file == outfile {
				outfile = v
			}
		}
	}

	if file == "" {
		printHelp(1)
	}
	if option == "" {
		option = "Print"
	}
	_, err := os.Stat(file)
	if err != nil && os.IsNotExist(err) {
		log.Printf("%q does not exist. try again\n", file)
	}

	var result []byte
	fileData, err := os.ReadFile(file)
	if err != nil {
		log.Fatalln("Error reading file:", err)
	}

	if option == "Print" || option == "Decrypt" {
		password, err := prompt("Enter password: ")
		if err != nil {
			log.Fatalln(err)
		}
		result, err = decrypt(fileData, password)
		if err != nil {
			log.Fatalln("Error decryption:", err)
		}
	} else if option == "Encrypt" {
		password, err := setPassword(minPasswordLength)
		if err != nil {
			log.Fatalln(err)
		}
		result, err = encrypt(fileData, password)
		if err != nil {
			log.Fatalln("Encryption error:", err)
		}
	}

	if !(option == "Print" && file == outfile) {
		if err = os.WriteFile(outfile, result, 0600); err != nil {
			log.Println("Error writing file:", err)
		}
		fmt.Printf("Successfully %sed %q.\n", option, outfile)
	}

	if option == "Print" {
		fmt.Printf("%s", result)
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
	nonce, err := generateNonce()
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
			return nil, fmt.Errorf("Password must contain at least %d characters\n", minLength)
		}
		confirm, err := prompt("Confirm password: ")
		if err != nil {
			return nil, fmt.Errorf("confirmation error: %s", err)
		}
		if !bytes.Equal(password, confirm) {
			return nil, fmt.Errorf("Passwords did not match. Try again.")
		}

		return password, nil
	}
}

func prompt(input string) ([]byte, error) {
	defer fmt.Println()
	fmt.Print(input)

	return term.ReadPassword(int(syscall.Stdin))
}
