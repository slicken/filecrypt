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
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	minPasswordLength = 8
)

var (
	saltSize       = 16       // Salt size (good default)
	keySize        = 32       // Key size for AES-256 (good default)
	nonceSize      = 12       // Nonce size for AES-GCM (good default)
	iterationCount = 10000000 // Very string iteration count for PBKDF2
)

func printHelp(code int) {
	fmt.Printf(`Usage: %s [<settings>] [option] <input_file> [<output_file>]

Encryption Settings:
  -s, --salt         Salt size (default: %d)
  -k, --key          Key size (default: %d)
  -n, --nonce        Nonce size (default: %d)
  -i, --iter         Iteration count (default: %d)

Option:
  -e, --encrypt      Encrypt the input_file
  -d, --decrypt      Decrypt the input_file
  -p, --print        Decrypt and print to stdout
                     without altering input_file
  (default: no option will use --print)

if output_file is provided, option data will be written
without altering the input_file

`, os.Args[0], saltSize, keySize, nonceSize, iterationCount)
	os.Exit(code)
}

func main() {
	var option, file, outfile string
	var printScreen bool

	for i := 0; i < len(os.Args)-1; i++ {
		arg := os.Args[i+1]

		// Process flags that have an equal sign
		if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			flag := parts[0]
			value := parts[1]

			if len(value) == 0 {
				log.Fatalf("value is missing in %s=\n", flag)
			}

			var err error
			switch flag {
			case "-s", "--salt":
				if saltSize, err = strconv.Atoi(value); err != nil {
					log.Fatalln("Salt size value is missing (type=int) in -s=value/--salt=value")
				}
				fmt.Println("Salt size set to:", saltSize)
			case "-k", "--key":
				if keySize, err = strconv.Atoi(value); err != nil {
					log.Fatalln("Key size value is missing (type=int) in -k=value/--key=value")
				}
				fmt.Println("Key size set to:", keySize)
			case "-n", "--nonce":
				if nonceSize, err = strconv.Atoi(value); err != nil {
					log.Fatalln("Nonce size value is missing (type=int) in -n=value/--nonce=value")
				}
				fmt.Println("Nonce size set to:", nonceSize)
			case "-i", "--iter":
				if iterationCount, err = strconv.Atoi(value); err != nil {
					log.Fatalln("Iteration count value is missing (type=int) in -i=value/--iter=value")
				}
				fmt.Println("Iteration count set to:", iterationCount)
			default:
				log.Fatalf("Invalid argument %s", flag)
			}
		} else {
			// Process flags that don't require an equal sign
			switch arg {
			case "-s", "--salt":
				if i+2 < len(os.Args) {
					n, err := strconv.Atoi(os.Args[i+2])
					if err != nil {
						log.Fatalln("Invalid salt size:", err)
					}
					saltSize = n
					fmt.Println("Salt size set to:", saltSize)
					i++
				} else {
					log.Fatalln("Salt size value is missing after -s/--salt")
				}
			case "-k", "--key":
				if i+2 < len(os.Args) {
					n, err := strconv.Atoi(os.Args[i+2])
					if err != nil {
						log.Fatalln("Invalid key size:", err)
					}
					keySize = n
					fmt.Println("Key size set to:", keySize)
					i++ // Skip next argument
				} else {
					log.Fatalln("Key size value is missing after -k/--key")
				}
			case "-n", "--nonce":
				if i+2 < len(os.Args) {
					n, err := strconv.Atoi(os.Args[i+2])
					if err != nil {
						log.Fatalln("Invalid nonce size:", err)
					}
					nonceSize = n
					fmt.Println("Nonce size set to:", nonceSize)
					i++ // Skip next argument
				} else {
					log.Fatalln("Nonce value is missing after -n/--nonce")
				}
			case "-i", "--iter":
				if i+2 < len(os.Args) {
					n, err := strconv.Atoi(os.Args[i+2])
					if err != nil {
						log.Fatalln("Invalid iteration count:", err)
					}
					iterationCount = n
					fmt.Println("Iteration count set to:", iterationCount)
					i++ // Skip next argument
				} else {
					log.Fatalln("Iteration count value is missing after -i/--iter")
				}
			case "-e", "-enc", "--encrypt":
				option = "Encrypt"
			case "-d", "-dec", "--decrypt":
				option = "Decrypt"
			case "-p", "--print":
				printScreen = true
			default:
				if file == "" {
					file = arg
				} else {
					outfile = arg
				}
			}
		}
	}

	if outfile == "" && file != "" {
		outfile = file
	}

	if file == "" {
		printHelp(1)
	}
	if option == "" {
		option = "Decrypt"
		printScreen = true
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

	if !(printScreen && file == outfile) {
		if err = os.WriteFile(outfile, result, 0600); err != nil {
			log.Println("Error writing file:", err)
		}
		fmt.Printf("Successfully %sed %q.\n", option, outfile)
	}

	if printScreen {
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
	password, err := prompt("Enter password: ")
	if err != nil {
		return nil, fmt.Errorf("password error: %s", err)
	}
	if len(password) < minLength {
		return nil, fmt.Errorf("password must contain at least %d characters", minLength)
	}
	if !isStrongPassword(password) {
		return nil, fmt.Errorf("password must contain at least one uppercase letter, one digit, and one special character")
	}
	confirm, err := prompt("Confirm password: ")
	if err != nil {
		return nil, fmt.Errorf("confirmation error: %s", err)
	}
	if !bytes.Equal(password, confirm) {
		return nil, fmt.Errorf("passwords did not match. Try again")
	}
	return password, nil
}

func isStrongPassword(password []byte) bool {
	hasUpper := false
	hasDigit := false
	hasSpecial := false
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case (c >= '!' && c <= '/') || (c >= ':' && c <= '@') || (c >= '[' && c <= '`') || (c >= '{' && c <= '~'):
			hasSpecial = true
		}
	}
	return hasUpper && hasDigit && hasSpecial
}

func prompt(input string) ([]byte, error) {
	defer fmt.Println()
	fmt.Print(input)

	return term.ReadPassword(int(syscall.Stdin))
}
