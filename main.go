package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	minPasswordLength = 8
	defaultSaltSize   = 32
	defaultKeySize    = 32
	defaultIterCount  = 4
	requiredNonceSize = 12 // Fixed to 12 bytes as required by AES-GCM

	argonMemory      uint32 = 128 * 1024
	argonParallelism uint8  = 4
)

var (
	saltSize       = defaultSaltSize
	iterationCount = defaultIterCount
	keySize        = defaultKeySize
)

func printHelp(code int) {
	fmt.Printf(`Usage: %s [<settings>] [option] <input_file> [<output_file>]

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
  Encrypt a file: %s -e file.txt file.enc
  Decrypt a file: %s -d file.enc file.txt
  Print decrypted file: %s -d file.enc -p or %s file.enc

`, os.Args[0], defaultSaltSize, defaultIterCount, defaultIterCount, defaultKeySize, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
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
				if saltSize < defaultSaltSize {
					log.Fatalf("Salt size must be at least %d bytes\n", defaultSaltSize)
				}
				fmt.Println("Salt size set to:", saltSize)
			case "-i", "--iter":
				if iterationCount, err = strconv.Atoi(value); err != nil {
					log.Fatalln("Iteration count value is missing (type=int) in -i=value/--iter=value")
				}
				if iterationCount < defaultIterCount {
					log.Fatalf("Iteration count must be at least %d\n", defaultIterCount)
				}
				fmt.Println("Iteration count set to:", iterationCount)
			case "-k", "--key":
				if keySize, err = strconv.Atoi(value); err != nil {
					log.Fatalln("Key size value is missing (type=int) in -k=value/--key=value")
				}
				if keySize < defaultKeySize {
					log.Fatalf("Key size must be at least %d bytes\n", defaultKeySize)
				}
				fmt.Println("Key size set to:", keySize)
			default:
				log.Fatalf("Invalid argument: %s\n", flag)
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
					if n < defaultSaltSize {
						log.Fatalf("Salt size must be at least %d bytes\n", defaultSaltSize)
					}
					saltSize = n
					fmt.Println("Salt size set to:", saltSize)
					i++
				} else {
					log.Fatalln("Salt size value is missing after -s/--salt")
				}
			case "-i", "--iter":
				if i+2 < len(os.Args) {
					n, err := strconv.Atoi(os.Args[i+2])
					if err != nil {
						log.Fatalln("Invalid iteration count:", err)
					}
					if n < defaultIterCount {
						log.Fatalf("Iteration count must be at least %d\n", defaultIterCount)
					}
					iterationCount = n
					fmt.Println("Iteration count set to:", iterationCount)
					i++
				} else {
					log.Fatalln("Iteration count value is missing after -i/--iter")
				}
			case "-k", "--key":
				if i+2 < len(os.Args) {
					n, err := strconv.Atoi(os.Args[i+2])
					if err != nil {
						log.Fatalln("Invalid key size:", err)
					}
					if n < defaultKeySize {
						log.Fatalf("Key size must be at least %d bytes\n", defaultKeySize)
					}
					keySize = n
					fmt.Println("Key size set to:", keySize)
					i++
				} else {
					log.Fatalln("Key size value is missing after -k/--key")
				}
			case "-e", "-enc", "--encrypt":
				if option == "Decrypt" {
					log.Fatalln("Cant use Encrypt and Decrypt at the same time")
				}
				option = "Encrypt"
			case "-d", "-dec", "--decrypt":
				if option == "Encrypt" {
					log.Fatalln("Cant use Encrypt and Decrypt at the same time")
				}
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
		defer zeroBytes(password)
		result, err = decrypt(fileData, password)
		if err != nil {
			log.Fatalln("Error decryption:", err)
		}
	} else if option == "Encrypt" {
		password, err := setPassword(minPasswordLength)
		if err != nil {
			log.Fatalln(err)
		}
		defer zeroBytes(password)
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
	nonce := make([]byte, requiredNonceSize) // Fixed to 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}
	return nonce, nil
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	return salt, nil
}

func deriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, uint32(iterationCount), argonMemory, argonParallelism, uint32(keySize))
}

func encrypt(data, passphrase []byte) ([]byte, error) {
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(salt)

	key := deriveKey(passphrase, salt)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher mode: %v", err)
	}

	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(nonce)

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return []byte(base64.URLEncoding.EncodeToString(append(salt, ciphertext...))), nil
}

func decrypt(data, passphrase []byte) ([]byte, error) {
	rawData, err := base64.URLEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %v", err)
	}

	if len(rawData) < saltSize+requiredNonceSize {
		return nil, errors.New("ciphertext is malformed or corrupted")
	}

	salt, ciphertext := rawData[:saltSize], rawData[saltSize:]
	defer zeroBytes(salt)

	key := deriveKey(passphrase, salt)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher mode: %v", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext is too short")
	}

	nonce, ciphertext := ciphertext[:requiredNonceSize], ciphertext[requiredNonceSize:]
	defer zeroBytes(nonce)

	// 	return gcm.Open(nil, nonce, ciphertext, nil)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	return plaintext, nil
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
	if subtle.ConstantTimeCompare(password, confirm) != 1 {
		return nil, fmt.Errorf("passwords did not match. Try again")
	}
	return password, nil
}

func isStrongPassword(password []byte) bool {
	re := regexp.MustCompile(`[A-Z]`)
	hasUppercase := re.Match(password)

	re = regexp.MustCompile(`\d`)
	hasDigit := re.Match(password)

	re = regexp.MustCompile(`[!@#$%^&*]`)
	hasSpecial := re.Match(password)

	return len(password) >= minPasswordLength && hasUppercase && hasDigit && hasSpecial
}

func prompt(input string) ([]byte, error) {
	fmt.Fprint(os.Stderr, input)
	defer fmt.Fprintln(os.Stderr)

	return term.ReadPassword(int(syscall.Stdin))
}
