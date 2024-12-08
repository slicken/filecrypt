package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	minPasswordLength = 8
	minSaltSize       = 8
	minIterCount      = 10000
	minKeySize        = 16
	requiredNonceSize = 12 // Fixed to 12 bytes as required by AES-GCM
)

var (
	saltSize       = 16       // Salt size (good default)
	keySize        = 32       // Ensure AES-256 key size
	iterationCount = 10000000 // Strong iteration count for PBKDF2
	binary         = false
)

func printHelp(code int) {
	fmt.Printf(`Usage: %s [<settings>] [option] <input_file> [<output_file>]

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
  Encrypt a file: %s -e file.txt file.enc
  Decrypt a file: %s -d file.enc file.txt
  Print decrypted file: %s -d file.enc -p or %s file.enc

`, os.Args[0], saltSize, iterationCount, keySize, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
	os.Exit(code)
}

func main() {
	var option, file, outfile string
	var printScreen bool

	// arguments works in any order and with 'flag=X' or without '-flag X'

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
				if saltSize < minSaltSize {
					log.Fatalf("Salt size must be at least %d bytes\n", minSaltSize)
				}
				fmt.Println("Salt size set to:", saltSize)
			case "-i", "--iter":
				if iterationCount, err = strconv.Atoi(value); err != nil {
					log.Fatalln("Iteration count value is missing (type=int) in -i=value/--iter=value")
				}
				if iterationCount < minIterCount {
					log.Fatalf("Iteration count must be at least %d\n", minIterCount)
				}
				fmt.Println("Iteration count set to:", iterationCount)
			case "-k", "--key":
				if keySize, err = strconv.Atoi(value); err != nil {
					log.Fatalln("Key size value is missing (type=int) in -k=value/--key=value")
				}
				if keySize < minKeySize {
					log.Fatalf("Key size must be at least %d bytes\n", minKeySize)
				}
				fmt.Println("Key size set to:", keySize)
			default:
				log.Fatalf("Invalid argument: %s. Use -h or --help to see the correct usage.\n", flag)
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
					if n < minSaltSize {
						log.Fatalf("Salt size must be at least %d bytes\n", minSaltSize)
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
					if n < minIterCount {
						log.Fatalf("Iteration count must be at least %d\n", minIterCount)
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
					if n < minKeySize {
						log.Fatalf("Key size must be at least %d bytes\n", minKeySize)
					}
					keySize = n
					fmt.Println("Key size set to:", keySize)
					i++
				} else {
					log.Fatalln("Key size value is missing after -k/--key")
				}
			case "-e", "-enc", "--encrypt":
				if option == "Decrypt" {
					log.Fatalln("Can't use Encrypt and Decrypt at the same time")
				}
				option = "Encrypt"
			case "-d", "-dec", "--decrypt":
				if option == "Encrypt" {
					log.Fatalln("Can't use Encrypt and Decrypt at the same time")
				}
				option = "Decrypt"
			case "-p", "--print":
				printScreen = true
			case "-b", "--binary":
				binary = true
				fmt.Println("Output will be in binary format (raw data)")
			default:
				if file == "" {
					file = arg
				} else {
					outfile = arg
				}
			}
		}
	}

	// checks

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
		log.Printf("%q does not exist. Try again\n", file)
	}

	// program

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
		result, err = decrypt(fileData, &password)
		if err != nil {
			log.Fatalln("Error during decryption:", err)
		}
	} else if option == "Encrypt" {
		password, err := setPassword(minPasswordLength)
		if err != nil {
			log.Fatalln(err)
		}
		result, err = encrypt(fileData, &password)
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

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

func generateNonce() ([]byte, error) {
	nonce := make([]byte, requiredNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}
	return nonce, nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	return salt, nil
}

func deriveKey(password []byte, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterationCount, keySize, sha256.New)
}

func encrypt(data []byte, password *[]byte) ([]byte, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}

	key := deriveKey(*password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	zeroBytes(*password)

	// return binary or base64 format
	if binary {
		return append(append(salt, nonce...), ciphertext...), nil
	}

	encData := append(append(salt, nonce...), ciphertext...)
	encoded := base64.StdEncoding.EncodeToString(encData)
	return []byte(encoded), nil
}

func decrypt(data []byte, passphrase *[]byte) ([]byte, error) {
	// base64 format
	if !binary {
		var err error
		decodedData, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, err
		}
		data = decodedData
	}

	if len(data) < saltSize+requiredNonceSize {
		return nil, errors.New("malformed ciphertext")
	}

	salt, ciphertext := data[:saltSize], data[saltSize:]
	nonce, ciphertext := ciphertext[:requiredNonceSize], ciphertext[requiredNonceSize:]

	key := deriveKey(*passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		zeroBytes(*passphrase)
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(*passphrase)
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	zeroBytes(*passphrase)

	return plaintext, err
}

func setPassword(minLength int) ([]byte, error) {
	password, err := prompt("Enter password: ")
	if err != nil {
		return nil, fmt.Errorf("password error: %s", err)
	}
	if len(password) < minLength {
		zeroBytes(password)
		return nil, fmt.Errorf("password must contain at least %d characters", minLength)
	}
	if !isStrongPassword(password) {
		zeroBytes(password)
		return nil, fmt.Errorf("password must contain at least one uppercase letter, one digit, and one special character")
	}
	confirm, err := prompt("Confirm password: ")
	if err != nil {
		zeroBytes(password)
		return nil, fmt.Errorf("confirmation error: %s", err)
	}
	if subtle.ConstantTimeCompare(password, confirm) != 1 {
		zeroBytes(password)
		zeroBytes(confirm)
		return nil, fmt.Errorf("passwords did not match. Try again")
	}
	zeroBytes(confirm)
	return password, nil
}

func isStrongPassword(password []byte) bool {
	// check for one uppercase letter
	re := regexp.MustCompile(`[A-Z]`)
	hasUppercase := re.Match(password)
	// check for one digit
	re = regexp.MustCompile(`\d`)
	hasDigit := re.Match(password)
	// check for one special character from the set [!@#$%^&*()_+=\[\]{}:;'"<>.,?/~\-]
	//re = regexp.MustCompile(`[!@#$%^&*()_+=\[\]{}:;'"<>.,?/~\-]`)
	//hasSpecial := re.Match(password)
	return hasUppercase && hasDigit //&& hasSpecial
}

func prompt(label string) ([]byte, error) {
	fmt.Fprint(os.Stderr, label)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return password, nil
}
