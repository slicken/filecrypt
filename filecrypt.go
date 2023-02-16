package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

var iv = []byte("masterskey16bits")

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

	for _, v := range os.Args {
		switch v {
		case "-e", "--encrypt":
			mode = "Encrypt"

		case "-d", "--dectrypt":
			mode = "Decrypt"

		default:
			file = v
		}
	}

	if file == "" || len(os.Args) == 1 {
		printHelp()
		return
	}

	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Printf("%s does not exist. try again\n", file)
		return
	}

	// ---
	var w, pw []byte
	r, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}

	if mode == "Encrypt" {
		pw, err = SetPassword(3)
		if err != nil {
			fmt.Println(err)
			return
		}
		w, err = encrypt(r, string(pw))
		if err != nil {
			panic(err)
		}
	}

	if mode == "Decrypt" || mode == "" {
		pw, err = Prompt("Enter password: ", true)
		if err != nil {
			fmt.Println(err)
			return
		}
		w, err = decrypt(r, string(pw))
		if err != nil {
			fmt.Println("Wrong Password")
			return
		}
	}

	if mode == "" {
                fmt.Printf("%s\n", w)
                return
        }

	// write file
	if err = ioutil.WriteFile(file, w, 0644); err != nil {
		panic(err)
	}
	fmt.Printf("Successfully %sed %s\n", mode, file)
}

func md5hash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(md5hash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	// encode to string
	return []byte(base64.URLEncoding.EncodeToString(ciphertext)), nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	key := []byte(md5hash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// decode string
	msg, err := base64.URLEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := msg[:nonceSize], msg[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SetPassword ...
func SetPassword(minLenght int) ([]byte, error) {
	password, err := Prompt("Enter password: ", true)
	if err != nil {
		return nil, fmt.Errorf("password error: %s", err)
	}
	if len(password) < minLenght {
		fmt.Printf("Password must contain at least %d charecters\n", minLenght)
	}
	confirm, err := Prompt("Confirm password: ", true)
	if err != nil {
		return nil, fmt.Errorf("confirmation error: %s", err)
	}
	if !bytes.Equal(password, confirm) {
		return nil, errors.New("passwords did not match")
	}
	return password, nil
}

// Prompt for input ...
func Prompt(input string, hidden bool) (b []byte, err error) {
	defer fmt.Println()
	fmt.Printf(input)

	if hidden {
		return terminal.ReadPassword(int(syscall.Stdin))
	} else {
		_, err = fmt.Fscanln(bufio.NewReader(os.Stdin), &b)
	}
	return b, err
}

// func maskInput(mask string) ([]byte, error) {
// 	fd := int(os.Stdin.Fd())
// 	state, err := terminal.MakeRaw(fd)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer terminal.Restore(fd, state)

// 	// read and manipulate stdin
// 	var buf []byte
// 	for {
// 		var b [1]byte
// 		n, err := os.Stdin.Read(b[:])
// 		if err != nil && err != io.EOF {
// 			return nil, err
// 		}
// 		if n == 0 || b[0] == '\n' || b[0] == '\r' {
// 			break
// 		}

// 		buf = append(buf, b[0])
// 		fmt.Printf(mask)
// 	}

// 	fmt.Printf("\r\n")
// 	return buf, nil
// }
