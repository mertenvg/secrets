package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	"gopkg.in/yaml.v3"

	"github.com/mertenvg/secrets/pkg/colorterm"
)

var (
	// App metadata
	name    = "secrets"
	version = "v1.0.0"

	// App configuration options
	options struct {
		Version bool   `long:"version" short:"v" description:"Display service name and version, then exit"`
		Key     string `long:"key" short:"k" env:"SECRETS_KEY" default:"" description:"Optional secrets key (if empty, one will be provided)"`
		Lock    bool   `long:"lock" short:"l" description:"Move secrets to encrypted files"`
		Unlock  bool   `long:"unlock" short:"u" description:"Extract secrets from encrypted files"`
		Force   bool   `long:"force" short:"f" description:"Forgo secrets hash checks and overwrite changes in unencrypted files"`
		Dry     bool   `long:"dry" short:"d" description:"Dry run mode, lock or unlock without updating files"`
		Wait    bool   `long:"wait" short:"w" description:"The number of minutes to wait before locking and exiting"`
		Minutes int    `long:"minutes" short:"m" env:"SECRETS_WAIT_MINUTES" default:"10" description:"The number of minutes to wait before locking and exiting"`
		Seconds int    `long:"seconds" short:"s" env:"SECRETS_WAIT_SECONDS" default:"0" description:"The number of seconds to wait before locking and exiting, may be used in conjunction with minutes"`
	}
)

const (
	encryptedFileExtension = ".enc"
	hashFileExtension      = ".sha256"
)

type Conf struct {
	Files []string `yaml:"files"`
}

func main() {
	// Parse the flags
	args, err := flags.Parse(&options)
	if err != nil {
		return
	}

	// Print the version and exit when version flag is set
	if options.Version {
		fmt.Printf("%s %s\n", name, version)
		return
	}

	var files []string

	b, err := os.ReadFile("./secrets.yaml")
	if err == nil {
		var conf Conf

		err = yaml.Unmarshal(b, &conf)
		if err != nil {
			colorterm.Error("Cannot parse secrets.yaml:", err)
			os.Exit(1)
		}

		files = append(files, conf.Files...)
	}

	for _, f := range args {
		files = append(files, f)
	}

	if options.Key == "" {
		if options.Key, err = generateRandomKey(32); err != nil {
			colorterm.Error("Failed to create a random key:", err)
			os.Exit(1)
		}
		fmt.Println("You didn't provide a key so we've created one for you, don't forget to save it:")
		colorterm.Successf("\n\t%s\n", options.Key)
		fmt.Println("Copy this to bash profile so we can get it from your env next time:")
		colorterm.Successf("\n\texport SECRETS_KEY=\"%s\"\n", options.Key)
	}

	key, err := hex.DecodeString(options.Key)
	if err != nil {
		colorterm.Error("Cannot decode key:", err)
		os.Exit(1)
	}

	if options.Lock {
		colorterm.None("Locking secrets")

		for _, f := range files {
			err := encryptFile(f, key, options.Dry, !options.Force)
			if err != nil {
				colorterm.Error(f, "lock error:", err)
			}
		}
	}

	if options.Unlock {
		colorterm.None("Unlocking secrets")

		for _, f := range files {
			err := decryptFile(f, key, options.Dry, !options.Force)
			if err != nil {
				colorterm.Error(f, "unlock error:", err)
			}
		}
	}

	if options.Wait {
		duration := time.Duration(options.Minutes)*time.Minute + time.Duration(options.Seconds)*time.Second

		colorterm.Nonef("Locking secrets up in %s", duration)

		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		select {
		case <-time.After(duration):
			break
		case <-ctx.Done():
			break
		}

		colorterm.None("Done waiting! locking secrets up again")

		for _, f := range files {
			err := encryptFile(f, key, options.Dry, !options.Force)
			if err != nil {
				colorterm.Error(f, "lock error:", err)
			}
		}
	}

}

func generateRandomKey(length int) (string, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func encryptFile(filename string, key []byte, dry bool, checkHash bool) error {
	plaintext, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	hashArr := sha256.Sum256(plaintext)

	textHash := []byte(hex.EncodeToString(hashArr[:]))

	if checkHash {
		hash, err := os.ReadFile(filename + hashFileExtension)
		if err == nil {
			if bytes.Equal(hash, textHash[:]) {
				colorterm.Info(filename, "is unchanged")
				if !dry {
					err = os.Remove(filename)
					if err != nil {
						return err
					}
				}
				return nil
			}
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	if dry {
		return nil
	}

	hextext := make([]byte, hex.EncodedLen(len(ciphertext)))
	hex.Encode(hextext, ciphertext)

	err = os.WriteFile(filename+encryptedFileExtension, chunkSplit(hextext, 64), 0600)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename+hashFileExtension, textHash, 0600)
	if err != nil {
		return err
	}

	colorterm.Success(filename, "=>", filename+encryptedFileExtension, "+", filename+hashFileExtension)

	err = os.Remove(filename)
	if err != nil {
		return err
	}

	return nil
}

func decryptFile(filename string, key []byte, dry bool, checkHash bool) error {
	hextext, err := os.ReadFile(filename + encryptedFileExtension)
	if err != nil {
		return err
	}

	hextext = chunkJoin(hextext)

	ciphertext := make([]byte, hex.DecodedLen(len(hextext)))
	_, err = hex.Decode(ciphertext, hextext)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// check that the hash of the plaintext is the same as the hash stored in file
	if checkHash {
		hash, err := os.ReadFile(filename + hashFileExtension)
		if err != nil {
			return err
		}
		hashArr := sha256.Sum256(plaintext)
		textHash := []byte(hex.EncodeToString(hashArr[:]))
		if !bytes.Equal(hash, textHash) {
			return fmt.Errorf("local file has unsaved changes, aborting. Use -f or --force to override local changes")
		}
	}

	if dry {
		return nil
	}

	err = os.WriteFile(filename, plaintext, 0600)
	if err != nil {
		return err
	}

	colorterm.Success(filename+encryptedFileExtension, "=>", filename)

	return nil
}

func chunkSplit(text []byte, size int) []byte {
	var res []byte
	buf := bytes.NewBuffer(text)
	for {
		chunk := make([]byte, size)
		read, err := buf.Read(chunk)
		if err != nil {
			break
		}
		res = append(res, chunk[0:read]...)
		res = append(res, '\n')
	}
	return res
}

func chunkJoin(text []byte) []byte {
	return bytes.ReplaceAll(text, []byte("\n"), []byte(""))
}
