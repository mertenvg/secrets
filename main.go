package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/mertenvg/secrets/pkg/colorterm"
)

var (
	// App metadata
	name    = "secrets"
	version = "dev"

	// App configuration options
	options struct {
		Version    bool   `long:"version" short:"v" description:"Display service name and version, then exit"`
		Key        string `long:"key" short:"k" env:"SECRETS_KEY" default:"" description:"Optional secrets key (if empty, one will be provided)"`
		Passphrase bool   `long:"passphrase" short:"p" description:"Prompt (no echo) for a passphrase instead of using a key; takes precedence over --key/SECRETS_KEY"`
		Lock       bool   `long:"lock" short:"l" description:"Move secrets to encrypted files"`
		Unlock     bool   `long:"unlock" short:"u" description:"Extract secrets from encrypted files"`
		Force      bool   `long:"force" short:"f" description:"Forgo secrets hash checks and overwrite changes in unencrypted files"`
		Dry        bool   `long:"dry" short:"d" description:"Dry run mode, lock or unlock without updating files"`
		Wait       bool   `long:"wait" short:"w" description:"The number of minutes to wait before locking and exiting"`
		Minutes    int    `long:"minutes" short:"m" env:"SECRETS_WAIT_MINUTES" default:"10" description:"The number of minutes to wait before locking and exiting"`
		Seconds    int    `long:"seconds" short:"s" env:"SECRETS_WAIT_SECONDS" default:"0" description:"The number of seconds to wait before locking and exiting, may be used in conjunction with minutes"`
	}
)

const (
	encryptedFileExtension = ".enc"
	hashFileExtension      = ".sha256"
	hashFormatPrefix       = "hmac-sha256:"
	hashKDFContext         = "secrets:hmac-v1"

	// passphraseKDFSalt is a FIXED application salt. The tool stores no
	// key-derivation metadata, so a fixed salt is required for the same
	// passphrase to reproducibly derive the same key across machines and
	// invocations. This mirrors the fixed hashKDFContext domain separator.
	// Tradeoff: the same passphrase derives the same key globally, with no
	// rainbow-table protection; the high iteration count plus a strong
	// passphrase are the defense. This value is a frozen on-disk contract —
	// changing it makes previously-locked files undecryptable.
	passphraseKDFSalt = "secrets:pbkdf2-v1"
	// passphraseKDFIterations is the PBKDF2 work factor (OWASP recommendation
	// for PBKDF2-HMAC-SHA256). Like the salt, this is a frozen contract.
	passphraseKDFIterations = 600_000
	// passphraseMinLength enforces a length-first policy (NIST SP 800-63B):
	// length, not character-class composition, is the meaningful defense
	// against offline brute-force, and it keeps passphrases human-friendly.
	passphraseMinLength = 12
)

type Conf struct {
	Files []string `yaml:"files"`
}

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	// VCS settings are embedded for local builds but absent when installed via
	// `go install pkg@version` — only trust Main.Version in the latter case.
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return
		}
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		version = v
	}
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

	// A passphrase, if requested, takes precedence over any configured key. We
	// derive a 32-byte key from it and store the hex back into options.Key so the
	// existing decode path below is unchanged and the auto-generate branch is
	// skipped.
	if options.Passphrase {
		confirm := options.Lock || options.Wait // re-enter only when encryption will occur
		passphrase, err := readPassphrase(confirm)
		if err != nil {
			colorterm.Error("Failed to read passphrase:", err)
			os.Exit(1)
		}
		if options.Key != "" {
			colorterm.Warning("A passphrase was provided; ignoring the configured key.")
		}
		derived, err := deriveKeyFromPassphrase(passphrase)
		if err != nil {
			colorterm.Error("Failed to derive key from passphrase:", err)
			os.Exit(1)
		}
		options.Key = hex.EncodeToString(derived)
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

// deriveKeyFromPassphrase derives a 32-byte AES key from a human-friendly
// passphrase using PBKDF2-HMAC-SHA256 with a fixed application salt.
func deriveKeyFromPassphrase(passphrase string) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, []byte(passphraseKDFSalt), passphraseKDFIterations, 32)
}

// validatePassphrase enforces a length-first policy (NIST SP 800-63B): a minimum
// length with no character-class requirements. Passphrase length, not composition
// complexity, is the meaningful defense against offline brute-force, and it keeps
// passphrases human-friendly.
func validatePassphrase(passphrase string) error {
	if n := len([]rune(passphrase)); n < passphraseMinLength {
		return fmt.Errorf("passphrase must be at least %d characters (got %d)", passphraseMinLength, n)
	}
	if isAllSameRune(passphrase) {
		return fmt.Errorf("passphrase must not be a single repeated character")
	}
	return nil
}

// isAllSameRune reports whether s consists entirely of one repeated character.
func isAllSameRune(s string) bool {
	runes := []rune(s)
	if len(runes) == 0 {
		return false
	}
	for _, r := range runes[1:] {
		if r != runes[0] {
			return false
		}
	}
	return true
}

// readPassphrase prompts for a passphrase without echoing it, validates it, and —
// when confirm is true (locking) — prompts a second time and requires a match.
func readPassphrase(confirm bool) (string, error) {
	fmt.Fprintf(os.Stderr, "Enter passphrase (min %d chars; a multi-word phrase works well): ", passphraseMinLength)
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	passphrase := strings.TrimSpace(string(first))
	if err := validatePassphrase(passphrase); err != nil {
		return "", err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if passphrase != strings.TrimSpace(string(second)) {
			return "", fmt.Errorf("passphrases do not match")
		}
	}
	return passphrase, nil
}

// deriveHashKey derives a domain-separated MAC key from the master AES key
// using a one-block HMAC-based KDF, so the same master key is not reused
// directly across AES encryption and plaintext fingerprinting.
func deriveHashKey(masterKey []byte) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte(hashKDFContext))
	return mac.Sum(nil)
}

// plaintextFingerprint returns the on-disk hash file contents for plaintext:
// "hmac-sha256:" + hex(HMAC-SHA256(deriveHashKey(masterKey), plaintext)).
func plaintextFingerprint(plaintext, masterKey []byte) []byte {
	mac := hmac.New(sha256.New, deriveHashKey(masterKey))
	mac.Write(plaintext)
	sum := mac.Sum(nil)
	out := make([]byte, len(hashFormatPrefix)+hex.EncodedLen(len(sum)))
	copy(out, hashFormatPrefix)
	hex.Encode(out[len(hashFormatPrefix):], sum)
	return out
}

// fingerprintMatches verifies whether stored matches plaintext. It accepts both
// the "hmac-sha256:" format and the legacy unprefixed SHA256(plaintext) hex
// written by older versions, so existing .sha256 files keep verifying until
// the next lock rewrites them.
func fingerprintMatches(stored, plaintext, masterKey []byte) bool {
	if bytes.HasPrefix(stored, []byte(hashFormatPrefix)) {
		return hmac.Equal(stored, plaintextFingerprint(plaintext, masterKey))
	}
	legacy := sha256.Sum256(plaintext)
	legacyHex := []byte(hex.EncodeToString(legacy[:]))
	return hmac.Equal(stored, legacyHex)
}

func encryptFile(filename string, key []byte, dry bool, checkHash bool) error {
	plaintext, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	textHash := plaintextFingerprint(plaintext, key)

	if checkHash {
		hash, err := os.ReadFile(filename + hashFileExtension)
		if err == nil {
			if fingerprintMatches(hash, plaintext, key) {
				colorterm.Info(filename, "is unchanged")
				if !dry {
					if !bytes.HasPrefix(hash, []byte(hashFormatPrefix)) {
						if err := os.WriteFile(filename+hashFileExtension, textHash, 0600); err != nil {
							return err
						}
					}
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

	hextext := make([]byte, hex.EncodedLen(len(ciphertext)))
	hex.Encode(hextext, ciphertext)

	if !dry {
		err = os.WriteFile(filename+encryptedFileExtension, chunkSplit(hextext, 64), 0600)
		if err != nil {
			return err
		}

		err = os.WriteFile(filename+hashFileExtension, textHash, 0600)
		if err != nil {
			return err
		}
	}

	colorterm.Success(filename, "=>", filename+encryptedFileExtension, "+", filename+hashFileExtension)

	if !dry {
		err = os.Remove(filename)
		if err != nil {
			return err
		}
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

	if checkHash {
		hash, err := os.ReadFile(filename + hashFileExtension)
		if err != nil {
			return fmt.Errorf("decrypt: read hash file: %w", err)
		}
		if !fingerprintMatches(hash, plaintext, key) {
			return fmt.Errorf("local file has unsaved changes, aborting. Use -f or --force to override local changes")
		}
	}

	if !dry {
		err = os.WriteFile(filename, plaintext, 0600)
		if err != nil {
			return err
		}
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
