package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, content, 0600))
}

func TestChunkSplit_BoundaryCases(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		size int
	}{
		{"empty", []byte{}, 64},
		{"single short chunk", []byte("abc"), 64},
		{"exact one chunk", bytes.Repeat([]byte("a"), 64), 64},
		{"ragged final chunk", bytes.Repeat([]byte("b"), 100), 64},
		{"multi full chunk", bytes.Repeat([]byte("c"), 192), 64},
		{"size 1", []byte("xyz"), 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := chunkSplit(tc.in, tc.size)
			for _, line := range bytes.Split(got, []byte("\n")) {
				assert.LessOrEqual(t, len(line), tc.size, "chunk longer than size")
			}
			assert.True(t, bytes.Equal(tc.in, chunkJoin(got)), "chunkJoin must invert chunkSplit; got=%q want=%q", chunkJoin(got), tc.in)
		})
	}
}

func TestChunkJoin_RemovesNewlines(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want []byte
	}{
		{"no newlines", []byte("abcdef"), []byte("abcdef")},
		{"trailing newline", []byte("abc\n"), []byte("abc")},
		{"interleaved", []byte("a\nb\nc\n"), []byte("abc")},
		{"only newlines", []byte("\n\n\n"), []byte("")},
		{"empty", []byte{}, []byte{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, bytes.Equal(tc.want, chunkJoin(tc.in)), "got=%q want=%q", chunkJoin(tc.in), tc.want)
		})
	}
}

func TestEncryptFile_WritesEncAndHashAndRemovesPlaintext(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	plaintext := []byte("supersecret=value\n")
	writeFile(t, "secret.txt", plaintext)

	key := randomKey(t)
	require.NoError(t, encryptFile("secret.txt", key, false, false))

	encBytes, err := os.ReadFile("secret.txt.enc")
	require.NoError(t, err)
	assert.NotEmpty(t, encBytes)

	joined := chunkJoin(encBytes)
	decoded := make([]byte, hex.DecodedLen(len(joined)))
	_, err = hex.Decode(decoded, joined)
	assert.NoError(t, err, "enc file must be hex-decodable after chunkJoin")

	hashBytes, err := os.ReadFile("secret.txt.sha256")
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(hashBytes, []byte("hmac-sha256:")), "hmac fingerprint format expected; got %q", hashBytes)
	assert.Len(t, hashBytes, len("hmac-sha256:")+64, "hmac fingerprint is prefix + 64 hex chars")
	_, err = hex.DecodeString(string(hashBytes[len("hmac-sha256:"):]))
	assert.NoError(t, err, "hmac fingerprint payload must be valid hex")

	_, err = os.Stat("secret.txt")
	assert.True(t, os.IsNotExist(err), "plaintext should be removed after non-dry encrypt")
}

func TestEncryptFile_SkipsWhenHashMatches(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	plaintext := []byte("unchanging content")
	writeFile(t, "secret.txt", plaintext)

	key := randomKey(t)
	require.NoError(t, encryptFile("secret.txt", key, false, true))

	encBefore, err := os.ReadFile("secret.txt.enc")
	require.NoError(t, err)
	hashBefore, err := os.ReadFile("secret.txt.sha256")
	require.NoError(t, err)

	writeFile(t, "secret.txt", plaintext)

	require.NoError(t, encryptFile("secret.txt", key, false, true))

	encAfter, err := os.ReadFile("secret.txt.enc")
	require.NoError(t, err)
	hashAfter, err := os.ReadFile("secret.txt.sha256")
	require.NoError(t, err)

	assert.Equal(t, encBefore, encAfter, "unchanged plaintext must NOT trigger re-encryption (fresh nonce would change bytes)")
	assert.Equal(t, hashBefore, hashAfter, "hash file must be untouched on the unchanged path")

	_, err = os.Stat("secret.txt")
	assert.True(t, os.IsNotExist(err), "plaintext should still be removed on the unchanged path")
}

func TestEncryptFile_DryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	plaintext := []byte("dry run content")
	writeFile(t, "secret.txt", plaintext)

	key := randomKey(t)
	require.NoError(t, encryptFile("secret.txt", key, true, false))

	_, err := os.Stat("secret.txt.enc")
	assert.True(t, os.IsNotExist(err), "no .enc file in dry mode")

	_, err = os.Stat("secret.txt.sha256")
	assert.True(t, os.IsNotExist(err), "no .sha256 file in dry mode")

	got, err := os.ReadFile("secret.txt")
	require.NoError(t, err, "plaintext must remain in dry mode")
	assert.Equal(t, plaintext, got)
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"small ascii", []byte("hello world\n")},
		{"binary with NULs", []byte{0x00, 0x01, 0x02, 0xff, 0x00, 0x80}},
		{"about 1MB", bytes.Repeat([]byte("x"), 1024*1024)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)

			path := "secret.txt"
			writeFile(t, path, tc.plaintext)

			key := randomKey(t)
			require.NoError(t, encryptFile(path, key, false, false))
			require.NoError(t, decryptFile(path, key, false, false))

			got, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, tc.plaintext, got)

			_, err = os.Stat(path + ".enc")
			assert.NoError(t, err, ".enc must remain after decrypt")
		})
	}
}

// decryptFile's hash check (main.go:270) hashes the *decrypted* plaintext, not
// the on-disk plaintext, so it does NOT detect local modifications despite the
// error message's wording. What it actually catches is a stored hash that does
// not match the .enc payload — i.e. tamper detection on the .sha256 sidecar.
// See README/ASSESSMENT note from PR 1 for follow-up.
func TestDecryptFile_RejectsTamperedHashFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	writeFile(t, "secret.txt", []byte("original\n"))

	key := randomKey(t)
	require.NoError(t, encryptFile("secret.txt", key, false, false))

	tampered := bytes.Repeat([]byte("0"), 64)
	writeFile(t, "secret.txt.sha256", tampered)

	err := decryptFile("secret.txt", key, false, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "local file has unsaved changes",
		"current error message is misleading; PR 2 should consider rephrasing")

	_, statErr := os.Stat("secret.txt")
	assert.True(t, os.IsNotExist(statErr), "decrypt must not write plaintext when hash check fails")
}

func TestDecryptFile_HashCheckIgnoresLocalModifications(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	writeFile(t, "secret.txt", []byte("original\n"))

	key := randomKey(t)
	require.NoError(t, encryptFile("secret.txt", key, false, false))

	modified := []byte("modified locally\n")
	writeFile(t, "secret.txt", modified)

	require.NoError(t, decryptFile("secret.txt", key, false, true),
		"decryptFile hashes the decrypted plaintext, not the on-disk file, so a modified local file does not trigger the check")

	got, err := os.ReadFile("secret.txt")
	require.NoError(t, err)
	assert.Equal(t, []byte("original\n"), got, "decrypt overwrites the local file regardless of its prior content")
}

func TestDecryptFile_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	original := []byte("original\n")
	writeFile(t, "secret.txt", original)

	key := randomKey(t)
	require.NoError(t, encryptFile("secret.txt", key, false, false))

	modified := []byte("modified locally\n")
	writeFile(t, "secret.txt", modified)

	require.NoError(t, decryptFile("secret.txt", key, false, false))

	got, err := os.ReadFile("secret.txt")
	require.NoError(t, err)
	assert.Equal(t, original, got, "force decrypt must restore original plaintext")
}

func TestDecryptFile_DryRunDoesNotWritePlaintext(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	plaintext := []byte("dry decrypt content")
	writeFile(t, "secret.txt", plaintext)

	key := randomKey(t)
	require.NoError(t, encryptFile("secret.txt", key, false, false))

	require.NoError(t, decryptFile("secret.txt", key, true, false))

	_, err := os.Stat("secret.txt")
	assert.True(t, os.IsNotExist(err), "dry decrypt must not recreate plaintext")
}

func TestDecryptFile_WrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	writeFile(t, "secret.txt", []byte("payload"))

	keyA := randomKey(t)
	require.NoError(t, encryptFile("secret.txt", keyA, false, false))

	keyB := randomKey(t)
	err := decryptFile("secret.txt", keyB, false, false)
	require.Error(t, err, "AES-GCM must reject wrong key")
}

func TestDecryptFile_MissingHashFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	writeFile(t, "secret.txt", []byte("payload"))

	key := randomKey(t)
	require.NoError(t, encryptFile("secret.txt", key, false, false))

	require.NoError(t, os.Remove("secret.txt.sha256"))

	err := decryptFile("secret.txt", key, false, true)
	require.Error(t, err, "missing .sha256 must fail when checkHash is true")
	assert.Contains(t, err.Error(), "decrypt: read hash file:", "missing .sha256 should be wrapped per code-quality convention")

	if !strings.Contains(err.Error(), filepath.Base("secret.txt.sha256")) {
		t.Logf("note: error did not name the hash file: %v", err)
	}
}

func TestPlaintextFingerprint_Deterministic(t *testing.T) {
	key := randomKey(t)
	pt := []byte("deterministic content")
	a := plaintextFingerprint(pt, key)
	b := plaintextFingerprint(pt, key)
	assert.Equal(t, a, b, "same key + plaintext must yield same fingerprint")
	assert.True(t, bytes.HasPrefix(a, []byte("hmac-sha256:")), "fingerprint must carry hmac-sha256: prefix")
	assert.Len(t, a, len("hmac-sha256:")+64)
}

func TestPlaintextFingerprint_DiffersAcrossKeys(t *testing.T) {
	pt := []byte("same plaintext")
	a := plaintextFingerprint(pt, randomKey(t))
	b := plaintextFingerprint(pt, randomKey(t))
	assert.NotEqual(t, a, b, "different keys must produce different fingerprints (non-leaking property)")
}

func TestDeriveHashKey_DomainSeparated(t *testing.T) {
	key := randomKey(t)
	derived := deriveHashKey(key)
	assert.Len(t, derived, 32, "HMAC-SHA256 output is 32 bytes")
	assert.NotEqual(t, key, derived, "derived hash key must differ from master key")
}

func TestFingerprintMatches_AcceptsLegacySHA256(t *testing.T) {
	pt := []byte("legacy plaintext")
	key := randomKey(t)

	h := sha256.Sum256(pt)
	legacy := []byte(hex.EncodeToString(h[:]))

	assert.True(t, fingerprintMatches(legacy, pt, key),
		"legacy unprefixed SHA256 must still verify so existing .sha256 files keep working")

	assert.False(t, fingerprintMatches(legacy, []byte("different plaintext"), key),
		"legacy verify must reject mismatched plaintext")
}

func TestFingerprintMatches_RejectsModifiedHMAC(t *testing.T) {
	pt := []byte("hmac plaintext")
	key := randomKey(t)
	stored := plaintextFingerprint(pt, key)
	assert.True(t, fingerprintMatches(stored, pt, key))
	assert.False(t, fingerprintMatches(stored, []byte("modified"), key))
}

func TestEncryptFile_UpgradesLegacyHashOnUnchangedPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	plaintext := []byte("legacy migration content")
	writeFile(t, "secret.txt", plaintext)

	key := randomKey(t)
	require.NoError(t, encryptFile("secret.txt", key, false, false))

	encBefore, err := os.ReadFile("secret.txt.enc")
	require.NoError(t, err)

	h := sha256.Sum256(plaintext)
	legacy := []byte(hex.EncodeToString(h[:]))
	writeFile(t, "secret.txt.sha256", legacy)

	writeFile(t, "secret.txt", plaintext)
	require.NoError(t, encryptFile("secret.txt", key, false, true))

	upgraded, err := os.ReadFile("secret.txt.sha256")
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(upgraded, []byte("hmac-sha256:")),
		"legacy hash should be upgraded to hmac format on the unchanged path; got %q", upgraded)
	assert.Equal(t, plaintextFingerprint(plaintext, key), upgraded,
		"upgraded hash must equal the hmac fingerprint of the same plaintext+key")

	encAfter, err := os.ReadFile("secret.txt.enc")
	require.NoError(t, err)
	assert.Equal(t, encBefore, encAfter, "unchanged path must NOT re-encrypt the .enc file even when upgrading the hash")
}

func TestDecryptFile_AcceptsLegacyHash(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	plaintext := []byte("legacy decrypt content")
	writeFile(t, "secret.txt", plaintext)

	key := randomKey(t)
	require.NoError(t, encryptFile("secret.txt", key, false, false))

	h := sha256.Sum256(plaintext)
	legacy := []byte(hex.EncodeToString(h[:]))
	writeFile(t, "secret.txt.sha256", legacy)

	require.NoError(t, decryptFile("secret.txt", key, false, true),
		"decrypt must accept a legacy SHA256 .sha256 file paired with a matching .enc")

	got, err := os.ReadFile("secret.txt")
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestDeriveKeyFromPassphrase_Length(t *testing.T) {
	key, err := deriveKeyFromPassphrase("correct horse battery staple")
	require.NoError(t, err)
	assert.Len(t, key, 32, "derived key must be 32 bytes for AES-256")
	_, err = aes.NewCipher(key)
	assert.NoError(t, err, "derived key must be accepted by aes.NewCipher")
}

func TestDeriveKeyFromPassphrase_Deterministic(t *testing.T) {
	a, err := deriveKeyFromPassphrase("a memorable passphrase")
	require.NoError(t, err)
	b, err := deriveKeyFromPassphrase("a memorable passphrase")
	require.NoError(t, err)
	assert.Equal(t, a, b, "same passphrase must derive the same key (fixed-salt reproducibility)")
}

func TestDeriveKeyFromPassphrase_DiffersAcrossPassphrases(t *testing.T) {
	a, err := deriveKeyFromPassphrase("passphrase one is here")
	require.NoError(t, err)
	b, err := deriveKeyFromPassphrase("passphrase two is here")
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "different passphrases must derive different keys")
}

func TestDeriveKeyFromPassphrase_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	plaintext := []byte("passphrase round trip\n")
	writeFile(t, "secret.txt", plaintext)

	key, err := deriveKeyFromPassphrase("a friendly multi-word passphrase")
	require.NoError(t, err)

	require.NoError(t, encryptFile("secret.txt", key, false, false))
	require.NoError(t, decryptFile("secret.txt", key, false, false))

	got, err := os.ReadFile("secret.txt")
	require.NoError(t, err)
	assert.Equal(t, plaintext, got, "a passphrase-derived key must round-trip encrypt/decrypt")
}

func TestValidatePassphrase(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		wantErr    bool
	}{
		{"multi-word phrase", "correct horse battery staple", false},
		{"hyphenated phrase", "Reef-Mango-Lantern-92", false},
		{"exactly min length", "abcdef-12345", false}, // 12 distinct-enough chars
		{"empty", "", true},
		{"whitespace only collapses to empty", "          ", true},
		{"too short", "short1!", true},
		{"one under min", "abcdefghijk", true}, // 11 chars
		{"all identical at min length", "aaaaaaaaaaaa", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// readPassphrase trims before validating; mirror that here so the
			// whitespace-only case reflects real behaviour.
			err := validatePassphrase(strings.TrimSpace(tc.passphrase))
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidatePassphrase_TooShortMentionsMinimum(t *testing.T) {
	err := validatePassphrase("short")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 12 characters",
		"too-short error should state the minimum length")
}
