package main

import (
	"bytes"
	"crypto/rand"
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
	assert.Len(t, hashBytes, 64, "current format is 64 hex chars (SHA256(plaintext)); PR 2 changes this")
	_, err = hex.DecodeString(string(hashBytes))
	assert.NoError(t, err, "hash file content must be valid hex")

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

	if !strings.Contains(err.Error(), filepath.Base("secret.txt.sha256")) {
		t.Logf("note: error did not name the hash file: %v", err)
	}
}
