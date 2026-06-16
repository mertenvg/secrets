# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Refer to the AI engineering guidelines at https://github.com/mertenvg/my-ai-guidelines/guidelines/ for the full set of rules.

## Overview

A Go CLI tool that encrypts/decrypts secret files using AES-GCM encryption. Files are locked (encrypted) with a hex-encoded 32-byte key and stored as `.enc` files with `.sha256` hash files for change detection.

## Build & Run

```shell
go build -o secrets .
go run .
go install github.com/mertenvg/secrets@latest
```

There are no tests in this project currently.

## Architecture

Single-binary CLI app. All core logic lives in `main.go`:
- Flag parsing via `github.com/jessevdk/go-flags`
- Config loading from `secrets.yaml` (list of files to encrypt/decrypt)
- `encryptFile()` — reads plaintext, AES-GCM encrypts, writes hex-encoded `.enc` file + `.sha256` hash, removes original
- `decryptFile()` — reads `.enc` file, decrypts, verifies hash, writes plaintext
- `chunkSplit`/`chunkJoin` — splits hex ciphertext into 64-char lines for storage
- `deriveKeyFromPassphrase()`/`validatePassphrase()`/`readPassphrase()` — `-p`/`--passphrase` prompts (no echo via `golang.org/x/term`) for a passphrase, validates it (min 12 chars), and derives the 32-byte key via PBKDF2-HMAC-SHA256

`pkg/colorterm/` — colored terminal output utility (package-level functions delegate to a singleton `CT` instance).

## Key Design Details

- Encryption key: 32 bytes, passed as hex string via `-k` flag or `SECRETS_KEY` env var. Auto-generated if not provided.
- Passphrase alternative: `-p`/`--passphrase` (boolean) interactively prompts (no echo) for a passphrase that takes precedence over `-k`/`SECRETS_KEY`. It is stretched into the 32-byte key with PBKDF2-HMAC-SHA256 using a fixed application salt (`passphraseKDFSalt`) and `passphraseKDFIterations` — both are frozen on-disk contracts. Minimum length 12; no character-class rules (length-first, NIST SP 800-63B). Confirmed by re-entry when locking. There is intentionally no env var for the passphrase.
- Encrypted files stored as newline-chunked hex (64 chars per line).
- SHA256 hash files track plaintext state to skip re-encryption of unchanged files and detect local modifications before decryption.
- `-f`/`--force` bypasses hash checks; `-d`/`--dry` prevents file writes; `-w`/`--wait` unlocks then re-locks after a timeout (default 10min).
