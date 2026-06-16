# Secrets
A utility to lock your secrets and store them securely using AES-GCM encryption in your repository, and unlock them when you need them.

## Install
```shell
go install github.com/mertenvg/secrets@latest
```

## Usage
You may specify any number of files to lock and unlock along with each command. These will be combined with any files listed in a secrets.yaml configuration file.

Locking and unlocking files requires a key, specified by a `-k` [`--key`] argument or a `SECRETS_KEY` environment variable. Don't worry if you don't have one yet.

When using this tool for the first time on a project, if no key is provided, one will be generated for you. Please make sure you store the key securely so you can unlock your files again when you need it.

### Using a passphrase instead of a key

If you'd rather use a human-friendly passphrase than a hex key, add the `-p` [`--passphrase`] flag. The tool then prompts for the passphrase interactively with **no echo**, so it never appears in your shell history, environment, or any file. The passphrase is stretched into the encryption key, and **takes precedence over** any `-k`/`SECRETS_KEY`. When locking, you'll be asked to re-enter it to confirm.

A passphrase must be **at least 12 characters** — there are no uppercase/number/special-character requirements, so a memorable multi-word phrase like `correct horse battery staple` is both strong and easy to type. Choose a long passphrase: length is the main defense, because the same passphrase always derives the same key (so you can decrypt anywhere) but the encrypted files offer no rainbow-table protection.

```shell
# export your secret key to your env if you have one
export SECRETS_KEY="<your-secret-key>"
# or add -k to your secrets commands like this
secrets -k "<your-secret-key>" ...

# or use a passphrase — you'll be prompted for it (and asked to confirm when locking)
secrets -p -l file-one file-two   # prompts twice (enter + confirm), then locks
secrets -p -u file-one file-two   # prompts once, then unlocks

# show help
secrets -h

# lock some files
secrets -l file-one file-two file-n

# unlock some files
secrets -u file-one file-two file-n

# lock and unlock to restore clear text secrets files
secrets -lu

# unlock files and wait before locking again (default is 10 minutes unless terminated manually, but can be overridden with -m [--minutes=#] and -s [--seconds=#] if desired)
secrets -u -w ...
secrets -u -w -m 5 -s 30

# dry run
secrets -l -d

# force file updates when there are conflicts
secrets -l -f
```

## Configuration
Create a `secrets.yaml` file in the root of your project and include a list of the files you wish to have locked
```yaml
files:
  - example.secret.txt
```
