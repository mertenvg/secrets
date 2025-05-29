# Secrets
A utility to lock your secrets and store them securely using AES-GCM encryption in your repository, and unlock them when you need them.

## Install
```shell
go install github.com/mertenvg/secrets@latest
```

## Usage
You may specify any number of files to lock and unlock along with each command. These will be combined with any files listed in a secrets.yaml configuration file.

When using this tool for the first time on a project, if no key is provided one will be generated for you. Please make sure you store the key securely so you can unlock your files again when you need them.
```shell
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
