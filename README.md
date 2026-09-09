# gopass-hibp

Gopass haveibeenpwnd.com integration

## Installation

### Fedora

To install gopass-hibp in Fedora you can do:

```bash
sudo dnf install gopass-hibp
```

### From Source

```bash
go install github.com/gopasspw/gopass-hibp@latest
```

## Setup

If you want to use the offline mode you need to obtain a copy of the HIBP hashes first.
The dumps are not available for download from the [official sources](https://haveibeenpwned.com/Passwords) anymore.

Instead use the built-in downloader. It is a Go re-implementation of the
[official .NET downloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)
and downloads all hash ranges from the pwnedpasswords.com range API.

```bash
# download all hash ranges into a directory of individual files
# (an ETag based index makes subsequent runs only download changed ranges)
gopass-hibp download --output /some/folder/with/40G/pwnedpasswords

# or download everything into one large file with full hashes
# (suitable for use with the "dump" command)
gopass-hibp download --single --output /some/folder/with/40G/pwnedpasswords.txt
```

The output will be around 40GB in size. The download itself makes about one million requests,
one per possible hash prefix.

### Legacy dumps

The `dump` and `merge` commands (working on local HIBP dump files) are deprecated and hidden.
They are kept for users that still have local dumps around (possibly manually curated), but they
will be removed in a future release. Only plain text and gzip compressed dumps are supported,
the 7z support was dropped. Use `7z` to extract the dumps and (re-)compress them with `gzip`
if necessary.
