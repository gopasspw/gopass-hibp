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

Instead use the built-in downloader. It uses the same approach as the
[official .NET downloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)
and downloads all hashes from the pwnedpasswords.com range API into a single, gzipped dump
(ordered by hash).

```bash
gopass-hibp download --output /some/folder/with/40G/dump.txt.gz
```

The data will be downloaded into a million chunks first and then assembled to a large file later.
The output file will be around 18GB in size. During assembly of the chunks it will use twice that space for a short time.

### Legacy dumps

The `dump` and `merge` commands (working on local HIBP dump files) are deprecated and hidden.
They are kept for users that still have local dumps around (possibly manually curated), but they
will be removed in a future release. Only plain text and gzip compressed dumps are supported,
the 7z support was dropped. Use `7z` to extract the dumps and (re-)compress them with `gzip`
if necessary.
