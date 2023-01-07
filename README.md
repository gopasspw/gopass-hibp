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

If you want to use the offline mode (`dump`) you need to obtain a HIBP dump (SHA1, ordered by hash).
You can use one of the [official sources](https://haveibeenpwned.com/Passwords) but they haven't been
updated in a while and it [seems](https://www.troyhunt.com/downloading-pwned-passwords-hashes-with-the-hibp-downloader/) like they won't receive further updates.

Instead prefer the built-in downloader. It does use the same approach as the official .NET tool.

```bash
gopass-hibp download --output /some/folder/with/40G/dump.txt.gz
```

The data will be downloaded into a million chunks first and then assembled to a large file later.
The output file will be around 18GB in size. During assembly of the chunks it will use twice that space for a short time.
