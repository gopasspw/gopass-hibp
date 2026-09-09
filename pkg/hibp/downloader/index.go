package downloader

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/gopasspw/gopass/pkg/fsutil"
)

// Index is an ETag based index of downloaded hash ranges. It is used to
// avoid re-downloading unchanged ranges. It is safe for concurrent use.
type Index struct {
	mu    sync.RWMutex
	etags map[string]string
}

// LoadIndex loads an index from the given path. If force is set or the file
// does not exist an empty index is returned.
func LoadIndex(path string, force bool) (*Index, error) {
	idx := &Index{
		etags: make(map[string]string, NumRanges),
	}
	if force || !fsutil.IsFile(path) {
		return idx, nil
	}

	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close() //nolint:errcheck

	lineNo := 0
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		prefix, etag, found := strings.Cut(line, "\t")
		if !found || len(prefix) != 5 || strings.Contains(etag, "\t") {
			return nil, fmt.Errorf("index file %s contains an invalid entry on line %d", path, lineNo)
		}
		if !isHashRange(prefix) || etag == "" {
			return nil, fmt.Errorf("index file %s contains an invalid entry on line %d", path, lineNo)
		}
		if _, found := idx.etags[prefix]; found {
			return nil, fmt.Errorf("index file %s contains a duplicate prefix on line %d", path, lineNo)
		}

		idx.etags[prefix] = etag
	}

	return idx, scanner.Err()
}

// Count returns the number of entries in the index.
func (i *Index) Count() int {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return len(i.etags)
}

// Get returns the ETag for the given prefix, if any.
func (i *Index) Get(prefix string) string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return i.etags[prefix]
}

// Set stores the ETag for the given prefix.
func (i *Index) Set(prefix, etag string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.etags[prefix] = etag
}

// Remove deletes the given prefix from the index.
func (i *Index) Remove(prefix string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	delete(i.etags, prefix)
}

// Save persists the index to the given path. The index is written to a
// temporary file first and then moved into place to avoid corrupting the
// index on failures.
func (i *Index) Save(path string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(tmp.Name())
	}()

	i.mu.RLock()
	entries := make([]string, 0, len(i.etags))
	for prefix, etag := range i.etags {
		entries = append(entries, prefix+"\t"+etag)
	}
	i.mu.RUnlock()

	sort.Strings(entries)

	buf := &bytes.Buffer{}
	for _, entry := range entries {
		buf.WriteString(entry)
		buf.WriteString("\n")
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()

		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), path)
}

// isHashRange returns true if the given string is a valid hash range prefix,
// i.e. five uppercase hex characters.
func isHashRange(prefix string) bool {
	if len(prefix) != 5 {
		return false
	}
	for _, c := range prefix {
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return false
		}
	}

	return true
}
