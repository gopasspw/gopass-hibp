// Package dump implements an haveibeenpwned.com dump scanner. It is designed
// to operate on HIBP SHA-1 dumps which are ordered by hash. It will work with
// dumps ordered by prevalence, too. But processing those will take much, much
// longer.
//
// Unfortunately these dumps need to be unpacked before use, since there is no
// 7z implementation for Go at the time of this writing.
package dump

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/gopasspw/gopass/pkg/debug"
	"github.com/gopasspw/gopass/pkg/fsutil"
	"github.com/kjk/lzmadec"
)

// Scanner is a HIBP dump scanner.
type Scanner struct {
	dumps []string
}

// New creates a new scanner. Provide a list of filenames to HIBP SHA-1 dumps.
// Those should be ordered by hash or lookups will take forever.
func New(dumps ...string) (*Scanner, error) {
	ok := make([]string, 0, len(dumps))
	for _, dump := range dumps {
		if !fsutil.IsFile(dump) {
			continue
		}
		ok = append(ok, dump)
	}
	if len(ok) < 1 {
		return nil, fmt.Errorf("no valid dumps given")
	}

	return &Scanner{
		dumps: ok,
	}, nil
}

// LookupBatch takes a slice SHA1 hashes and matches them against
// the provided dumps.
func (s *Scanner) LookupBatch(ctx context.Context, in []string) []string {
	if len(in) < 1 {
		return nil
	}

	sort.Strings(in)
	for i, hash := range in {
		in[i] = strings.ToUpper(hash)
	}

	out := make([]string, 0, len(in))
	results := make(chan string, len(in))
	done := make(chan struct{}, len(s.dumps))

	for _, fn := range s.dumps {
		go s.scanFile(ctx, fn, in, results, done)
	}

	go func() {
		for result := range results {
			out = append(out, result)
		}
		done <- struct{}{}
	}()

	for range s.dumps {
		<-done
	}
	close(results)
	<-done

	return out
}

func (s *Scanner) scanFile(ctx context.Context, fn string, in []string, results chan string, done chan struct{}) {
	defer func() {
		done <- struct{}{}
	}()

	if isSorted(fn) {
		debug.Log("file %s appears to be sorted", fn)
		s.scanSortedFile(ctx, fn, in, results)

		return
	}
	debug.Log("file %s is not sorted", fn)
	s.scanUnsortedFile(ctx, fn, in, results)
}

func isSorted(fn string) bool {
	var rdr io.Reader
	fh, err := os.Open(fn)
	if err != nil {
		return false
	}
	defer func() {
		_ = fh.Close()
	}()

	switch {
	case strings.HasSuffix(fn, ".gz"):
		gzr, err := gzip.NewReader(fh)
		if err != nil {
			return false
		}
		defer func() {
			_ = gzr.Close()
		}()
		rdr = gzr
	case strings.HasSuffix(fn, ".7z"):
		arc, err := lzmadec.NewArchive(fn)
		if err != nil {
			return false
		}
		if len(arc.Entries) < 1 {
			return false
		}
		rzr, err := arc.GetFileReader(arc.Entries[0].Path)
		if err != nil {
			return false
		}
		defer func() {
			_ = rzr.Close()
		}()
		rdr = rzr
	default:
		rdr = fh
	}

	lineNo := 0
	lastLine := ""
	scanner := bufio.NewScanner(rdr)
	for scanner.Scan() {
		lineNo++
		if lineNo > 100 {
			return true
		}

		line := scanner.Text()
		if len(line) > 40 {
			line = line[:40]
		}
		if line < lastLine {
			return false
		}
		lastLine = line
	}

	return true
}

func (s *Scanner) scanSortedFile(ctx context.Context, fn string, in []string, results chan string) {
	var rdr io.Reader
	fh, err := os.Open(fn)
	if err != nil {
		fmt.Printf("Failed to open file %s: %s", fn, err)

		return
	}
	defer func() {
		_ = fh.Close()
	}()

	switch {
	case strings.HasSuffix(fn, ".gz"):
		gzr, err := gzip.NewReader(fh)
		if err != nil {
			fmt.Printf("Failed to open the file with gzip %s: %s", fn, err)

			return
		}
		defer func() {
			_ = gzr.Close()
		}()
		rdr = gzr
	case strings.HasSuffix(fn, ".7z"):
		arc, err := lzmadec.NewArchive(fn)
		if err != nil {
			fmt.Printf("Failed to open the file with 7z %s: %s", fn, err)

			return
		}
		if len(arc.Entries) < 1 {
			fmt.Printf("7z archive %s contains no entries", fn)

			return
		}
		rzr, err := arc.GetFileReader(arc.Entries[0].Path)
		if err != nil {
			fmt.Printf("Failed open %s in %s for reading: %s", arc.Entries[0].Path, fn, err)

			return
		}
		defer func() {
			_ = rzr.Close()
		}()
		rdr = rzr
	default:
		rdr = fh
	}

	debug.Log("Checking file %s ...\n", fn)

	// index in input (sorted SHA sums)
	i := 0
	lineNo := 0
	numMatches := 0
	scanner := bufio.NewScanner(rdr)
SCAN:
	for scanner.Scan() {
		// check for context cancelation
		select {
		case <-ctx.Done():
			break SCAN
		default:
		}

		lineNo++
		if in == nil {
			results <- strings.TrimSpace(scanner.Text())

			continue
		}

		if i >= len(in) {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		hash := line[:40]

		if hash == in[i] {
			results <- hash
			debug.Log("[%s] MATCH at line %d: %s", fn, lineNo, hash)
			numMatches++
			// advance to next sha sum from store and next line in file
			i++

			continue
		}
		// advance in sha sums from store until we've reached the position in
		// the file
		for i < len(in) && line > in[i] {
			i++
		}
	}

	debug.Log("Finished checking file %s", fn)
}

func (s *Scanner) scanUnsortedFile(ctx context.Context, fn string, in []string, results chan string) {
	var rdr io.Reader
	fh, err := os.Open(fn)
	if err != nil {
		fmt.Printf("Failed to open file %s: %s", fn, err)

		return
	}
	defer func() {
		_ = fh.Close()
	}()

	switch {
	case strings.HasSuffix(fn, ".gz"):
		gzr, err := gzip.NewReader(fh)
		if err != nil {
			fmt.Printf("Failed to open the file with gzip %s: %s", fn, err)

			return
		}
		defer func() {
			_ = gzr.Close()
		}()
		rdr = gzr
	case strings.HasSuffix(fn, ".7z"):
		arc, err := lzmadec.NewArchive(fn)
		if err != nil {
			fmt.Printf("Failed to open the file with 7z %s: %s", fn, err)

			return
		}
		if len(arc.Entries) < 1 {
			fmt.Printf("7z archive %s contains no entries", fn)

			return
		}
		rzr, err := arc.GetFileReader(arc.Entries[0].Path)
		if err != nil {
			fmt.Printf("Failed open %s in %s for reading: %s", arc.Entries[0].Path, fn, err)

			return
		}
		defer func() {
			_ = rzr.Close()
		}()
		rdr = rzr
	default:
		rdr = fh
	}

	lines := make(chan string, 1024)
	worker := runtime.NumCPU()
	done := make(chan struct{}, worker)
	for i := range worker {
		debug.Log("[%d] Starting matcher ...", i)
		go s.matcher(ctx, in, lines, results, done)
	}

	debug.Log("Checking file %s ...\n", fn)
	scanner := bufio.NewScanner(rdr)
SCAN:
	for scanner.Scan() {
		// check for context cancelation
		select {
		case <-ctx.Done():
			break SCAN
		default:
		}

		lines <- scanner.Text()
	}
	close(lines)

	for range worker {
		<-done
	}

	debug.Log("Finished checking file %s", fn)
}

func (s *Scanner) matcher(ctx context.Context, in []string, lines chan string, results chan string, done chan struct{}) {
	defer func() {
		done <- struct{}{}
	}()

LINE:
	for line := range lines {
		// check for context cancelation
		select {
		case <-ctx.Done():
			break LINE
		default:
		}

		line := strings.ToUpper(strings.TrimSpace(line))
		hash := line[:40]
		for _, candidate := range in {
			if candidate == hash {
				results <- hash

				continue LINE
			}
		}
	}
}
