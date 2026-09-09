// Package downloader implements a Go re-implementation of the official .NET
// based HaveIBeenPwned PwnedPasswords downloader.
//
// It downloads all 1024*1024 possible five character hash prefixes from the
// pwnedpasswords.com range API and stores them either as individual files in
// a directory or as a single file containing full (40 character) hashes.
//
// In directory mode an ETag based index is maintained so subsequent runs can
// use conditional requests to only download ranges that changed. Every
// downloaded range is verified against its Content-MD5 response header.
//
// See https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader for the
// reference implementation.
package downloader

import (
	"context"
	"crypto/md5"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/debug"
	"github.com/gopasspw/gopass/pkg/fsutil"
	"github.com/gopasspw/gopass/pkg/termio"
)

// BaseURL is the base URL of the pwnedpasswords.com range API.
var BaseURL = "https://api.pwnedpasswords.com/range/"

// NumRanges is the total number of five character hash ranges (16^5).
// It is a variable to allow small test fixtures.
var NumRanges = 1024 * 1024

// Settings configures a download run.
type Settings struct {
	// Output is the output directory, or the output file in single file mode.
	Output string
	// Parallelism is the number of parallel requests. Values < 2 default to
	// eight times the number of CPUs.
	Parallelism int
	// Overwrite existing output files.
	Overwrite bool
	// Single writes all hashes into one file instead of individual files.
	Single bool
	// NTLM fetches NTLM hashes instead of SHA1 hashes.
	NTLM bool
	// MaxRetries is the maximum number of retries per prefix. 0 disables
	// retries, -1 retries without limits.
	MaxRetries int
	// Force ignores the saved ETags and downloads every range.
	Force bool
	// Keep re-uses (keeps) previously downloaded ranges. This is the default
	// in directory mode, single file mode requires Overwrite instead.
	Keep bool
}

// Statistics contains statistics about a download run.
type Statistics struct {
	HashesDownloaded   atomic.Int64
	Requests           atomic.Int64
	ConditionalRequest atomic.Int64
	NotModifiedRanges  atomic.Int64
	ModifiedRanges     atomic.Int64
	CacheHits          atomic.Int64
	CacheMisses        atomic.Int64
	RequestTimeTotal   atomic.Int64
	IndexEntries       int
	Elapsed            time.Duration
}

// Downloader downloads pwned password hash ranges.
type Downloader struct {
	client *http.Client
	stats  Statistics
}

// New returns a new Downloader.
func New() *Downloader {
	return &Downloader{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Download downloads all hash ranges according to the given settings.
func (d *Downloader) Download(ctx context.Context, settings Settings) error {
	if settings.Output == "" {
		return fmt.Errorf("need output path")
	}
	if settings.Parallelism < 2 {
		settings.Parallelism = max(runtime.NumCPU()*8, 2)
	}
	if settings.MaxRetries < -1 {
		return fmt.Errorf("max retries must be 0 (disable retries) or greater, or -1 for unlimited retries")
	}

	if err := d.checkOutput(settings); err != nil {
		return err
	}

	// an existing directory without any usable content gets a default output
	// name appended
	if !settings.Single && fsutil.IsDir(settings.Output) && dirIsEmpty(settings.Output) {
		settings.Output = filepath.Join(settings.Output, defaultName(settings.NTLM))
		debug.Log("output is an empty directory, writing to %s", settings.Output)
		if err := os.MkdirAll(settings.Output, 0o755); err != nil {
			return err
		}
	}

	idx, err := d.loadIndex(settings)
	if err != nil {
		return err
	}

	if settings.Single {
		out := settings.Output
		if filepath.Ext(out) != ".txt" {
			out += ".txt"
		}
		if fsutil.IsFile(out) && !settings.Overwrite {
			return fmt.Errorf("output file %s already exists, use --overwrite to overwrite it", out)
		}
	} else if err := os.MkdirAll(settings.Output, 0o755); err != nil {
		return err
	}

	bar := termio.NewProgressBar(int64(NumRanges))
	bar.Hidden = ctxutil.IsHidden(ctx)

	start := time.Now()
	if settings.Single {
		err = d.downloadSingle(ctx, settings, bar)
	} else {
		err = d.downloadRanges(ctx, settings, idx, bar)
	}
	d.stats.Elapsed = time.Since(start)
	bar.Done()
	if err != nil {
		return err
	}

	if idx != nil {
		if err := idx.Save(indexPath(settings.Output, settings.NTLM)); err != nil {
			return fmt.Errorf("failed to save index: %w", err)
		}
		d.stats.IndexEntries = idx.Count()
	}

	d.printSummary(settings)

	return nil
}

// checkOutput verifies that the output location is usable.
func (d *Downloader) checkOutput(settings Settings) error {
	out := settings.Output
	if settings.Single && filepath.Ext(out) != ".txt" {
		out += ".txt"
	}

	if settings.Single {
		if fsutil.IsFile(out) && !settings.Overwrite {
			return fmt.Errorf("output file %s already exists, use --overwrite to overwrite it", out)
		}

		return nil
	}

	if fsutil.IsFile(out) {
		return fmt.Errorf("output %s is an existing file, not a directory", out)
	}
	if !fsutil.IsDir(out) {
		// the output directory does not exist, yet, nothing to check
		return nil
	}

	// refuse to pick up an unknown existing directory unless explicitly asked to
	indexExists := fsutil.IsFile(indexPath(out, settings.NTLM))
	if !settings.Overwrite && !settings.Force && !settings.Keep && !indexExists {
		if entries, err := os.ReadDir(out); err == nil && len(entries) > 0 {
			return fmt.Errorf("output directory %s already exists and is not empty, use --overwrite to overwrite it", out)
		}
	}

	return nil
}

// loadIndex loads the ETag index in directory mode.
func (d *Downloader) loadIndex(settings Settings) (*Index, error) {
	if settings.Single {
		return nil, nil
	}

	return LoadIndex(indexPath(settings.Output, settings.NTLM), settings.Force)
}

// downloadRanges downloads every hash range into an individual file.
func (d *Downloader) downloadRanges(ctx context.Context, settings Settings, idx *Index, bar *termio.ProgressBar) error {
	var firstErr atomic.Value

	sem := make(chan struct{}, settings.Parallelism)
	done := make(chan struct{}, NumRanges)
	go func() {
		for range done {
			bar.Inc()
		}
	}()

LOOP:
	for i := range NumRanges {
		// check for context cancelation
		select {
		case <-ctx.Done():
			break LOOP
		default:
		}
		if firstErr.Load() != nil {
			break
		}

		sem <- struct{}{}

		go func() {
			defer func() {
				<-sem
				done <- struct{}{}
			}()

			if err := d.downloadRange(ctx, i, settings, idx); err != nil {
				fmt.Printf("Prefix %05X failed: %s\n", i, err)
				firstErr.CompareAndSwap(nil, err)
			}
		}()
	}

	// wait for the remaining workers
	for range settings.Parallelism {
		sem <- struct{}{}
	}
	close(done)

	if err, _ := firstErr.Load().(error); err != nil {
		return err
	}

	return ctx.Err()
}

// downloadSingle downloads every hash range and writes them into a single file.
func (d *Downloader) downloadSingle(ctx context.Context, settings Settings, bar *termio.ProgressBar) error {
	out := settings.Output
	if filepath.Ext(out) != ".txt" {
		out += ".txt"
	}

	fh, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close() //nolint:errcheck

	results := make(chan rangeFuture, settings.Parallelism)

	// producer: enqueue all ranges, the bounded channel and the semaphore
	// limit the number of in-flight downloads
	prodErr := make(chan error, 1)
	go func() {
		defer close(results)

		sem := make(chan struct{}, settings.Parallelism)

	LOOP:
		for i := range NumRanges {
			select {
			case <-ctx.Done():
				break LOOP
			default:
			}

			sem <- struct{}{}
			select {
			case results <- d.downloadRangeAsync(ctx, i, settings.NTLM, sem):
			case <-ctx.Done():
				<-sem

				break LOOP
			}
		}

		// wait for the remaining workers
		for range settings.Parallelism {
			sem <- struct{}{}
		}

		prodErr <- ctx.Err()
	}()

	for resCh := range results {
		res := <-resCh
		if res.err != nil {
			return fmt.Errorf("prefix %s failed: %w", res.prefix, res.err)
		}
		if _, err := fh.Write(res.content); err != nil {
			return err
		}
		bar.Inc()
	}

	return <-prodErr
}

type rangeResult struct {
	prefix  string
	content []byte
	err     error
}

// rangeFuture is a channel that will receive exactly one range download
// result. It is used to preserve the submission order in single file mode.
type rangeFuture <-chan *rangeResult

// downloadRangeAsync returns a rangeFuture that will receive the result of
// the given range download.
func (d *Downloader) downloadRangeAsync(ctx context.Context, i int, ntlm bool, sem chan struct{}) rangeFuture {
	ch := make(chan *rangeResult, 1)

	go func() {
		defer func() {
			<-sem
		}()

		prefix := rangePrefix(i)
		content, err := d.downloadRangeToBuffer(ctx, prefix, ntlm)
		ch <- &rangeResult{prefix: prefix, content: content, err: err}
	}()

	return ch
}

// downloadRangeToBuffer downloads a single range and expands it to full
// (40 character) hashes, one per line, in the returned buffer.
func (d *Downloader) downloadRangeToBuffer(ctx context.Context, prefix string, ntlm bool) ([]byte, error) {
	body, err := withRetries(ctx, prefix, "downloading range data", -1, func() ([]byte, error) {
		resp, err := d.getRange(ctx, prefix, ntlm, "")
		if err != nil {
			return nil, err
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		if resp.StatusCode == http.StatusNotModified {
			return nil, nil
		}

		return readVerifiedBody(prefix, resp)
	})
	if err != nil || body == nil {
		return nil, err
	}

	return expandRange(prefix, body), nil
}

// downloadRange downloads a single range into an individual file.
func (d *Downloader) downloadRange(ctx context.Context, i int, settings Settings, idx *Index) error {
	prefix := rangePrefix(i)
	out := filepath.Join(settings.Output, prefix+".txt")

	etag := ""
	if idx != nil && fsutil.IsFile(out) {
		etag = idx.Get(prefix)
	}

	_, err := withRetries(ctx, prefix, "downloading range file", settings.MaxRetries, func() (struct{}, error) {
		resp, err := d.getRange(ctx, prefix, settings.NTLM, etag)
		if err != nil {
			return struct{}{}, err
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		if resp.StatusCode == http.StatusNotModified {
			d.stats.NotModifiedRanges.Add(1)

			return struct{}{}, nil
		}
		if etag != "" {
			d.stats.ModifiedRanges.Add(1)
		}

		if err := writeVerifiedBody(prefix, resp, out); err != nil {
			return struct{}{}, err
		}

		if idx != nil {
			if etag := resp.Header.Get("ETag"); etag != "" {
				idx.Set(prefix, etag)
			} else {
				debug.Log("response for prefix %s did not contain an ETag header, the range will not be indexed", prefix)
				idx.Remove(prefix)
			}
		}

		return struct{}{}, nil
	})
	if err != nil {
		return err
	}

	d.stats.HashesDownloaded.Add(1)

	return nil
}

// getRange fetches a single hash range. If etag is given a conditional
// request is made.
func (d *Downloader) getRange(ctx context.Context, prefix string, ntlm bool, etag string) (*http.Response, error) {
	url := BaseURL + prefix
	if ntlm {
		url += "?mode=ntlm"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
		d.stats.ConditionalRequest.Add(1)
	}

	start := time.Now()
	resp, err := d.client.Do(req)
	d.stats.RequestTimeTotal.Add(time.Since(start).Milliseconds())
	if err != nil {
		return nil, err
	}

	d.stats.Requests.Add(1)
	d.trackCacheStatus(resp)

	if resp.StatusCode == http.StatusNotModified {
		return resp, nil
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()

		return nil, fmt.Errorf("HTTP request failed: %s", resp.Status)
	}

	return resp, nil
}

// trackCacheStatus records the Cloudflare cache status of the response.
func (d *Downloader) trackCacheStatus(resp *http.Response) {
	if resp.Header.Get("CF-Cache-Status") == "HIT" {
		d.stats.CacheHits.Add(1)

		return
	}

	d.stats.CacheMisses.Add(1)
}

// readVerifiedBody reads and verifies the response body against its
// Content-MD5 header.
func readVerifiedBody(prefix string, resp *http.Response) ([]byte, error) {
	expected, err := contentMD5(prefix, resp)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := validateMD5(expected, md5.Sum(body)); err != nil {
		return nil, err
	}

	return body, nil
}

// writeVerifiedBody writes the response body to the given file and verifies
// it against its Content-MD5 header.
func writeVerifiedBody(prefix string, resp *http.Response, out string) error {
	expected, err := contentMD5(prefix, resp)
	if err != nil {
		return err
	}

	fh, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close() //nolint:errcheck

	hash := md5.New()
	if _, err := io.Copy(io.MultiWriter(fh, hash), resp.Body); err != nil {
		return err
	}

	var sum [md5.Size]byte
	copy(sum[:], hash.Sum(nil))

	return validateMD5(expected, sum)
}

// contentMD5 extracts and validates the Content-MD5 header of the response.
func contentMD5(prefix string, resp *http.Response) ([md5.Size]byte, error) {
	expected, err := decodeContentMD5(resp.Header.Get("Content-MD5"))
	if err != nil {
		return expected, fmt.Errorf("response for prefix %s did not contain a valid Content-MD5 header, the range cannot be verified", prefix)
	}

	return expected, nil
}

// validateMD5 compares two hashes in constant time.
func validateMD5(expected, actual [md5.Size]byte) error {
	if subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
		return errors.New("response body did not match its Content-MD5 header")
	}

	return nil
}

// rangePrefix returns the five character hash range prefix for the given index.
func rangePrefix(i int) string {
	return fmt.Sprintf("%05X", i&0xFFFFF)
}

// defaultName returns the default output name for the given hash mode.
func defaultName(ntlm bool) string {
	if ntlm {
		return "pwnedpasswords-ntlm"
	}

	return "pwnedpasswords"
}

// indexPath returns the path of the ETag index file.
func indexPath(output string, ntlm bool) string {
	name := "sha1.index"
	if ntlm {
		name = "ntlm.index"
	}

	return filepath.Join(output, name)
}

// dirIsEmpty returns true if the given directory contains no files.
func dirIsEmpty(dir string) bool {
	entries, err := os.ReadDir(dir)

	return err == nil && len(entries) < 1
}

// printSummary prints the download statistics.
func (d *Downloader) printSummary(settings Settings) {
	s := &d.stats
	reqs := s.Requests.Load()

	var avgRTT int64
	if reqs > 0 {
		avgRTT = s.RequestTimeTotal.Load() / reqs
	}

	var rps int64
	if secs := int64(s.Elapsed.Seconds()); secs > 0 {
		rps = s.HashesDownloaded.Load() / secs
	}

	fmt.Printf("Finished processing all hash ranges in %s (%d hash ranges per second).\n", s.Elapsed.Round(time.Millisecond), rps)
	fmt.Printf("Made %d requests (avg response time: %dms). Of those, %d were cache hits and %d were sent to the origin server.\n", reqs, avgRTT, s.CacheHits.Load(), s.CacheMisses.Load())

	if !settings.Single {
		fmt.Printf("The index made %d conditional requests. %d ranges were unchanged, %d were modified and downloaded, and the index now contains %d entries.\n", s.ConditionalRequest.Load(), s.NotModifiedRanges.Load(), s.ModifiedRanges.Load(), s.IndexEntries)
	}
}
