package downloader

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRanges is the number of hash ranges used in the tests.
const testRanges = 8

func setup(t *testing.T) {
	t.Helper()

	oldNumRanges := NumRanges
	oldBaseURL := BaseURL
	t.Cleanup(func() {
		NumRanges = oldNumRanges
		BaseURL = oldBaseURL
	})
	NumRanges = testRanges
}

// newTestServer returns a test server that serves the given ranges. Each
// entry maps a range prefix to its response body.
func newTestServer(t *testing.T, ranges map[string]string) *httptest.Server {
	t.Helper()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := strings.TrimPrefix(r.URL.Path, "/range/")

		body, ok := ranges[prefix]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)

			return
		}

		if r.Header.Get("If-None-Match") == `"etag-`+prefix+`"` {
			w.WriteHeader(http.StatusNotModified)

			return
		}

		w.Header().Set("ETag", `"etag-`+prefix+`"`)
		w.Header().Set("Content-MD5", base64.StdEncoding.EncodeToString(md5sum([]byte(body))))
		fmt.Fprint(w, body)
	}))
	t.Cleanup(ts.Close)

	return ts
}

// testRangesMap returns a map of all test ranges.
func testRangesMap() map[string]string {
	ranges := make(map[string]string, testRanges)
	for i := range testRanges {
		prefix := fmt.Sprintf("%05X", i)
		ranges[prefix] = fmt.Sprintf("%012X:%d\r\n%012X:%d\r\n", i, i+1, i+2, i+3)
	}

	return ranges
}

func md5sum(b []byte) []byte {
	sum := md5.Sum(b)

	return sum[:]
}

func TestDownloadSingle(t *testing.T) { //nolint:paralleltest
	setup(t)
	BaseURL = newTestServer(t, testRangesMap()).URL + "/range/"

	out := filepath.Join(t.TempDir(), "pwnedpasswords.txt")
	require.NoError(t, New().Download(t.Context(), Settings{
		Output:      out,
		Single:      true,
		Parallelism: 2,
		MaxRetries:  0,
	}))

	buf, err := os.ReadFile(out)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(buf)), "\n")
	require.Len(t, lines, 2*testRanges)
	for i, line := range lines {
		prefix := fmt.Sprintf("%05X", i/2)
		assert.True(t, strings.HasPrefix(line, prefix), "line %d should start with %s: %s", i, prefix, line)
		assert.Contains(t, line, ":")
	}

	// existing output file without overwrite
	require.Error(t, New().Download(t.Context(), Settings{
		Output:      out,
		Single:      true,
		Parallelism: 2,
	}))
}

func TestDownloadRanges(t *testing.T) { //nolint:paralleltest
	setup(t)
	BaseURL = newTestServer(t, testRangesMap()).URL + "/range/"

	out := filepath.Join(t.TempDir(), "pwnedpasswords")
	require.NoError(t, New().Download(t.Context(), Settings{
		Output:      out,
		Parallelism: 2,
		MaxRetries:  0,
	}))

	// all ranges should have been downloaded as individual files
	for i := range testRanges {
		fn := filepath.Join(out, fmt.Sprintf("%05X.txt", i))
		require.FileExists(t, fn)
		buf, err := os.ReadFile(fn)
		require.NoError(t, err)
		assert.Len(t, strings.Split(strings.TrimSpace(string(buf)), "\n"), 2)
	}

	// the index should have been written
	idx, err := LoadIndex(filepath.Join(out, "sha1.index"), false)
	require.NoError(t, err)
	assert.Equal(t, testRanges, idx.Count())
	assert.Equal(t, `"etag-00000"`, idx.Get("00000"))

	// a second run should re-use the index and make conditional requests
	require.NoError(t, New().Download(t.Context(), Settings{
		Output:      out,
		Parallelism: 2,
		MaxRetries:  0,
	}))
}

func TestDownloadRangesSubdir(t *testing.T) { //nolint:paralleltest
	setup(t)
	BaseURL = newTestServer(t, testRangesMap()).URL + "/range/"

	// an existing directory gets a default output name appended
	td := t.TempDir()
	require.NoError(t, New().Download(t.Context(), Settings{
		Output:      td,
		Parallelism: 2,
		MaxRetries:  0,
	}))

	assert.FileExists(t, filepath.Join(td, "pwnedpasswords", "00000.txt"))
	assert.FileExists(t, filepath.Join(td, "pwnedpasswords", "sha1.index"))
}

func TestDownloadNTLM(t *testing.T) { //nolint:paralleltest
	setup(t)

	var ntlm atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("mode") == "ntlm" {
			ntlm.Store(true)
		}
		body := "0123456789ABCDEF0123456789ABCDEF0:1\r\n"
		w.Header().Set("Content-MD5", base64.StdEncoding.EncodeToString(md5sum([]byte(body))))
		fmt.Fprint(w, body)
	}))
	t.Cleanup(ts.Close)
	BaseURL = ts.URL + "/range/"

	out := filepath.Join(t.TempDir(), "ntlm")
	require.NoError(t, New().Download(t.Context(), Settings{
		Output:      out,
		NTLM:        true,
		Parallelism: 2,
		MaxRetries:  0,
	}))
	assert.True(t, ntlm.Load(), "expected the ntlm mode to be requested")
	assert.FileExists(t, filepath.Join(out, "ntlm.index"))
}

func TestDownloadBadMD5(t *testing.T) { //nolint:paralleltest
	setup(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-MD5", base64.StdEncoding.EncodeToString(md5sum([]byte("something else"))))
		fmt.Fprint(w, "0123456789ABCDEF0123456789ABCDEF0:1\r\n")
	}))
	t.Cleanup(ts.Close)
	BaseURL = ts.URL + "/range/"

	require.Error(t, New().Download(t.Context(), Settings{
		Output:      filepath.Join(t.TempDir(), "out"),
		Parallelism: 2,
		MaxRetries:  0,
	}))
}

func TestDownloadMissingMD5(t *testing.T) { //nolint:paralleltest
	setup(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "0123456789ABCDEF0123456789ABCDEF0:1\r\n")
	}))
	t.Cleanup(ts.Close)
	BaseURL = ts.URL + "/range/"

	require.Error(t, New().Download(t.Context(), Settings{
		Output:      filepath.Join(t.TempDir(), "out"),
		Parallelism: 2,
		MaxRetries:  0,
	}))
}

func TestDownloadErrors(t *testing.T) { //nolint:paralleltest
	setup(t)
	BaseURL = newTestServer(t, testRangesMap()).URL + "/range/"

	td := t.TempDir()

	// no output path
	require.Error(t, New().Download(t.Context(), Settings{}))

	// invalid max retries
	require.Error(t, New().Download(t.Context(), Settings{
		Output:     filepath.Join(td, "a"),
		MaxRetries: -2,
	}))

	// non-empty directory without index and without overwrite
	dir := filepath.Join(td, "b")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "foo"), []byte("bar"), 0o644))
	require.Error(t, New().Download(t.Context(), Settings{
		Output:      dir,
		Parallelism: 2,
	}))

	// existing regular file as output
	fn := filepath.Join(td, "c")
	require.NoError(t, os.WriteFile(fn, []byte("bar"), 0o644))
	require.Error(t, New().Download(t.Context(), Settings{
		Output:      fn,
		Parallelism: 2,
	}))
}

func TestRangePrefix(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "00000", rangePrefix(0))
	assert.Equal(t, "00001", rangePrefix(1))
	assert.Equal(t, "00ABC", rangePrefix(0xABC))
	assert.Equal(t, "FFFFF", rangePrefix(0xFFFFF))
	assert.Equal(t, "00000", rangePrefix(0x100000)) // wraps around
}

func TestExpandRange(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "00000ABC:1\r\n", string(expandRange("00000", []byte("ABC:1\r\n"))))
	assert.Equal(t, "00000ABC:1\n", string(expandRange("00000", []byte("ABC:1\n"))))
	assert.Empty(t, string(expandRange("00000", []byte("\n\r\n"))))
	assert.Equal(t, "00000ABC:1\r\n00000DEF:2\r\n", string(expandRange("00000", []byte("ABC:1\r\nDEF:2\r\n"))))
}

func TestIndex(t *testing.T) {
	t.Parallel()

	td := t.TempDir()
	fn := filepath.Join(td, "sha1.index")

	// load a non-existing index
	idx, err := LoadIndex(fn, false)
	require.NoError(t, err)
	assert.Equal(t, 0, idx.Count())
	assert.Empty(t, idx.Get("00000"))

	// save and re-load
	idx.Set("00000", `"foo"`)
	idx.Set("FFFFF", `"bar"`)
	idx.Set("00000", `"baz"`) // overwrite
	require.NoError(t, idx.Save(fn))

	idx, err = LoadIndex(fn, false)
	require.NoError(t, err)
	assert.Equal(t, 2, idx.Count())
	assert.Equal(t, `"baz"`, idx.Get("00000"))
	assert.Equal(t, `"bar"`, idx.Get("FFFFF"))

	// remove
	idx.Remove("00000")
	assert.Empty(t, idx.Get("00000"))

	// force load ignores the file
	idx, err = LoadIndex(fn, true)
	require.NoError(t, err)
	assert.Equal(t, 0, idx.Count())
}

func TestIndexInvalid(t *testing.T) {
	t.Parallel()

	td := t.TempDir()

	for _, content := range []string{
		"invalid\n",
		"00000\n",
		"00000\tfoo\tbar\n",
		"0000\t\"foo\"\n",
		"0000Z\t\"foo\"\n",
		"00000\t\n",
		"00000\t\"foo\"\n00000\t\"bar\"\n",
	} {
		fn := filepath.Join(td, "sha1.index")
		require.NoError(t, os.WriteFile(fn, []byte(content), 0o644))
		_, err := LoadIndex(fn, false)
		assert.Error(t, err, "content %q should be invalid", content)
	}
}

func TestIsHashRange(t *testing.T) {
	t.Parallel()

	assert.True(t, isHashRange("00000"))
	assert.True(t, isHashRange("FFFFF"))
	assert.False(t, isHashRange(""))
	assert.False(t, isHashRange("0000"))
	assert.False(t, isHashRange("000000"))
	assert.False(t, isHashRange("fffff"))
	assert.False(t, isHashRange("0000G"))
}
