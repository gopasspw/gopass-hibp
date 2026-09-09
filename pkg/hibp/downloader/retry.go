package downloader

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/gopasspw/gopass/pkg/debug"
)

const (
	retryDelay    = 2 * time.Second
	maxRetryDelay = 10 * time.Second
)

// withRetries executes the given operation and retries it on failure. If
// maxRetries is negative the operation is retried without limits, if it is
// zero the operation is only attempted once.
func withRetries[T any](ctx context.Context, prefix, operation string, maxRetries int, work func() (T, error)) (T, error) {
	var result T

	retryAttempt := 0
	for {
		res, err := work()
		if err == nil {
			return res, nil
		}

		// never retry canceled operations
		if ctx.Err() != nil {
			return result, err
		}

		if maxRetries >= 0 && retryAttempt >= maxRetries {
			return result, err
		}

		retryAttempt++
		delay := min(time.Duration(retryAttempt)*retryDelay, maxRetryDelay)
		debug.Log("retry %d for prefix %s in %s while %s: %s", retryAttempt, prefix, delay, operation, err)

		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(delay):
		}
	}
}

// decodeContentMD5 decodes a base64 encoded Content-MD5 header value.
func decodeContentMD5(header string) ([16]byte, error) {
	var sum [16]byte

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header))
	if err != nil || len(raw) != len(sum) {
		return sum, fmt.Errorf("invalid Content-MD5 header %q", header)
	}
	copy(sum[:], raw)

	return sum, nil
}

// expandRange expands a range response body (suffix:count per line) into full
// (40 character) hash lines prefixed with the given range prefix.
func expandRange(prefix string, body []byte) []byte {
	out := make([]byte, 0, len(body)+1024) // some extra space for the prefixes
	for len(body) > 0 {
		line := body
		if i := indexByte(body, '\n'); i >= 0 {
			line = body[:i]
			body = body[i+1:]
		} else {
			body = nil
		}
		if len(line) < 1 || string(line) == "\r" {
			continue
		}

		out = append(out, prefix...)
		out = append(out, line...)
		out = append(out, '\n')
	}

	return out
}

// indexByte is bytes.IndexByte, kept private to avoid importing bytes in
// downloader.go only for this.
func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}

	return -1
}
