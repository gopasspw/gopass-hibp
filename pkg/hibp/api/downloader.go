package api

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/debug"
	"github.com/gopasspw/gopass/pkg/termio"
)

func Download(ctx context.Context, output string) error {
	if !strings.HasSuffix(output, ".gz") {
		output += ".gz"
	}

	fh, err := os.OpenFile(output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()

	gzw := gzip.NewWriter(fh)
	defer gzw.Close()

	return DownloadTo(ctx, gzw)
}

func DownloadTo(ctx context.Context, w io.Writer) error {
	max := 1024 * 1024
	bar := termio.NewProgressBar(int64(max))
	bar.Hidden = ctxutil.IsHidden(ctx)

	for i := 0; i < max; i++ {
		if err := downloadChunk(ctx, i, w); err != nil {
			return err
		}
		bar.Inc()
	}

	bar.Done()

	return nil
}

func downloadChunk(ctx context.Context, chunk int, w io.Writer) error {
	hex := fmt.Sprintf("%X", chunk)
	prefix := strings.Repeat("0", 5-len(hex)) + hex

	url := URL + "/range/" + prefix

	op := func() error {
		debug.Log("HTTP Request: %s", url)
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		if resp.StatusCode == http.StatusNotFound {
			return nil
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP request failed: %s %s", resp.Status, body)
		}

		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if len(line) < 37 {
				continue
			}
			fmt.Fprintf(w, "%s%s\n", prefix, line)
		}

		return nil
	}

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 10 * time.Second

	return backoff.Retry(op, bo)
}
