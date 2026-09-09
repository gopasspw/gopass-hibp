package main

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	hibpapi "github.com/gopasspw/gopass-hibp/pkg/hibp/api"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/gopass/apimock"
	"github.com/stretchr/testify/require"
)

const testHibpSample = `000000005AD76BD555C1D6D771DE417A4B87E4B4
00000000A8DAE4228F821FB418F59826079BF368:42
00000000DD7F2A1C68A35673713783CA390C9E93:42
00000001E225B908BAC31C56DB04D892E47536E0:42
00000008CD1806EB7B9B46A8F87690B2AC16F617:42
0000000A0E3B9F25FF41DE4B5AC238C2D545C7A8:42
0000000A1D4B746FAA3FD526FF6D5BC8052FDB38:42
0000000CAEF405439D57847A8657218C618160B2:42
0000000FC1C08E6454BED24F463EA2129E254D43:42
00000010F4B38525354491E099EB1796278544B1`

func TestHIBPDump(t *testing.T) {
	dir := t.TempDir()

	ctx := t.Context()
	ctx = ctxutil.WithAlwaysYes(ctx, true)

	act := &hibp{
		gp: apimock.New(),
	}

	// setup file and env
	fn := filepath.Join(dir, "dump.txt")

	require.NoError(t, os.WriteFile(fn, []byte(testHibpSample), 0o644))
	require.NoError(t, act.CheckDump(ctx, false, []string{fn}))

	// gzip
	fn = filepath.Join(dir, "dump.txt.gz")

	require.NoError(t, testWriteGZ(fn, []byte(testHibpSample)))
	require.NoError(t, act.CheckDump(ctx, false, []string{fn}))
}

func testWriteGZ(fn string, buf []byte) error {
	fh, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		_ = fh.Close()
	}()

	gzw := gzip.NewWriter(fh)
	defer func() {
		_ = gzw.Close()
	}()

	_, err = gzw.Write(buf)

	return err
}

func TestHIBPAPI(t *testing.T) {
	ctx := t.Context()
	ctx = ctxutil.WithAlwaysYes(ctx, true)

	act := &hibp{
		gp: apimock.New(),
	}

	reqCnt := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCnt++
		if reqCnt < 2 {
			http.Error(w, "fake error", http.StatusInternalServerError)

			return
		}
		if strings.TrimPrefix(r.URL.String(), "/range/") == "8843D" {
			fmt.Fprintf(w, "8843D:1\n")                                     // invalid
			fmt.Fprintf(w, "7F92416211DE9EBB963FF4CE2812593287:3234879\n")  // invalid
			fmt.Fprintf(w, "7F92416211DE9EBB963FF4CE28125932878:\n")        // invalid
			fmt.Fprintf(w, "7F92416211DE9EBB963FF4CE28125932878\n")         // invalid
			fmt.Fprintf(w, "7F92416211DE9EBB963FF4CE28125932878:3234879\n") // valid

			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer ts.Close()
	hibpapi.URL = ts.URL

	// test with one entry
	require.NoError(t, act.CheckAPI(ctx, false))

	// add another one
	require.NoError(t, act.gp.Set(ctx, "baz", &apimock.Secret{Buf: []byte("foobar")}))
	require.Error(t, act.CheckAPI(ctx, false))
}

func TestFilterExcludes(t *testing.T) {
	tests := []struct {
		name     string
		excludes string
		in       []string
		want     []string
	}{
		{
			name:     "no excludes",
			excludes: "",
			in:       []string{"secret1", "secret2"},
			want:     []string{"secret1", "secret2"},
		},
		{
			name:     "exclude one secret",
			excludes: "secret1",
			in:       []string{"secret1", "secret2"},
			want:     []string{"secret2"},
		},
		{
			name:     "exclude all secrets",
			excludes: "secret1\nsecret2",
			in:       []string{"secret1", "secret2"},
			want:     []string{},
		},
		{
			name:     "exclude with comment",
			excludes: "# this is a comment\nsecret1",
			in:       []string{"secret1", "secret2"},
			want:     []string{"secret2"},
		},
		{
			name:     "exclude with empty lines",
			excludes: "\nsecret1\n\n",
			in:       []string{"secret1", "secret2"},
			want:     []string{"secret2"},
		},
		{
			name:     "exclude with regex",
			excludes: "secret.*",
			in:       []string{"secret1", "secret2", "other"},
			want:     []string{"other"},
		},
		{
			name:     "ignore invalid regex",
			excludes: "([",
			in:       []string{"secret1", "secret2"},
			want:     []string{"secret1", "secret2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterExcludes(tt.excludes, tt.in)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestPrecomputeHashesAuditIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PASSWORD_STORE_DIR", dir)

	ctx := t.Context()
	act := &hibp{
		gp: apimock.New(),
	}

	require.NoError(t, act.gp.Set(ctx, "keep/me", &apimock.Secret{Buf: []byte("hunter2")}))
	require.NoError(t, act.gp.Set(ctx, "skip/me", &apimock.Secret{Buf: []byte("password1")}))
	require.NoError(t, act.gp.Set(ctx, "team/service", &apimock.Secret{Buf: []byte("password2")}))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".gopass-audit-ignore"), []byte("# comment\nskip/me\nteam/.*\n(["), 0o644))

	shaSums, sortedShaSums, err := act.precomputeHashes(ctx)
	require.NoError(t, err)
	require.Len(t, shaSums, 1)
	require.Len(t, sortedShaSums, 1)

	names := make([]string, 0, len(shaSums))
	for _, name := range shaSums {
		names = append(names, name)
	}
	slices.Sort(names)
	require.Equal(t, []string{"keep/me"}, names)
}

func TestRootStoreDirFromConfig(t *testing.T) {
	dir := t.TempDir()
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "config")

	require.NoError(t, os.WriteFile(cfgPath, []byte("[mounts]\n\tpath = "+dir+"\n"), 0o644))

	t.Setenv("GOPASS_CONFIG", cfgPath)
	t.Setenv("PASSWORD_STORE_DIR", filepath.Join(t.TempDir(), "other"))

	require.Equal(t, dir, rootStoreDir())
}
