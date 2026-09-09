package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/gopasspw/gitconfig"
	"github.com/gopasspw/gopass/pkg/appdir"
	"github.com/fatih/color"
	hibpapi "github.com/gopasspw/gopass-hibp/pkg/hibp/api"
	hibpdump "github.com/gopasspw/gopass-hibp/pkg/hibp/dump"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/debug"
	"github.com/gopasspw/gopass/pkg/fsutil"
	"github.com/gopasspw/gopass/pkg/gopass"
	"github.com/gopasspw/gopass/pkg/termio"
)

type hibp struct {
	gp gopass.Store
}

// CheckAPI checks your secrets against the HIBPv2 API.
func (s *hibp) CheckAPI(ctx context.Context, force bool) error {
	if !force && !termio.AskForConfirmation(ctx, "This command is checking all your secrets against the haveibeenpwned.com API.\n\nThis will send five bytes of each passwords SHA1 hash to an untrusted server!\n\nYou will be asked to unlock all your secrets!\nDo you want to continue?") {
		return fmt.Errorf("user aborted")
	}

	shaSums, sortedShaSums, err := s.precomputeHashes(ctx)
	if err != nil {
		return err
	}

	fmt.Println("Checking pre-computed SHA1 hashes against the HIBP API ...")

	// compare the prepared list against all provided files
	matchList := make([]string, 0, len(sortedShaSums))
	for _, shaSum := range sortedShaSums {
		freq, err := hibpapi.Lookup(shaSum)
		if err != nil {
			fmt.Printf("Failed to check HIBP API: %s\n", err)

			continue
		}
		if freq < 1 {
			continue
		}
		if pw, found := shaSums[shaSum]; found {
			matchList = append(matchList, pw)
		}
	}

	return s.printMatches(matchList)
}

// CheckDump checks your secrets against the provided HIBPv2 Dumps.
func (s *hibp) CheckDump(ctx context.Context, force bool, dumps []string) error {
	fmt.Println("Using the HIBPv2 dumps is very expensive. If you can condone leaking a few bits of entropy per secret you should probably use the '--api' flag.")

	if len(dumps) < 1 {
		return fmt.Errorf("need a least one dump file")
	}

	// New also checks if there is at least one valid dump file given
	scanner, err := hibpdump.New(dumps...)
	if err != nil {
		return fmt.Errorf("failed to create new HIBP Dump scanner: %w", err)
	}

	if !force && !termio.AskForConfirmation(ctx, fmt.Sprintf("This command is checking all your secrets against the haveibeenpwned.com hashes in %+v.\nYou will be asked to unlock all your secrets!\nDo you want to continue?", dumps)) {
		return fmt.Errorf("user aborted")
	}

	shaSums, sortedShaSums, err := s.precomputeHashes(ctx)
	if err != nil {
		return err
	}

	fmt.Println("Checking hashes against the provided dumps. This will take a while.")

	matchedSums := scanner.LookupBatch(ctx, sortedShaSums)
	debug.Log("In: %+v - Out: %+v", sortedShaSums, matchedSums)
	matchList := make([]string, 0, len(matchedSums))
	for _, matchedSum := range matchedSums {
		if pw, found := shaSums[matchedSum]; found {
			matchList = append(matchList, pw)
		}
	}

	return s.printMatches(matchList)
}

func (s *hibp) precomputeHashes(ctx context.Context) (map[string]string, []string, error) {
	// build a map of all secrets sha sums to their names and also build a sorted (!)
	// list of this shasums. As the hibp dump is already sorted this allows for
	// a very efficient stream compare in O(n)
	pwList, err := s.gp.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	nList := filterExcludes(readAuditIgnoreFile(), pwList)
	if len(nList) < len(pwList) {
		fmt.Printf("Excluding %d secrets based on .gopass-audit-ignore\n", len(pwList)-len(nList))
	}
	pwList = nList
	// map sha1sum back to secret name for reporting
	shaSums := make(map[string]string, len(pwList))
	// build list of sha1sums (must be sorted later!) for stream comparison
	sortedShaSums := make([]string, 0, len(shaSums))
	// display progress bar
	bar := termio.NewProgressBar(int64(len(pwList)))
	bar.Hidden = ctxutil.IsHidden(ctx)

	fmt.Println("Computing SHA1 hashes of all your secrets ...")
	for _, secret := range pwList {
		// check for context cancelation
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("user aborted")
		default:
		}

		bar.Inc()

		// only handle secrets / passwords, never the body
		// comparing the body is super hard, as every user may choose to use
		// the body of a secret differently. In the future we may support
		// go templates to extract and compare data from the body
		sec, err := s.gp.Get(ctx, secret, "latest")
		if err != nil {
			fmt.Printf("%s", "\n"+color.YellowString("Failed to retrieve secret '%s': %s\n", secret, err))

			continue
		}

		pw := sec.Password()
		// do not check empty passwords, there should be caught by `gopass audit`
		// anyway
		if len(pw) < 1 {
			continue
		}
		sum := sha1hex(pw)
		shaSums[sum] = secret
		sortedShaSums = append(sortedShaSums, sum)
	}
	bar.Done()
	// IMPORTANT: sort after all entries have been added. without the sort
	// the stream compare will not work
	sort.Strings(sortedShaSums)

	return shaSums, sortedShaSums, nil
}

func readAuditIgnoreFile() string {
	fn := filepath.Join(rootStoreDir(), ".gopass-audit-ignore")
	buf, err := os.ReadFile(fn)
	if err != nil {
		return ""
	}

	return string(buf)
}

func rootStoreDir() string {
	for _, configPath := range []string{
		os.Getenv("GOPASS_CONFIG"),
		filepath.Join(appdir.UserConfig(), "config"),
		"/etc/gopass/config",
	} {
		if p := configMountPath(configPath); p != "" {
			return p
		}
	}

	if d := os.Getenv("PASSWORD_STORE_DIR"); d != "" {
		return fsutil.CleanPath(d)
	}

	if ld := filepath.Join(appdir.UserHome(), ".password-store"); fsutil.IsDir(ld) {
		return ld
	}

	return fsutil.CleanPath(filepath.Join(appdir.UserData(), "stores", "root"))
}

func configMountPath(path string) string {
	if path == "" {
		return ""
	}

	cfg, err := gitconfig.LoadConfig(path)
	if err != nil {
		return ""
	}

	if p, ok := cfg.Get("mounts.path"); ok && p != "" {
		return fsutil.CleanPath(p)
	}

	return ""
}

func filterExcludes(excludes string, in []string) []string {
	res := make([]*regexp.Regexp, 0, strings.Count(excludes, "\n")+1)
	for _, line := range strings.Split(excludes, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		re, err := regexp.Compile(line)
		if err != nil {
			debug.Log("failed to compile exclude pattern %q: %s", line, err)

			continue
		}
		res = append(res, re)
	}

	if len(res) < 1 {
		return in
	}

	out := make([]string, 0, len(in))
	for _, s := range in {
		matched := false
		for _, re := range res {
			if re.MatchString(s) {
				matched = true

				break
			}
		}
		if !matched {
			out = append(out, s)
		}
	}

	return out
}

func (s *hibp) printMatches(matchList []string) error {
	if len(matchList) < 1 {
		fmt.Println("Good news - No matches found!")

		return nil
	}

	sort.Strings(matchList)
	fmt.Println("Oh no - Found some matches:")
	for _, m := range matchList {
		fmt.Printf("\t- %s\n", m)
	}
	fmt.Println("The passwords in the listed secrets were included in public leaks in the past. This means they are likely included in many word-list attacks and provide only very little security. Strongly consider changing those passwords!")

	return fmt.Errorf("weak passwords found")
}

func sha1hex(data string) string {
	h := sha1.New()
	_, _ = h.Write([]byte(data))

	return fmt.Sprintf("%X", h.Sum(nil))
}
