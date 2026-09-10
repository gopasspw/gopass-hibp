package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/gopasspw/gopass/pkg/gopass/api"
	hapi "github.com/gopasspw/gopass/pkg/hibp/api"
	hibpdump "github.com/gopasspw/gopass/pkg/hibp/dump"
	"github.com/urfave/cli/v3"
)

const (
	name = "gopass-hibp"
)

// Version is the released version of gopass.
var version string

func main() {
	ctx := context.Background()

	// trap Ctrl+C and call cancel on the context
	ctx, cancel := context.WithCancel(ctx)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	defer func() {
		signal.Stop(sigChan)
		cancel()
	}()
	go func() {
		select {
		case <-sigChan:
			cancel()
		case <-ctx.Done():
		}
	}()

	gp, err := api.New(ctx)
	if err != nil {
		fmt.Printf("Failed to initialize gopass API: %s\n", err)
		os.Exit(1)
	}

	hibp := &hibp{
		gp: gp,
	}

	app := &cli.Command{
		Name:                  name,
		Version:               getVersion().String(),
		Usage:                 "haveibeenpwned.com leak checker for gopass",
		EnableShellCompletion: true,
		Commands: []*cli.Command{
			{
				Name:  "api",
				Usage: "Detect leaked passwords using the HIBPv2 API",
				Description: "" +
					"This command will decrypt all secrets and check the passwords against the public " +
					"havibeenpwned.com v2 API.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return hibp.CheckAPI(ctx, cmd.Bool("force"))
				},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Force checking secrets against the public API",
					},
				},
			},
			{
				Name:   "dump",
				Usage:  "Detect leaked passwords using local HIBP SHA-1 dumps (deprecated)",
				Hidden: true,
				Description: "" +
					"DEPRECATED: This command is deprecated and will be removed in a future release. " +
					"The HIBP dumps are not available for download anymore. Please use the 'download' command " +
					"(which uses the same approach as the official .NET PwnedPasswords downloader) to obtain a fresh dump.\n\n" +
					"This command will decrypt all secrets and check the passwords against the " +
					"local havibeenpwned.com SHA-1 dumps (ordered by hash). " +
					"This is a very expensive operation, for advanced users. " +
					"Most users should probably use the API. " +
					"gzipped and plain text dumps are supported.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return hibp.CheckDump(ctx, cmd.Bool("force"), cmd.StringSlice("files"))
				},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Force checking secrets against the dumps",
					},
					&cli.StringSliceFlag{
						Name:  "files",
						Usage: "One or more HIBP v1/v2 dumps",
					},
				},
			},
			{
				Name:  "download",
				Usage: "Download HIBP dumps from the v2 API",
				Description: "" +
					"This command downloads all pwned password hashes from the pwnedpasswords.com range API " +
					"into a single, gzipped dump (ordered by hash). It uses the same approach as the official " +
					".NET PwnedPasswords downloader. The resulting file can be used with the 'dump' command.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return hapi.Download(ctx, cmd.String("output"), cmd.Bool("keep"))
				},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"f"},
						Usage:   "Output location",
					},
					&cli.BoolFlag{
						Name:    "keep",
						Aliases: []string{"k"},
						Usage:   "Keep and re-use partial downloads",
					},
				},
			},
			{
				Name:   "merge",
				Usage:  "Merge different dumps (deprecated)",
				Hidden: true,
				Description: "" +
					"DEPRECATED: This command is deprecated and will be removed in a future release. " +
					"It is only useful with manually maintained local dumps.\n\n" +
					"Merge two sorted HIBP SHA-1 dumps into one.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					scanner, err := hibpdump.New(cmd.StringSlice("files")...)
					if err != nil {
						return err
					}

					return scanner.Merge(ctx, cmd.String("output"))
				},
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "files",
						Usage: "One or more HIBP v1/v2 dumps",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"f"},
						Usage:   "Output location",
					},
				},
			},
			{
				Name: "version",
				Action: func(_ context.Context, cmd *cli.Command) error {
					cli.VersionPrinter(cmd)

					return nil
				},
			},
		},
	}

	if err := app.Run(ctx, os.Args); err != nil {
		log.Fatal(err)
	}
}
