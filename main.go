package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/thde/cves/internal/cli"
)

// variables passed by goreleaser.
var (
	version   string
	commit    string
	date      string
	goVersion string
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err := cli.Run(ctx, os.Stderr, &cli.BuildInfo{
		Version:   version,
		Commit:    commit,
		Date:      date,
		GoVersion: goVersion,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	if version == "" {
		version = info.Main.Version
	}

	goVersion = info.GoVersion

	for _, kv := range info.Settings {
		switch kv.Key {
		case "vcs.revision":
			if commit == "" {
				commit = kv.Value
			}
		case "vcs.time":
			if date == "" {
				date = kv.Value
			}
		}
	}
}
