// Package cli provides the command-line interface for the CVES application.
package cli

import (
	"bytes"
	"cmp"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/httplog/v2"
	"github.com/google/go-github/v70/github"
	"github.com/klauspost/compress/gzhttp"
	"github.com/thde/cves/internal/api"
	v1 "github.com/thde/cves/internal/api/v1"
	"github.com/thde/cves/internal/cache"
)

const githubTimeout = 30 * time.Second

// BuildInfo carries version metadata injected at build time.
type BuildInfo struct {
	Version   string
	Commit    string
	Date      string
	GoVersion string
}

// Run is the application entry point. It wires dependencies and starts the HTTP server.
func Run(ctx context.Context, stderr io.Writer, info *BuildInfo) error {
	logger := httplog.NewLogger("cves", httplog.Options{
		LogLevel:        slog.LevelDebug,
		Concise:         true,
		RequestHeaders:  false,
		Tags:            map[string]string{"version": info.Version},
		Writer:          stderr,
		TimeFieldFormat: time.DateTime,
	})

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		logger.Warn("GITHUB_TOKEN not set — GitHub API rate limits will apply")
	}

	ghClient := newGitHubClient(token)

	c, err := newAdvisoryCache(os.Getenv("CACHE_DIR"), logger.With("component", "cache"))
	if err != nil {
		return fmt.Errorf("open cache: %w", err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			logger.Error("close cache", "err", err)
		}
	}()

	addr := os.Getenv("ADDR")
	if addr == "" {
		port := cmp.Or(os.Getenv("PORT"), strconv.Itoa(8080))
		addr = ":" + port
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	srv, err := api.New(
		api.WithLogger(logger),
		api.WithBuildInfo(api.BuildInfo{
			Version:   info.Version,
			GoVersion: info.GoVersion,
			Commit:    info.Commit,
			Date:      info.Date,
		}),
	)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	api, err := v1.New(
		v1.WithCache(c),
		v1.WithGitHubClient(ghClient),
		v1.WithLogger(logger.With("component", "v1")),
	)
	if err != nil {
		return fmt.Errorf("create v1: %w", err)
	}
	srv.Mount("/v1", api.Handler())

	logger.Info("server starting", "addr", l.Addr(), "version", info.Version)
	return srv.Listen(ctx, l)
}

// newAdvisoryCache opens (or creates) a cache for GitHub security advisories at dir.
// If no dir is provided, a default OS cache directory is used (typically ~/.cache/cves).
func newAdvisoryCache(dir string, logger *slog.Logger) (*cache.Cache[[]*github.SecurityAdvisory], error) {
	if dir == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("lookup cache dir: %w", err)
		}

		dir = filepath.Join(cacheDir, "cves")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache dir %q: %w", dir, err)
	}

	encode := func(v []*github.SecurityAdvisory) (b []byte, err error) {
		buf := bytes.NewBuffer(b)
		err = gob.NewEncoder(buf).Encode(v)
		if err != nil {
			return nil, fmt.Errorf("cache encode: %w", err)
		}

		return buf.Bytes(), nil
	}
	decode := func(b []byte) (v []*github.SecurityAdvisory, err error) {
		err = gob.NewDecoder(bytes.NewReader(b)).Decode(&v)
		if err != nil {
			return nil, fmt.Errorf("cache decode: %w", err)
		}

		return v, nil
	}

	return cache.New(dir, encode, decode, cache.WithLogger(logger))
}

// newGitHubClient builds a GitHub client with gzip transport and optional token auth.
func newGitHubClient(token string) *github.Client {
	httpClient := &http.Client{
		Transport: gzhttp.Transport(http.DefaultTransport),
		Timeout:   githubTimeout,
	}
	gh := github.NewClient(httpClient)
	if token != "" {
		gh = gh.WithAuthToken(token)
	}
	return gh
}
