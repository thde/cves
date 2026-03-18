// Package api implements the HTTP server: middleware stack, listener lifecycle,
// and the index page. Version-specific route groups are mounted via [Server.Mount].
package api

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v2"
	"github.com/klauspost/compress/gzhttp"
)

//go:embed static
var staticFiles embed.FS

const (
	defaultTimeout = 30 * time.Second
)

// BuildInfo carries version metadata shown on the index page.
type BuildInfo struct {
	Version   string
	Commit    string
	Date      string
	GoVersion string
}

// config holds the resolved server configuration.
type config struct {
	timeout   time.Duration
	logger    *httplog.Logger
	buildInfo BuildInfo
}

// Option configures a Server.
type Option func(*config)

// WithLogger sets the request logger. Defaults to a new httplog.Logger named "cves".
func WithLogger(logger *httplog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// WithTimeout sets the read/write timeout for the HTTP server. Defaults to 30s.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithBuildInfo attaches version metadata shown on the index page.
func WithBuildInfo(info BuildInfo) Option {
	return func(c *config) { c.buildInfo = info }
}

// Server is the HTTP server.
type Server struct {
	cfg      config
	router   *chi.Mux
	indexTpl *template.Template
}

// New creates a new Server. All options have defaults and may be omitted.
func New(opts ...Option) (*Server, error) {
	cfg := config{
		timeout: defaultTimeout,
		logger:  httplog.NewLogger("cves"),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, fmt.Errorf("server: static fs: %w", err)
	}
	tpl, err := loadIndexTemplate(staticFS)
	if err != nil {
		return nil, fmt.Errorf("server: load index template: %w", err)
	}

	s := &Server{cfg: cfg, indexTpl: tpl}
	s.router = s.buildRouter()
	return s, nil
}

// Mount mounts a handler at the given pattern.
func (s *Server) Mount(pattern string, handler http.Handler) {
	s.router.Mount(pattern, handler)
}

// Listen serves HTTP on l and blocks until ctx is canceled, then shuts down gracefully.
func (s *Server) Listen(ctx context.Context, l net.Listener) error {
	compress, err := gzhttp.NewWrapper()
	if err != nil {
		return fmt.Errorf("gzhttp wrapper: %w", err)
	}

	srv := &http.Server{
		Handler:      compress(s.router),
		ReadTimeout:  s.cfg.timeout,
		WriteTimeout: s.cfg.timeout,
		BaseContext:  func(net.Listener) context.Context { return ctx },
		ErrorLog:     slog.NewLogLogger(s.cfg.logger.With("component", "http.Server").Handler(), slog.LevelError),
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		s.cfg.logger.Info("shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// buildRouter constructs the root chi router with shared middleware applied.
func (s *Server) buildRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.CleanPath)
	r.Use(middleware.RedirectSlashes)
	r.Use(httplog.Handler(s.cfg.logger))
	r.Use(middleware.Recoverer)

	r.Get("/", s.handleIndex)

	return r
}

// handleIndex renders the index page with all registered routes.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	type routeInfo struct {
		Method  string
		Pattern string
	}
	type data struct {
		Routes    []routeInfo
		BuildInfo BuildInfo
	}

	var routes []routeInfo
	if err := chi.Walk(s.router, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, routeInfo{Method: method, Pattern: pattern})
		return nil
	}); err != nil {
		slog.ErrorContext(r.Context(), "walk routes", "err", err)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.indexTpl.Execute(w, data{
		Routes:    routes,
		BuildInfo: s.cfg.buildInfo,
	}); err != nil {
		slog.ErrorContext(r.Context(), "render index", "err", err)
	}
}

// loadIndexTemplate reads and parses index.html from staticFS.
func loadIndexTemplate(staticFS fs.FS) (*template.Template, error) {
	b, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		return nil, err
	}
	return template.New("index").Parse(string(b))
}
