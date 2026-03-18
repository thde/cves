// Package v1 implements the v1 API routes for the CVE RSS bridge.
package v1

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"iter"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/elnormous/contenttype"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/go-github/v70/github"
	"github.com/thde/cves/internal/cache"
	"github.com/thde/cves/internal/cachecontrol"
	"github.com/yuin/goldmark"
)

//go:embed static
var staticFiles embed.FS

// severities is the ordered list of all valid severity levels.
var severities = []string{"critical", "high", "medium", "low"}

var availableMediaTypes = []contenttype.MediaType{
	contenttype.NewMediaType("application/rss+xml"),
	contenttype.NewMediaType("text/html"),
}

// Option configures an API.
type Option func(*API)

// WithLogger sets the request [slog.Logger]. Defaults to a discard logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *API) { c.logger = logger }
}

// WithCache configures the advisory cache.
func WithCache(cache *cache.Cache[[]*github.SecurityAdvisory]) Option {
	return func(c *API) { c.cache = cache }
}

// WithGitHubClient sets the GitHub API client.
func WithGitHubClient(gh *github.Client) Option {
	return func(c *API) { c.gh = gh }
}

// WithMinCacheTTL sets the minimum cache TTL.
func WithMinCacheTTL(minCacheTTL time.Duration) Option {
	return func(c *API) { c.minCacheTTL = minCacheTTL }
}

// API handles v1 route logic, including the GitHub security advisory feed endpoint.
type API struct {
	logger      *slog.Logger
	cache       *cache.Cache[[]*github.SecurityAdvisory]
	minCacheTTL time.Duration
	gh          *github.Client
	tpl         *template.Template
}

// Handler returns an [http.Handler] with all v1 routes registered.
func (s *API) Handler() http.Handler {
	r := chi.NewMux()

	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.URLFormat)

	r.Get("/github/{owner}/{repo}", s.handleFeed)

	return r
}

// New creates a new API. When no [WithGitHubClient] option is provided an
// unauthenticated client is used. When no [WithCache] option is provided a
// temporary on-disk cache is created automatically.
func New(opts ...Option) (*API, error) {
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, fmt.Errorf("static fs: %w", err)
	}
	tpl, err := loadTemplate(staticFS)
	if err != nil {
		return nil, fmt.Errorf("load template: %w", err)
	}

	api := &API{
		logger:      slog.New(slog.DiscardHandler),
		minCacheTTL: 1 * time.Hour,
		tpl:         tpl,
	}
	for _, opt := range opts {
		opt(api)
	}

	if api.gh == nil {
		api.gh = github.NewClient(nil)
	}
	if api.cache == nil {
		cacheDir, err := os.MkdirTemp("", "")
		if err != nil {
			return nil, fmt.Errorf("create cache dir: %w", err)
		}

		c, err := cache.New(
			cacheDir,
			func(v []*github.SecurityAdvisory) ([]byte, error) { return json.Marshal(v) },
			func(b []byte) ([]*github.SecurityAdvisory, error) {
				var v []*github.SecurityAdvisory
				return v, json.Unmarshal(b, &v)
			},
			cache.WithLogger(api.logger.With("component", "cache")),
		)
		if err != nil {
			return nil, fmt.Errorf("create cache: %w", err)
		}
		api.cache = c
	}

	return api, nil
}

// handleFeed fetches GitHub security advisories and serves them as RSS or HTML
// depending on the request's Accept header. RSS is the default.
func (s *API) handleFeed(w http.ResponseWriter, r *http.Request) {
	owner := chi.URLParam(r, "owner")
	repo := chi.URLParam(r, "repo")
	cacheKey := "feed:" + owner + "/" + repo

	mt, _, err := contenttype.GetAcceptableMediaType(r, availableMediaTypes)
	if err != nil {
		http.Error(w, "not acceptable", http.StatusNotAcceptable)
		return
	}

	var versionFilter *semver.Version
	if vStr := r.URL.Query().Get("v"); vStr != "" {
		versionFilter, err = semver.NewVersion(vStr)
		if err != nil {
			http.Error(w, "invalid version: use semver format e.g. 2.3.4", http.StatusBadRequest)
			return
		}
	}

	severityFilter := r.URL.Query()["severity"]
	for _, sf := range severityFilter {
		if !slices.Contains(severities, sf) {
			http.Error(w, fmt.Sprintf("invalid severity: must be one of %s", strings.Join(severities, ", ")), http.StatusBadRequest)
			return
		}
	}

	var advisories []*github.SecurityAdvisory
	ttl := s.minCacheTTL
	fromCache := false

	if s.cache != nil {
		if cached, ok, err := s.cache.Get(cacheKey); err != nil {
			s.logger.ErrorContext(r.Context(), "cache get", "err", err)
		} else if ok {
			advisories = cached
			fromCache = true
		}
	}

	if !fromCache {
		var ghResp *github.Response
		advisories, ghResp, err = s.gh.SecurityAdvisories.ListRepositorySecurityAdvisories(
			r.Context(),
			owner,
			repo,
			&github.ListRepositorySecurityAdvisoriesOptions{
				State:     "published",
				Sort:      "published",
				Direction: "desc",
				ListCursorOptions: github.ListCursorOptions{
					PerPage: 100,
				},
			},
		)
		if err != nil {
			s.handleGitHubError(w, r, err)
			return
		}

		if ghResp != nil {
			if cc := cachecontrol.Parse(ghResp.Header.Get("Cache-Control")); cc.MaxAge > 0 {
				ttl = max(cc.MaxAge, s.minCacheTTL)
			}
		}

		if s.cache != nil {
			if err := s.cache.Set(cacheKey, advisories, ttl); err != nil {
				s.logger.WarnContext(r.Context(), "cache set", "err", err)
			}
		}
	}

	seq := slices.Values(advisories)
	if versionFilter != nil {
		seq = s.filterByVersion(seq, versionFilter)
	}
	if len(severityFilter) > 0 {
		seq = filterBySeverity(seq, severityFilter)
	}

	xCache := "MISS"
	if fromCache {
		xCache = "HIT"
	}
	w.Header().Set("Cache-Control", cachecontrol.Header{Public: true, MaxAge: ttl}.Format())
	w.Header().Set("Vary", "Accept")
	w.Header().Set("X-Cache", xCache)

	if mt.Equal(contenttype.NewMediaType("text/html")) {
		s.renderHTML(w, r, owner, repo, seq, versionFilter, severityFilter)
	} else {
		s.renderRSS(w, r, owner, repo, seq)
	}
}

// filterByVersion returns an iterator over advisories where at least one
// vulnerability's version range includes v.
func (s *API) filterByVersion(seq iter.Seq[*github.SecurityAdvisory], v *semver.Version) iter.Seq[*github.SecurityAdvisory] {
	return func(yield func(*github.SecurityAdvisory) bool) {
		for adv := range seq {
			for _, vuln := range adv.Vulnerabilities {
				for r := range strings.SplitSeq(vuln.GetVulnerableVersionRange(), ",") {
					r = strings.TrimSpace(r)
					r = strings.ToLower(r)

					// Sometimes version ranges are not in semver format, so we try to normalize them:
					r = strings.ReplaceAll(r, "through", "-")               // 0.7.0 through 2.1.14 -> 0.7.0 - 2.1.14
					r = strings.ReplaceAll(r, "all versions prior to", "<") // all versions prior to 1.7.14 -> <1.7.14
					r = strings.ReplaceAll(r, "all versions until", "<=")   // all versions until 2.11.0 -> <=2.11.0
					r = strings.ReplaceAll(r, "all versions", "*")          // all versions -> *

					c, err := semver.NewConstraint(r)
					if err != nil {
						s.logger.Warn("parse version range", "range", r, "err", err)
						continue
					}

					if c.Check(v) && !isPatchedFor(vuln.GetPatchedVersions(), v) {
						if !yield(adv) {
							return
						}
						break
					}
				}
			}
		}
	}
}

// filterBySeverity returns an iterator over advisories whose severity matches any of the given values.
func filterBySeverity(seq iter.Seq[*github.SecurityAdvisory], severities []string) iter.Seq[*github.SecurityAdvisory] {
	set := make(map[string]bool, len(severities))
	for _, s := range severities {
		set[s] = true
	}
	return func(yield func(*github.SecurityAdvisory) bool) {
		for adv := range seq {
			if set[adv.GetSeverity()] {
				if !yield(adv) {
					return
				}
			}
		}
	}
}

// isPatchedFor reports whether v is >= any patched version in the
// comma-separated patchedVersions string, indicating the vulnerability is fixed.
func isPatchedFor(patchedVersions string, v *semver.Version) bool {
	for pv := range strings.SplitSeq(patchedVersions, ",") {
		pv = strings.TrimSpace(pv)
		if pv == "" {
			continue
		}
		parsed, err := semver.NewVersion(pv)
		if err != nil {
			continue
		}
		if v.GreaterThanEqual(parsed) {
			return true
		}
	}
	return false
}

// renderRSS writes the advisories as an RSS 2.0 feed.
func (s *API) renderRSS(w http.ResponseWriter, r *http.Request, owner, repo string, advisories iter.Seq[*github.SecurityAdvisory]) {
	rss, err := toRSS(owner, repo, advisories)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "build feed", "owner", owner, "repo", repo, "err", err)
		http.Error(w, "failed to build feed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	w.Write([]byte(rss)) //nolint:errcheck
}

// renderHTML writes the advisories as an HTML page.
func (s *API) renderHTML(w http.ResponseWriter, r *http.Request, owner, repo string, advisories iter.Seq[*github.SecurityAdvisory], versionFilter *semver.Version, severityFilter []string) {
	type data struct {
		Owner          string
		Repo           string
		Advisories     iter.Seq[*github.SecurityAdvisory]
		Severities     []string
		VersionFilter  string
		SeverityFilter []string
	}
	var versionStr string
	if versionFilter != nil {
		versionStr = versionFilter.Original()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.Execute(w, data{Owner: owner, Repo: repo, Advisories: advisories, Severities: severities, VersionFilter: versionStr, SeverityFilter: severityFilter}); err != nil {
		s.logger.ErrorContext(r.Context(), "render html", "owner", owner, "repo", repo, "err", err)
	}
}

// handleGitHubError maps GitHub API errors to appropriate HTTP responses.
func (s *API) handleGitHubError(w http.ResponseWriter, r *http.Request, err error) {
	if ghErr, ok := errors.AsType[*github.ErrorResponse](err); ok {
		switch ghErr.Response.StatusCode {
		case http.StatusNotFound:
			http.Error(w, "repository or advisories not found", http.StatusNotFound)
			return
		case http.StatusUnauthorized, http.StatusForbidden:
			s.logger.WarnContext(r.Context(), "github auth error", "err", err)
			http.Error(w, "GitHub API authorization error", http.StatusForbidden)
			return
		}
	}
	s.logger.ErrorContext(r.Context(), "github API error", "err", err)
	http.Error(w, "GitHub API request failed", http.StatusBadGateway)
}

// loadTemplate parses the advisories HTML template from staticFS.
func loadTemplate(staticFS fs.FS) (*template.Template, error) {
	b, err := fs.ReadFile(staticFS, "advisories.html")
	if err != nil {
		return nil, err
	}
	return template.New("advisories").Funcs(template.FuncMap{
		"deref": func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		},
		"title": title,
		"published": func(ts *github.Timestamp) string {
			if ts == nil {
				return ""
			}
			return ts.Format("2006-01-02")
		},
		"splitVersions": func(s string) []string {
			var versions []string
			for v := range strings.SplitSeq(s, ",") {
				if v = strings.TrimSpace(v); v != "" {
					versions = append(versions, v)
				}
			}
			return versions
		},
		"hasSeverity": func(filters []string, s string) bool {
			return slices.Contains(filters, s)
		},
		"capitalize": func(s string) string {
			if s == "" {
				return ""
			}
			return strings.ToUpper(s[:1]) + s[1:]
		},
		"markdown": func(s string) template.HTML {
			var buf bytes.Buffer
			if err := goldmark.Convert([]byte(s), &buf); err != nil {
				return template.HTML(template.HTMLEscapeString(s))
			}
			return template.HTML(buf.String())
		},
	}).Parse(string(b))
}
