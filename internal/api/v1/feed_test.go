package v1

import (
	"encoding/xml"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v70/github"
)

// rssDoc is a minimal RSS document structure for test assertions.
type rssDoc struct {
	Channel struct {
		Title string    `xml:"title"`
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	GUID        string `xml:"guid"`
}

func parseRSS(t *testing.T, s string) rssDoc {
	t.Helper()
	var doc rssDoc
	if err := xml.NewDecoder(strings.NewReader(s)).Decode(&doc); err != nil {
		t.Fatalf("xml.Decode() error = %v\nInput:\n%s", err, s)
	}
	return doc
}

func tsPtr(ts time.Time) *github.Timestamp {
	return &github.Timestamp{Time: ts}
}

func TestToRSS(t *testing.T) {
	t.Parallel()
	t1 := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 2, 20, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		owner         string
		repo          string
		advisories    []*github.SecurityAdvisory
		wantErr       bool
		wantItems     int
		wantChanTitle string
		checkItem     func(t *testing.T, items []rssItem)
	}{
		{
			name:          "empty advisory list produces valid feed",
			owner:         "owner",
			repo:          "repo",
			advisories:    nil,
			wantItems:     0,
			wantChanTitle: "owner/repo Security Advisories",
		},
		{
			name:  "single published advisory",
			owner: "golang",
			repo:  "go",
			advisories: []*github.SecurityAdvisory{
				{
					GHSAID:      new("GHSA-xxxx-yyyy-zzzz"),
					Summary:     new("Buffer overflow in net/http"),
					Description: new("A buffer overflow exists when parsing headers."),
					Severity:    new("high"),
					CVEID:       new("CVE-2024-0001"),
					HTMLURL:     new("https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"),
					State:       new("published"),
					PublishedAt: tsPtr(t1),
					UpdatedAt:   tsPtr(t2),
				},
			},
			wantItems:     1,
			wantChanTitle: "golang/go Security Advisories",
			checkItem: func(t *testing.T, items []rssItem) {
				item := items[0]
				if !strings.Contains(item.Title, "GHSA-xxxx-yyyy-zzzz") {
					t.Errorf("Title = %q, want to contain GHSA ID", item.Title)
				}
				if !strings.Contains(item.Title, "Buffer overflow in net/http") {
					t.Errorf("Title = %q, want to contain summary", item.Title)
				}
				if item.Link != "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz" {
					t.Errorf("Link = %q, want advisory URL", item.Link)
				}
				if !strings.Contains(item.Description, "buffer overflow") {
					t.Errorf("Description = %q, want to contain description text", item.Description)
				}
				if !strings.Contains(item.Description, "Severity: high") {
					t.Errorf("Description = %q, want severity", item.Description)
				}
				if !strings.Contains(item.Description, "CVE: CVE-2024-0001") {
					t.Errorf("Description = %q, want CVE ID", item.Description)
				}
				if item.GUID != "GHSA-xxxx-yyyy-zzzz" {
					t.Errorf("GUID = %q, want GHSA ID", item.GUID)
				}
			},
		},
		{
			name:  "advisory without summary falls back to GHSA ID",
			owner: "owner",
			repo:  "repo",
			advisories: []*github.SecurityAdvisory{
				{
					GHSAID:      new("GHSA-no-summary"),
					State:       new("published"),
					PublishedAt: tsPtr(t1),
				},
			},
			wantItems: 1,
			checkItem: func(t *testing.T, items []rssItem) {
				if items[0].Title != "GHSA-no-summary" {
					t.Errorf("Title = %q, want GHSA ID as fallback title", items[0].Title)
				}
			},
		},
		{
			name:  "advisory without timestamps uses zero time",
			owner: "owner",
			repo:  "repo",
			advisories: []*github.SecurityAdvisory{
				{
					GHSAID:  new("GHSA-no-time"),
					Summary: new("No timestamp advisory"),
					State:   new("published"),
				},
			},
			wantItems: 1,
		},
		{
			name:  "multiple published advisories all appear",
			owner: "owner",
			repo:  "repo",
			advisories: []*github.SecurityAdvisory{
				{GHSAID: new("GHSA-0001"), Summary: new("First"), State: new("published"), PublishedAt: tsPtr(t1)},
				{GHSAID: new("GHSA-0002"), Summary: new("Second"), State: new("published"), PublishedAt: tsPtr(t2)},
			},
			wantItems: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rss, err := toRSS(tt.owner, tt.repo, slices.Values(tt.advisories))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ToRSS() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if !strings.HasPrefix(strings.TrimSpace(rss), "<?xml") {
				t.Errorf("output does not start with XML declaration: %q", rss[:min(len(rss), 80)])
			}

			doc := parseRSS(t, rss)

			if tt.wantChanTitle != "" && doc.Channel.Title != tt.wantChanTitle {
				t.Errorf("channel title = %q, want %q", doc.Channel.Title, tt.wantChanTitle)
			}

			if len(doc.Channel.Items) != tt.wantItems {
				t.Errorf("item count = %d, want %d", len(doc.Channel.Items), tt.wantItems)
			}

			if tt.checkItem != nil && len(doc.Channel.Items) > 0 {
				tt.checkItem(t, doc.Channel.Items)
			}
		})
	}
}

func TestBuildTitle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		adv     *github.SecurityAdvisory
		wantStr string
	}{
		{
			name:    "both summary and GHSA ID",
			adv:     &github.SecurityAdvisory{GHSAID: new("GHSA-1234"), Summary: new("SQL injection")},
			wantStr: "[GHSA-1234] SQL injection",
		},
		{
			name:    "summary only",
			adv:     &github.SecurityAdvisory{Summary: new("SQL injection")},
			wantStr: "SQL injection",
		},
		{
			name:    "GHSA ID only",
			adv:     &github.SecurityAdvisory{GHSAID: new("GHSA-1234")},
			wantStr: "GHSA-1234",
		},
		{
			name:    "neither",
			adv:     &github.SecurityAdvisory{},
			wantStr: "Security Advisory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := title(tt.adv)
			if got != tt.wantStr {
				t.Errorf("buildTitle() = %q, want %q", got, tt.wantStr)
			}
		})
	}
}
