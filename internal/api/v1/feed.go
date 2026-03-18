package v1

import (
	"fmt"
	"iter"
	"strings"
	"time"

	"github.com/google/go-github/v70/github"
	"github.com/gorilla/feeds"
)

// toRSS converts a sequence of GitHub security advisories into an RSS 2.0 feed string.
func toRSS(owner, repo string, advisories iter.Seq[*github.SecurityAdvisory]) (string, error) {
	feedURL := fmt.Sprintf("https://github.com/%s/%s/security/advisories", owner, repo)

	f := &feeds.Feed{
		Title:       fmt.Sprintf("%s/%s Security Advisories", owner, repo),
		Link:        &feeds.Link{Href: feedURL},
		Description: fmt.Sprintf("GitHub Security Advisories for %s/%s", owner, repo),
		Author:      &feeds.Author{Name: "cves"},
		Updated:     time.Now(),
	}

	for adv := range advisories {
		f.Items = append(f.Items, advisoryToItem(adv))
	}

	return f.ToRss()
}

// advisoryToItem converts a single SecurityAdvisory into a feed Item.
func advisoryToItem(adv *github.SecurityAdvisory) *feeds.Item {
	title := title(adv)

	var sb strings.Builder
	if desc := adv.GetDescription(); desc != "" {
		sb.WriteString(desc)
		sb.WriteString("\n\n")
	}
	if sev := adv.GetSeverity(); sev != "" {
		fmt.Fprintf(&sb, "Severity: %s\n", sev)
	}
	if cve := adv.GetCVEID(); cve != "" {
		fmt.Fprintf(&sb, "CVE: %s\n", cve)
	}

	published := itemTime(adv.PublishedAt, adv.CreatedAt)
	updated := itemTime(adv.UpdatedAt, adv.PublishedAt)

	return &feeds.Item{
		Id:          adv.GetGHSAID(),
		Title:       title,
		Link:        &feeds.Link{Href: adv.GetHTMLURL()},
		Description: sb.String(),
		Created:     published,
		Updated:     updated,
	}
}

// title returns a "[GHSA-id] summary" string, falling back gracefully when
// either the GHSA ID or summary is absent.
func title(adv *github.SecurityAdvisory) string {
	summary := adv.GetSummary()
	ghsaID := adv.GetGHSAID()

	switch {
	case summary != "" && ghsaID != "":
		return fmt.Sprintf("[%s] %s", ghsaID, summary)
	case summary != "":
		return summary
	case ghsaID != "":
		return ghsaID
	default:
		return "Security Advisory"
	}
}

// itemTime returns the time from the first non-nil timestamp, falling back to the second.
func itemTime(primary, fallback *github.Timestamp) time.Time {
	if primary != nil {
		return primary.Time
	}
	if fallback != nil {
		return fallback.Time
	}
	return time.Time{}
}
