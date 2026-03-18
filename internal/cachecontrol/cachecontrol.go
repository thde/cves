// Package cachecontrol parses HTTP Cache-Control header values.
package cachecontrol

import (
	"strconv"
	"strings"
	"time"
)

// Directive constants for well-known Cache-Control tokens.
const (
	DirectivePublic  = "public"
	DirectivePrivate = "private"
	DirectiveNoStore = "no-store"
	DirectiveMaxAge  = "max-age"
)

// Header represents the directives parsed from a Cache-Control header value.
type Header struct {
	// MaxAge is the value of the max-age directive. Zero if absent.
	MaxAge time.Duration
	// Public reports whether the public directive is present.
	Public bool
	// Private reports whether the private directive is present.
	Private bool
	// NoStore reports whether the no-store directive is present.
	NoStore bool
}

// Parse parses a Cache-Control header value into a [Header].
// Unrecognised directives are silently ignored.
func Parse(header string) Header {
	var h Header
	for part := range strings.SplitSeq(header, ",") {
		part = strings.TrimSpace(part)
		switch part {
		case DirectivePublic:
			h.Public = true
		case DirectivePrivate:
			h.Private = true
		case DirectiveNoStore:
			h.NoStore = true
		default:
			if s, ok := strings.CutPrefix(part, DirectiveMaxAge+"="); ok {
				if n, err := strconv.Atoi(s); err == nil && n >= 0 {
					h.MaxAge = time.Duration(n) * time.Second
				}
			}
		}
	}
	return h
}

// Format returns a Cache-Control header value for h.
// Only directives with non-zero / true values are included.
func (h Header) Format() string {
	var parts []string
	if h.Public {
		parts = append(parts, DirectivePublic)
	}
	if h.Private {
		parts = append(parts, DirectivePrivate)
	}
	if h.NoStore {
		parts = append(parts, DirectiveNoStore)
	}
	if h.MaxAge > 0 {
		parts = append(parts, DirectiveMaxAge+"="+strconv.Itoa(int(h.MaxAge.Seconds())))
	}
	return strings.Join(parts, ", ")
}
