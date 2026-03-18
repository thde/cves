package cachecontrol

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  Header
	}{
		{
			name:  "empty",
			input: "",
			want:  Header{},
		},
		{
			name:  "max-age only",
			input: "max-age=3600",
			want:  Header{MaxAge: time.Hour},
		},
		{
			name:  "public with max-age",
			input: "public, max-age=60",
			want:  Header{Public: true, MaxAge: 60 * time.Second},
		},
		{
			name:  "private",
			input: "private, max-age=0",
			want:  Header{Private: true, MaxAge: 0},
		},
		{
			name:  "no-store",
			input: "no-store",
			want:  Header{NoStore: true},
		},
		{
			name:  "all directives",
			input: "public, no-store, max-age=120",
			want:  Header{Public: true, NoStore: true, MaxAge: 120 * time.Second},
		},
		{
			name:  "extra whitespace",
			input: "  public ,  max-age=30  ",
			want:  Header{Public: true, MaxAge: 30 * time.Second},
		},
		{
			name:  "negative max-age is ignored",
			input: "max-age=-1",
			want:  Header{},
		},
		{
			name:  "malformed max-age is ignored",
			input: "max-age=abc",
			want:  Header{},
		},
		{
			name:  "unknown directives are ignored",
			input: "no-cache, must-revalidate, max-age=300",
			want:  Header{MaxAge: 300 * time.Second},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Parse(tt.input)
			if got != tt.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input Header
		want  string
	}{
		{
			name:  "zero value",
			input: Header{},
			want:  "",
		},
		{
			name:  "public with max-age",
			input: Header{Public: true, MaxAge: time.Hour},
			want:  "public, max-age=3600",
		},
		{
			name:  "private",
			input: Header{Private: true},
			want:  "private",
		},
		{
			name:  "no-store",
			input: Header{NoStore: true},
			want:  "no-store",
		},
		{
			name:  "max-age only",
			input: Header{MaxAge: 30 * time.Second},
			want:  "max-age=30",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.input.Format()
			if got != tt.want {
				t.Errorf("Header.Format() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseFormatRoundtrip(t *testing.T) {
	t.Parallel()
	tests := []string{
		"public, max-age=3600",
		"private",
		"no-store",
		"public, no-store, max-age=60",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got := Parse(input).Format()
			if got != input {
				t.Errorf("roundtrip: Parse(%q).Format() = %q", input, got)
			}
		})
	}
}
