package cache

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func newTestCache(t *testing.T) *Cache[string] {
	t.Helper()
	c, err := New(
		t.TempDir(),
		func(s string) ([]byte, error) { return []byte(s), nil },
		func(b []byte) (string, error) { return string(b), nil },
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestCache_GetMiss(t *testing.T) {
	t.Parallel()
	c := newTestCache(t)

	val, ok, err := c.Get("missing")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if ok {
		t.Errorf("Get() ok = true, want false for missing key")
	}
	if val != "" {
		t.Errorf("Get() val = %q, want zero value for missing key", val)
	}
}

func TestCache_SetGet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "simple string", key: "foo", value: "bar"},
		{name: "empty value", key: "empty", value: ""},
		{name: "slash key", key: "owner/repo", value: "feed data"},
		{name: "multiline value", key: "multi", value: "line1\nline2\nline3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newTestCache(t)

			if err := c.Set(tt.key, tt.value, time.Minute); err != nil {
				t.Fatalf("Set() error = %v", err)
			}

			got, ok, err := c.Get(tt.key)
			if err != nil {
				t.Fatalf("Get() error = %v", err)
			}
			if !ok {
				t.Fatalf("Get() ok = false, want true after Set")
			}
			if got != tt.value {
				t.Errorf("Get() = %q, want %q", got, tt.value)
			}
		})
	}
}

func TestCache_Overwrite(t *testing.T) {
	t.Parallel()
	c := newTestCache(t)

	if err := c.Set("key", "first", time.Minute); err != nil {
		t.Fatalf("Set() first error = %v", err)
	}
	if err := c.Set("key", "second", time.Minute); err != nil {
		t.Fatalf("Set() second error = %v", err)
	}

	got, ok, err := c.Get("key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok {
		t.Fatalf("Get() ok = false")
	}
	if got != "second" {
		t.Errorf("Get() = %q, want %q", got, "second")
	}
}

func TestCache_WithLogger(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	c, err := New(
		t.TempDir(),
		func(s string) ([]byte, error) { return []byte(s), nil },
		func(b []byte) (string, error) { return string(b), nil },
		WithLogger(logger),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer c.Close()

	if !strings.Contains(buf.String(), "cache opened") {
		t.Errorf("logger not called on open; log output = %q", buf.String())
	}
}
