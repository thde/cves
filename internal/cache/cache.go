// Package cache provides a generic, TTL-aware key-value store backed by Badger.
package cache

import (
	"errors"
	"log/slog"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
)

// slogLogger satisfies [badger.Logger].
type slogLogger struct {
	*slog.Logger
}

func (l slogLogger) Errorf(string, ...any)   {}
func (l slogLogger) Warningf(string, ...any) {}
func (l slogLogger) Infof(string, ...any)    {}
func (l slogLogger) Debugf(string, ...any)   {}

// conf holds non-generic configuration applied via the conf pattern.
type conf struct {
	log *slog.Logger
}

// Option configures a Cache.
type Option func(*conf)

// WithLogger sets the slog.Logger used for cache diagnostics.
// Defaults to slog.Default() when not provided.
func WithLogger(logger *slog.Logger) Option {
	return func(o *conf) { o.log = logger }
}

// Cache is a generic key-value store backed by Badger with TTL support.
// V is the value type; encode and decode handle serialization to/from []byte.
type Cache[V any] struct {
	db     *badger.DB
	encode func(V) ([]byte, error)
	decode func([]byte) (V, error)
	log    *slog.Logger
}

// New opens (or creates) a Badger database at path.
// encode and decode serialize and deserialize values of type V.
func New[V any](path string, encode func(V) ([]byte, error), decode func([]byte) (V, error), opts ...Option) (*Cache[V], error) {
	o := &conf{log: slog.New(slog.DiscardHandler)}
	for _, opt := range opts {
		opt(o)
	}

	db, err := badger.Open(badger.DefaultOptions(path).WithLogger(slogLogger{o.log}).WithCompression(options.ZSTD))
	if err != nil {
		return nil, err
	}

	o.log.Debug("cache opened", "path", path)
	return &Cache[V]{db: db, encode: encode, decode: decode, log: o.log}, nil
}

// Get retrieves a value by key. Returns the zero value of V and false when the key is not found.
func (c *Cache[V]) Get(key string) (V, bool, error) {
	var raw []byte
	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		raw, err = item.ValueCopy(nil)
		return err
	})

	var zero V
	if errors.Is(err, badger.ErrKeyNotFound) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}

	val, err := c.decode(raw)
	if err != nil {
		return zero, false, err
	}
	return val, true, nil
}

// Set stores val under key with the given TTL.
func (c *Cache[V]) Set(key string, val V, ttl time.Duration) error {
	raw, err := c.encode(val)
	if err != nil {
		return err
	}
	return c.db.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(badger.NewEntry([]byte(key), raw).WithTTL(ttl))
	})
}

// Close closes the underlying database.
func (c *Cache[V]) Close() error {
	return c.db.Close()
}
