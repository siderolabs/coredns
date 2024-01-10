package cache

import (
	"fmt"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/cache"
)

// NewCache returns a new cache with the given options.
func NewCache(zonesMetricLabel string, viewMetricLabel string, opt ...Opt) *Cache {
	c := New()

	for _, o := range opt {
		o(c)
	}

	c.zonesMetricLabel = zonesMetricLabel
	c.viewMetricLabel = viewMetricLabel

	return c
}

// WithStale configures the stale serve settings for the cache. when StaleUpTo is set,
// cache will always serve an expired entry to a client if there is one available as long as it has not been expired
// for longer than duration (values of 1 hour and more are allowed).
//
// verifyStale will first verify that an entry is still unavailable from the source before sending the expired entry
// to the client. If it's false, will immediately send the expired entry to the client before checking to see if
// the entry is available from the source.
func WithStale(staleUpTo time.Duration, verifyStale bool) func(*Cache) {
	if staleUpTo < time.Hour {
		panic("staleUpTo must be at least 1 hour")
	}

	return func(c *Cache) {
		c.staleUpTo = staleUpTo
		c.verifyStale = verifyStale
	}
}

// WithZones configures zones it should cache for.
func WithZones(zones ...string) func(*Cache) {
	return func(c *Cache) {
		c.Zones = zones
	}
}

// WithCacheSize configures the size of the cache.
func WithCacheSize(size int) func(*Cache) {
	return func(c *Cache) {
		c.ncap = size
		c.ncache = cache.New(size)
		c.pcap = size
		c.pcache = cache.New(size)
	}
}

// WithTTL configures the TTL for the cache.
func WithTTL(ttl time.Duration) func(*Cache) {
	if ttl <= 0 {
		panic("TTL must be greater than 0")
	}

	return func(c *Cache) {
		c.nttl = ttl
		c.pttl = ttl
	}
}

// WithMinTTL configures the minimum TTL for the cache.
func WithMinTTL(ttl time.Duration) func(*Cache) {
	if ttl < 0 {
		panic("TTL must be greater than or equal to 0")
	}

	return func(c *Cache) {
		c.minnttl = ttl
		c.minpttl = ttl
	}
}

// WithSERVFAILTTL configures the TTL for SERVFAIL responses.
func WithSERVFAILTTL(ttl time.Duration) func(*Cache) {
	if ttl > 5*time.Minute {
		panic("SERVFAIL TTL must be less than 5 minutes")
	}

	return func(c *Cache) {
		c.failttl = ttl
	}
}

// WithPrefetch configures the prefetch settings for the cache.
// `prefetch` will prefetch popular items when they are about to be expunged from the cache.
// Popular means `prefetchAmount` queries have been seen with no gaps of `duration` or more between them.
// `duration` (no less than 1 minute). Prefetching will happen when the TTL drops below `percentage`,
// or latest 1 second before TTL expiration. Values should be in the range `[10, 90]`.
func WithPrefetch(prefetchAmount int, duration time.Duration, percentage int) func(*Cache) {
	if prefetchAmount < 0 {
		panic("prefetch must be greater than or equal to 0")
	}

	if percentage < 0 || percentage > 100 {
		panic(fmt.Errorf("percentage should fall in range [10, 90]: %d", percentage))
	}

	return func(c *Cache) {
		c.prefetch = prefetchAmount
		c.duration = duration
		c.percentage = percentage
	}
}

// Opt is a functional option for configuring the cache.
type Opt func(*Cache)

// Validate that [Cache] still has the same fields as we expect.
var _ = (*struct {
	Next  plugin.Handler
	Zones []string

	zonesMetricLabel string
	viewMetricLabel  string

	ncache  *cache.Cache
	ncap    int
	nttl    time.Duration
	minnttl time.Duration

	pcache  *cache.Cache
	pcap    int
	pttl    time.Duration
	minpttl time.Duration
	failttl time.Duration // TTL for caching SERVFAIL responses

	// Prefetch.
	prefetch   int
	duration   time.Duration
	percentage int

	// Stale serve
	staleUpTo   time.Duration
	verifyStale bool

	// Positive/negative zone exceptions
	pexcept []string
	nexcept []string

	// Keep ttl option
	keepttl bool

	// Testing.
	now func() time.Time
})((*Cache)(nil))
