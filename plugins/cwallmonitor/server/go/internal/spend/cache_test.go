package spend

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingFetcher returns a fixed snapshot after a short delay and counts how
// many times it actually ran, so the test can assert single-flight collapses
// concurrent first-callers into one fetch.
type blockingFetcher struct {
	calls atomic.Int32
	delay time.Duration
	snap  Snapshot
}

func (b *blockingFetcher) Fetch(ctx context.Context, now time.Time) (Snapshot, error) {
	b.calls.Add(1)
	select {
	case <-time.After(b.delay):
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	}
	return b.snap, nil
}

// Regression test for the cache fan-out bug: the leader publishes its result
// and closes the in-flight channel to broadcast. A buffered one-shot send only
// reached ONE waiter; the rest read a closed channel and silently got a zero
// Snapshot (empty $0.00, nil error). All concurrent waiters must now receive
// the real snapshot exactly once.
func TestCacheBroadcastsToAllWaiters(t *testing.T) {
	f := &blockingFetcher{delay: 50 * time.Millisecond, snap: Snapshot{
		Currency: "USD", MonthUSD: 48.31, MonthTokens: 1700,
	}}
	c := NewCache(5*time.Minute, map[string]Fetcher{"claude": f})

	const N = 16
	var wg sync.WaitGroup
	results := make([]Snapshot, N)
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = c.Get(context.Background(), "claude")
		}(i)
	}
	wg.Wait()

	for i := 0; i < N; i++ {
		if errs[i] != nil {
			t.Fatalf("waiter %d: unexpected error %v", i, errs[i])
		}
		if results[i].MonthUSD != 48.31 || results[i].MonthTokens != 1700 {
			t.Fatalf("waiter %d got empty/zero snapshot %+v (fan-out regression)", i, results[i])
		}
	}
	if got := f.calls.Load(); got != 1 {
		t.Fatalf("fetch ran %d times, want 1 (single-flight collapse)", got)
	}
}
