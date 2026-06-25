package buffer

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

func newTestBuffer(t *testing.T, maxMB int, maxAge time.Duration) *Buffer {
	t.Helper()
	dir := t.TempDir()
	buf, err := New(dir, maxMB, maxAge)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return buf
}

func TestBuffer_storeAndNext(t *testing.T) {
	buf := newTestBuffer(t, 10, time.Hour)

	if err := buf.Store(Entry{Kind: KindMetrics, Payload: []byte(`{"test":1}`)}); err != nil {
		t.Fatalf("Store: %v", err)
	}

	entry, err := buf.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if entry == nil {
		t.Fatal("want entry, got nil")
	}
	if entry.Kind != KindMetrics {
		t.Errorf("kind: want metrics, got %s", entry.Kind)
	}
}

func TestBuffer_ackRemovesEntry(t *testing.T) {
	buf := newTestBuffer(t, 10, time.Hour)
	buf.Store(Entry{Kind: KindMetrics, Payload: []byte(`{}`)})

	entry, _ := buf.Next()
	if err := entry.Ack(); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("want 0 after ack, got %d", buf.Len())
	}
}

func TestBuffer_nextKindFilters(t *testing.T) {
	buf := newTestBuffer(t, 10, time.Hour)
	buf.Store(Entry{Kind: KindMetrics, Payload: []byte(`{"m":1}`)})
	// ensure distinct timestamps
	time.Sleep(time.Millisecond)
	buf.Store(Entry{Kind: KindLogs, Payload: []byte(`{"l":1}`)})

	entry, err := buf.NextKind(KindLogs)
	if err != nil {
		t.Fatalf("NextKind: %v", err)
	}
	if entry == nil {
		t.Fatal("want logs entry, got nil")
	}
	if entry.Kind != KindLogs {
		t.Errorf("kind: want logs, got %s", entry.Kind)
	}
}

func TestBuffer_evictByAge(t *testing.T) {
	buf := newTestBuffer(t, 10, 1*time.Millisecond)
	buf.Store(Entry{Kind: KindMetrics, Payload: []byte(`{}`)})

	time.Sleep(5 * time.Millisecond)

	// Trigger eviction by storing a second entry.
	buf.Store(Entry{Kind: KindMetrics, Payload: []byte(`{}`)})

	// The buffer should contain only the new entry; the old one was evicted by age.
	// Allow for the possibility that both survived if timing is tight.
	if buf.Len() > 1 {
		t.Errorf("want ≤1 entry after age eviction, got %d", buf.Len())
	}
}

func TestBuffer_evictMetricsBeforeLogs(t *testing.T) {
	buf := newTestBuffer(t, 0, time.Hour)
	// Payloads: logs=13B, metrics=12B, logs2=14B → total=39B.
	// Cap at 30B: after adding all three, eviction fires and must remove
	// the metrics entry (oldest by kind-priority) before touching logs.
	buf.maxBytes = 30

	buf.Store(Entry{Kind: KindLogs, Payload: []byte(`{"logs":true}`)})
	time.Sleep(time.Millisecond)
	buf.Store(Entry{Kind: KindMetrics, Payload: []byte(`{"cpu":99.0}`)})
	time.Sleep(time.Millisecond)
	buf.Store(Entry{Kind: KindLogs, Payload: []byte(`{"logs2":true}`)})

	// Metrics must be evicted first; both log entries should survive.
	entry, _ := buf.NextKind(KindMetrics)
	if entry != nil {
		t.Error("expected metrics entry to be evicted first, but it still exists")
	}
	if buf.Len() != 2 {
		t.Errorf("expected 2 log entries to survive, got %d", buf.Len())
	}
}

func TestBuffer_lenEmpty(t *testing.T) {
	buf := newTestBuffer(t, 10, time.Hour)
	if buf.Len() != 0 {
		t.Errorf("want 0, got %d", buf.Len())
	}
}

func TestBuffer_multipleStoreOrderPreserved(t *testing.T) {
	buf := newTestBuffer(t, 10, time.Hour)
	for i := range 5 {
		buf.Store(Entry{Kind: KindMetrics, Payload: fmt.Appendf(nil, `{"i":%d}`, i)})
		time.Sleep(time.Millisecond) // ensure distinct timestamps
	}
	if buf.Len() != 5 {
		t.Fatalf("want 5 entries, got %d", buf.Len())
	}

	// Next should return oldest first.
	first, _ := buf.Next()
	if string(first.Payload) != `{"i":0}` {
		t.Errorf("oldest-first violation: got %s", first.Payload)
	}
}

// TestBuffer_diskFullDropsBatch verifies that a Store failure returns an error
// without panicking so the push loop can drop the batch and log a warning.
// Skipped on Windows (chmod semantics differ) and when running as root.
func TestBuffer_diskFullDropsBatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission test not reliable on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("cannot test permission restriction as root")
	}
	buf := newTestBuffer(t, 10, time.Hour)
	os.Chmod(buf.dir, 0o500)
	defer os.Chmod(buf.dir, 0o700)

	err := buf.Store(Entry{Kind: KindMetrics, Payload: []byte(`{}`)})
	if err == nil {
		t.Error("want error when buffer dir is unwritable, got nil")
	}
}