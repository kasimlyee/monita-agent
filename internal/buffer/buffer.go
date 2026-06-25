// Package buffer provides a durable on-disk queue for pending batches.
//
// Each pending batch is written as an atomic rename into a directory as a
// separate file: {unix_nano}_{kind}.pending. Delivery acks remove the file.
// Eviction evicts oldest metrics first, logs only as a last resort.
package buffer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Kind string

const (
	KindMetrics Kind = "metrics"
	KindLogs    Kind = "logs"
)

type Entry struct {
	Kind    Kind
	Payload []byte // JSON-encoded batch body (pre-compression)
}

// Buffer is a thread-safe file-per-batch durable queue.
type Buffer struct {
	dir       string
	maxBytes  int64
	maxAge    time.Duration
	mu        sync.Mutex
}

func New(dir string, maxSizeMB int, maxAge time.Duration) (*Buffer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create buffer dir: %w", err)
	}
	return &Buffer{
		dir:      dir,
		maxBytes: int64(maxSizeMB) * 1024 * 1024,
		maxAge:   maxAge,
	}, nil
}

// Store writes a batch durably via temp-file + rename (crash-safe).
// It then runs eviction to enforce size and age limits.
func (b *Buffer) Store(e Entry) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	name := fmt.Sprintf("%d_%s.pending", time.Now().UnixNano(), string(e.Kind))
	tmp := filepath.Join(b.dir, name+".tmp")
	dst := filepath.Join(b.dir, name)

	if err := os.WriteFile(tmp, e.Payload, 0o600); err != nil {
		return fmt.Errorf("write buffer tmp: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename buffer file: %w", err)
	}

	b.evict()
	return nil
}

// PendingEntry holds a batch read from disk. Call Ack to delete it after
// successful delivery, or simply drop the value to leave it for the next Run.
type PendingEntry struct {
	Kind    Kind
	Payload []byte

	buf  *Buffer
	name string
}

func (p *PendingEntry) Ack() error {
	return os.Remove(filepath.Join(p.buf.dir, p.name))
}

// Next returns the oldest pending entry regardless of kind, or nil if empty.
func (b *Buffer) Next() (*PendingEntry, error) {
	return b.nextWhere(func(Kind) bool { return true })
}

// NextKind returns the oldest pending entry of the given kind, or nil if none.
func (b *Buffer) NextKind(kind Kind) (*PendingEntry, error) {
	return b.nextWhere(func(k Kind) bool { return k == kind })
}

func (b *Buffer) nextWhere(match func(Kind) bool) (*PendingEntry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	files, err := b.list()
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if !match(f.kind) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(b.dir, f.name))
		if err != nil {
			return nil, fmt.Errorf("read buffer entry: %w", err)
		}
		return &PendingEntry{buf: b, name: f.name, Kind: f.kind, Payload: data}, nil
	}
	return nil, nil
}

// Len returns the number of pending entries.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	files, _ := b.list()
	return len(files)
}

type fileRecord struct {
	name   string
	kind   Kind
	tsNano int64
	size   int64
}

// list returns .pending files sorted oldest-first. Must be called with mu held.
func (b *Buffer) list() ([]fileRecord, error) {
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		return nil, fmt.Errorf("read buffer dir: %w", err)
	}

	var records []fileRecord
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pending") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		// filename: {tsNano}_{kind}.pending
		stem := strings.TrimSuffix(e.Name(), ".pending")
		tsStr, kindStr, ok := strings.Cut(stem, "_")
		if !ok {
			continue
		}
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			continue
		}
		records = append(records, fileRecord{
			name:   e.Name(),
			kind:   Kind(kindStr),
			tsNano: ts,
			size:   info.Size(),
		})
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].tsNano < records[j].tsNano
	})
	return records, nil
}

// evict enforces age and size limits. Must be called with mu held.
// Age eviction removes any file older than maxAge regardless of kind.
// Size eviction targets oldest metrics first, then logs as a last resort.
func (b *Buffer) evict() {
	records, err := b.list()
	if err != nil || len(records) == 0 {
		return
	}

	now := time.Now()

	// Age pass.
	for _, r := range records {
		if now.Sub(time.Unix(0, r.tsNano)) > b.maxAge {
			if err := os.Remove(filepath.Join(b.dir, r.name)); err == nil {
				fmt.Fprintf(os.Stderr, "level=info msg=\"buffer evict (age)\" file=%q\n", r.name)
			}
		}
	}

	// Re-read after age eviction then apply size limit.
	records, err = b.list()
	if err != nil {
		return
	}

	var total int64
	for _, r := range records {
		total += r.size
	}
	if total <= b.maxBytes {
		return
	}

	// Evict oldest metrics first.
	for _, r := range records {
		if total <= b.maxBytes {
			return
		}
		if r.kind == KindMetrics {
			if err := os.Remove(filepath.Join(b.dir, r.name)); err == nil {
				total -= r.size
				fmt.Fprintf(os.Stderr, "level=warn msg=\"buffer evict (size, metrics)\" file=%q\n", r.name)
			}
		}
	}

	// Fall back to evicting logs.
	for _, r := range records {
		if total <= b.maxBytes {
			return
		}
		if r.kind == KindLogs {
			if err := os.Remove(filepath.Join(b.dir, r.name)); err == nil {
				total -= r.size
				fmt.Fprintf(os.Stderr, "level=warn msg=\"buffer evict (size, logs)\" file=%q\n", r.name)
			}
		}
	}
}