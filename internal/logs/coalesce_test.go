package logs

import (
	"testing"
)

func TestCoalescer_distinctEntries(t *testing.T) {
	var c Coalescer
	c.Add(entry("src1", "msg A"))
	c.Add(entry("src1", "msg B"))
	c.Add(entry("src2", "msg A"))

	got := c.Flush()
	if len(got) != 3 {
		t.Fatalf("want 3 distinct entries, got %d", len(got))
	}
	for _, e := range got {
		if e.Count != 1 {
			t.Errorf("entry %q count: want 1, got %d", e.Message, e.Count)
		}
	}
}

func TestCoalescer_consecutiveDuplicatesMerged(t *testing.T) {
	var c Coalescer
	c.Add(entry("src", "crash: connection refused"))
	c.Add(entry("src", "crash: connection refused"))
	c.Add(entry("src", "crash: connection refused"))

	got := c.Flush()
	if len(got) != 1 {
		t.Fatalf("want 1 coalesced entry, got %d", len(got))
	}
	if got[0].Count != 3 {
		t.Errorf("want count=3, got %d", got[0].Count)
	}
}

// Non-consecutive identical entries must NOT be merged (A B A → 3 entries, not 2).
func TestCoalescer_nonConsecutiveNotMerged(t *testing.T) {
	var c Coalescer
	c.Add(entry("src", "A"))
	c.Add(entry("src", "B"))
	c.Add(entry("src", "A"))

	got := c.Flush()
	if len(got) != 3 {
		t.Fatalf("want 3 entries, got %d: %v", len(got), got)
	}
}

func TestCoalescer_flushResetsState(t *testing.T) {
	var c Coalescer
	c.Add(entry("src", "hello"))
	c.Flush()

	// Second flush of the same message must NOT inherit the previous key.
	c.Add(entry("src", "hello"))
	c.Add(entry("src", "hello"))
	got := c.Flush()
	if len(got) != 1 {
		t.Fatalf("want 1 entry after flush reset, got %d", len(got))
	}
	if got[0].Count != 2 {
		t.Errorf("want count=2, got %d", got[0].Count)
	}
}

func TestCoalescer_firstSeenLastSeenTracked(t *testing.T) {
	var c Coalescer
	e1 := entry("src", "msg")
	e1.FirstSeen = 1000
	e1.LastSeen = 1000
	e2 := entry("src", "msg")
	e2.FirstSeen = 2000
	e2.LastSeen = 2000
	c.Add(e1)
	c.Add(e2)

	got := c.Flush()
	if len(got) != 1 {
		t.Fatalf("want 1 coalesced entry, got %d", len(got))
	}
	if got[0].FirstSeen != 1000 {
		t.Errorf("first_seen: want 1000, got %d", got[0].FirstSeen)
	}
	if got[0].LastSeen != 2000 {
		t.Errorf("last_seen: want 2000, got %d", got[0].LastSeen)
	}
}

func TestCoalescer_emptyFlush(t *testing.T) {
	var c Coalescer
	if got := c.Flush(); got != nil {
		t.Errorf("want nil on empty flush, got %v", got)
	}
}

func entry(source, msg string) Entry {
	return Entry{Source: source, Message: msg, Count: 1, FirstSeen: 1, LastSeen: 1}
}