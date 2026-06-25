// Package logs handles log source tailing, redaction, and dedup coalescing.
package logs

import (
	"regexp"
	"strings"
)

// Entry is a single (possibly coalesced) log record, matching PROTOCOL.md §3.3.
type Entry struct {
	Source    string `json:"source"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Count     int    `json:"count"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

// levelRank maps canonical level names to a numeric rank for filter comparison.
var levelRank = map[string]int{
	"debug":   0,
	"info":    1,
	"notice":  2,
	"warn":    3,
	"warning": 3,
	"error":   4,
	"fatal":   5,
	"crit":    5,
	"panic":   5,
}

// PassesFilter reports whether the extracted level of line meets the minimum
// configured filter. An empty filter passes everything.
func PassesFilter(line, levelFilter string) bool {
	if levelFilter == "" {
		return true
	}
	minRank, ok := levelRank[strings.ToLower(levelFilter)]
	if !ok {
		return true // unknown filter → pass all
	}
	lvl := ExtractLevel(line)
	rank, ok := levelRank[strings.ToLower(lvl)]
	if !ok {
		// Unknown level in the line — conservatively pass it through.
		return true
	}
	return rank >= minRank
}

// ExtractLevel tries common log formats to pull a severity level from a line.
// Returns empty string if none is found.
func ExtractLevel(line string) string {
	// logfmt: level=warn or level="warn"
	if m := reLevelLogfmt.FindStringSubmatch(line); m != nil {
		return strings.Trim(m[1], `"`)
	}
	// JSON: "level":"warn" or "level": "warn"
	if m := reLevelJSON.FindStringSubmatch(line); m != nil {
		return strings.Trim(m[1], `"`)
	}
	// Bracketed: [WARN] [ERROR]
	if m := reLevelBracket.FindStringSubmatch(line); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

var (
	reLevelLogfmt  = regexp.MustCompile(`(?i)\blevel=("?[a-z]+)"?`)
	reLevelJSON    = regexp.MustCompile(`(?i)"level"\s*:\s*"([a-z]+)"`)
	reLevelBracket = regexp.MustCompile(`\[(DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|FATAL|CRIT|PANIC)\]`)
)

// Coalescer merges consecutive identical log lines (same source + message)
// within a single flush window per SPEC.md §5.
// It is not safe for concurrent use; the caller must hold a single goroutine.
type Coalescer struct {
	pending []Entry
	lastKey string // source + "\x00" + message
}

// Add incorporates a new entry. If it matches the last pending entry the
// counts are merged; otherwise the entry is appended as-is.
func (c *Coalescer) Add(e Entry) {
	key := e.Source + "\x00" + e.Message
	if len(c.pending) > 0 && key == c.lastKey {
		last := &c.pending[len(c.pending)-1]
		last.Count += e.Count
		last.LastSeen = e.LastSeen
		return
	}
	c.pending = append(c.pending, e)
	c.lastKey = key
}

// Len returns the number of distinct pending entries.
func (c *Coalescer) Len() int { return len(c.pending) }

// Flush returns all accumulated entries and resets the coalescer.
// The coalescing window is bounded by the caller's flush interval (push_interval)
// so no entry is held across multiple push cycles.
func (c *Coalescer) Flush() []Entry {
	if len(c.pending) == 0 {
		return nil
	}
	out := c.pending
	c.pending = nil
	c.lastKey = ""
	return out
}