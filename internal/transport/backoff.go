package transport

import "time"

// backoff implements the adaptive push-interval state machine from SPEC.md §6.
// It is not safe for concurrent use; each push loop owns its own instance.
type backoff struct {
	base    time.Duration
	current time.Duration
	max     time.Duration
	factor  time.Duration // multiplier applied on each failure
	resetAt int           // consecutive successes required to reset
	ok      int           // consecutive successes since last failure
}

func newBackoff(base, max time.Duration) *backoff {
	return &backoff{
		base:    base,
		current: base,
		max:     max,
		factor:  2,
		resetAt: 3,
	}
}

// Fail doubles the current interval (capped at max) and returns the new value.
func (b *backoff) Fail() time.Duration {
	b.ok = 0
	next := b.current * b.factor
	if next > b.max || next <= 0 {
		next = b.max
	}
	b.current = next
	return b.current
}

// Success records a successful push. Returns true (and resets the interval) once
// resetAt consecutive successes have been observed.
func (b *backoff) Success() bool {
	b.ok++
	if b.ok >= b.resetAt && b.current > b.base {
		b.current = b.base
		b.ok = 0
		return true
	}
	return false
}

// Current returns the active interval without modifying state.
func (b *backoff) Current() time.Duration { return b.current }