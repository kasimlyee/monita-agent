package transport

import (
	"testing"
	"time"
)

func TestBackoff_doublesOnFail(t *testing.T) {
	bo := newBackoff(30*time.Second, 300*time.Second)
	if bo.Current() != 30*time.Second {
		t.Fatalf("want 30s base, got %s", bo.Current())
	}

	next := bo.Fail()
	if next != 60*time.Second {
		t.Errorf("after 1 fail: want 60s, got %s", next)
	}
	next = bo.Fail()
	if next != 120*time.Second {
		t.Errorf("after 2 fails: want 120s, got %s", next)
	}
	next = bo.Fail()
	if next != 240*time.Second {
		t.Errorf("after 3 fails: want 240s, got %s", next)
	}
}

func TestBackoff_capsAtMax(t *testing.T) {
	bo := newBackoff(30*time.Second, 300*time.Second)
	for range 10 {
		bo.Fail()
	}
	if bo.Current() > 300*time.Second {
		t.Errorf("current exceeds max: got %s", bo.Current())
	}
	if bo.Current() != 300*time.Second {
		t.Errorf("want exactly max 300s, got %s", bo.Current())
	}
}

func TestBackoff_resetAfterSuccesses(t *testing.T) {
	bo := newBackoff(30*time.Second, 300*time.Second)
	bo.Fail()
	bo.Fail()
	// Need resetAt=3 consecutive successes to reset.
	if bo.Success() {
		t.Error("should not reset after 1 success")
	}
	if bo.Success() {
		t.Error("should not reset after 2 successes")
	}
	reset := bo.Success()
	if !reset {
		t.Error("should reset after 3 consecutive successes")
	}
	if bo.Current() != 30*time.Second {
		t.Errorf("after reset: want base 30s, got %s", bo.Current())
	}
}

func TestBackoff_successCounterResetOnFail(t *testing.T) {
	bo := newBackoff(30*time.Second, 300*time.Second)
	bo.Fail()
	bo.Success()
	bo.Success()
	// Fail interrupts the streak — reset should not fire.
	bo.Fail()
	// Two more successes (total of 4 across two streaks but only 2 consecutive).
	bo.Success()
	if bo.Success() {
		t.Error("reset fired mid-streak after fail interrupted")
	}
}

func TestBackoff_noResetWhenAtBase(t *testing.T) {
	bo := newBackoff(30*time.Second, 300*time.Second)
	// No failures, so we're already at base; success should not claim a reset.
	for i := range 5 {
		if bo.Success() {
			t.Errorf("reset claimed at iteration %d when already at base", i)
		}
	}
}