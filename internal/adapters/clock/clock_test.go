package clock_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/clock"
)

func TestSystem_Now(t *testing.T) {
	before := time.Now()
	got := clock.System{}.Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Errorf("System.Now() = %v, want between %v and %v", got, before, after)
	}
	if got.Location() != time.UTC {
		t.Errorf("expected UTC, got %v", got.Location())
	}
}

func TestFixed_Now(t *testing.T) {
	fixed := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	c := clock.Fixed{T: fixed}
	if got := c.Now(); got != fixed {
		t.Errorf("Fixed.Now() = %v, want %v", got, fixed)
	}
}
