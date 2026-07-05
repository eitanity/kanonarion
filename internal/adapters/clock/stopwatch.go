package clock

import (
	"time"

	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

var (
	_ ports.Stopwatch = Monotonic{}
	_ ports.Stopwatch = FakeStopwatch{}
	_ ports.Lap       = monotonicLap{}
	_ ports.Lap       = fakeLap{}
)

// Monotonic is the production ports.Stopwatch: each Start captures a monotonic
// reading from time.Now, and Elapsed reports time.Since that reading.
type Monotonic struct{}

// Start begins a new measurement anchored at the current monotonic instant.
func (Monotonic) Start() ports.Lap { return monotonicLap{start: time.Now()} }

type monotonicLap struct {
	start time.Time
}

func (l monotonicLap) Elapsed() time.Duration { return time.Since(l.start) }

// FakeStopwatch is a deterministic ports.Stopwatch for tests. Every Lap it
// produces reports the same fixed Duration regardless of real elapsed time.
type FakeStopwatch struct {
	Duration time.Duration
}

// Start returns a Lap that always reports the configured Duration.
func (f FakeStopwatch) Start() ports.Lap { return fakeLap{d: f.Duration} }

type fakeLap struct {
	d time.Duration
}

func (l fakeLap) Elapsed() time.Duration { return l.d }
