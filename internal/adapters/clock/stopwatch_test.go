package clock_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/clock"
)

func TestFakeStopwatch_Start_Elapsed(t *testing.T) {
	want := 250 * time.Millisecond
	sw := clock.FakeStopwatch{Duration: want}

	lap := sw.Start()
	if got := lap.Elapsed(); got != want {
		t.Errorf("Elapsed() = %v, want %v", got, want)
	}
}

func TestFakeStopwatch_Elapsed_Stable(t *testing.T) {
	sw := clock.FakeStopwatch{Duration: 7 * time.Second}

	lap := sw.Start()
	first := lap.Elapsed()
	time.Sleep(time.Millisecond)
	second := lap.Elapsed()

	if first != second {
		t.Errorf("Elapsed not stable: first %v, second %v", first, second)
	}
	if first != 7*time.Second {
		t.Errorf("Elapsed() = %v, want %v", first, 7*time.Second)
	}
}

func TestFakeStopwatch_IndependentLaps(t *testing.T) {
	sw := clock.FakeStopwatch{Duration: time.Minute}

	a := sw.Start()
	b := sw.Start()
	if a.Elapsed() != b.Elapsed() {
		t.Errorf("independent laps disagree: %v vs %v", a.Elapsed(), b.Elapsed())
	}
}

func TestMonotonic_Elapsed_Positive(t *testing.T) {
	sw := clock.Monotonic{}

	lap := sw.Start()
	time.Sleep(2 * time.Millisecond)
	got := lap.Elapsed()

	if got <= 0 {
		t.Errorf("Elapsed() = %v, want > 0", got)
	}
}

func TestMonotonic_Elapsed_Monotonic(t *testing.T) {
	sw := clock.Monotonic{}

	lap := sw.Start()
	first := lap.Elapsed()
	time.Sleep(2 * time.Millisecond)
	second := lap.Elapsed()

	if second < first {
		t.Errorf("elapsed went backwards: first %v, second %v", first, second)
	}
}
