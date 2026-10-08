package interrupt

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"testing"
	"time"
)

func TestCancelled(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelExpired()
	<-expired.Done()
	live := context.Background()

	wrapped := fmt.Errorf("fetching module: querying fetch records: %w", context.Canceled)
	genuine := errors.New("proxy: 404 Not Found")

	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"the cancellation, wrapped", cancelled, wrapped, true},
		{"a genuine failure while cancelled", cancelled, genuine, false},
		{"no error", cancelled, nil, false},
		{"a cancellation error on a live context", live, wrapped, false},
		{"a deadline the program set", expired, fmt.Errorf("x: %w", context.DeadlineExceeded), false},
	} {
		if got := Cancelled(tc.ctx, tc.err); got != tc.want {
			t.Errorf("%s: Cancelled = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A child that a cancelled context killed reports only "signal: killed"; that is
// the cancellation, while a child that exited non-zero on its own is not.
func TestCancelledRecognisesAKilledChild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("no sleep binary: %v", err)
	}
	cancel()
	killed := cmd.Wait()
	if !Cancelled(ctx, fmt.Errorf("running child: %w", killed)) {
		t.Errorf("a child killed by the cancellation (%v) was not recognised as cancelled", killed)
	}

	failed := exec.Command("false").Run()
	if Cancelled(ctx, failed) {
		t.Errorf("a child that exited non-zero on its own (%v) was read as cancelled", failed)
	}
}

func TestStatement(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	cause := errors.New("interrupt signal received")
	if got, want := Statement(cause), "interrupted (interrupt signal received)"; got != want {
		t.Errorf("nothing in flight: got %q, want %q", got, want)
	}
	for range 420 {
		Note(ModuleFetch)
	}
	Note(StdlibCustody)
	Note(Kind(-1))
	Note(numKinds)
	want := "interrupted (interrupt signal received); stopped with 420 module fetches, 1 stdlib custody check in flight"
	if got := Statement(cause); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
