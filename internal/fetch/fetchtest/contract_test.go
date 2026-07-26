package fetchtest_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// recordingTB stands in for the testing.TB an assertion reports through, so a
// contract helper can be exercised on the paths where it is meant to fail. It
// embeds testing.TB — the interface cannot be implemented outside the testing
// package — and overrides only the reporting methods; anything else the helper
// might call would panic on the nil embedded value, which is the honest answer
// for a method this stub has not been asked to stand in for.
type recordingTB struct {
	testing.TB
	failure string
}

func (r *recordingTB) Helper() {}

// Fatalf records the failure and unwinds, because the real one does not return
// either: testing.T.Fatalf ends the test goroutine, and a stub that returns
// would let the assertion run on past its own verdict and overwrite it with
// whatever it decided next.
func (r *recordingTB) Fatalf(format string, args ...any) {
	r.failure = fmt.Sprintf(format, args...)
	panic(fatalSignal{})
}

// fatalSignal is the sentinel recordingTB unwinds with, so run below can tell a
// recorded failure from a genuine panic in the code under test. It is
// deliberately not an error: an error sentinel here would be compared against a
// value the assertion never produced.
type fatalSignal struct{}

// run calls the assertion and returns what it reported, absorbing the unwind
// Fatalf uses to stand in for testing.T's goroutine exit.
func run(t *testing.T, op func() error) string {
	t.Helper()
	stub := &recordingTB{}
	func() {
		defer func() {
			if p := recover(); p != nil {
				if _, ok := p.(fatalSignal); !ok {
					panic(p)
				}
			}
		}()
		fetchtest.AssertRefusesZeroIdentity(stub, "PutSomething", op)
	}()
	return stub.failure
}

// AssertRefusesZeroIdentity is the definition of the rule every store will be
// held to, so it has to fail when the rule is broken. A helper that passes
// whatever it is handed would let every store that adopts it go green while
// accepting the zero identity — the failure the assertion exists to catch.
func TestAssertRefusesZeroIdentity(t *testing.T) {
	tests := []struct {
		name        string
		op          func() error
		wantFailure string
	}{
		{
			name: "refuses with the domain error",
			op:   func() error { return fmt.Errorf("putting record: %w", domain.ErrZeroIdentity) },
		},
		{
			name:        "accepts the zero identity",
			op:          func() error { return nil },
			wantFailure: "accepted the zero artefact identity",
		},
		{
			name:        "refuses with an unrelated error",
			op:          func() error { return errors.New("disk full") },
			wantFailure: "want artefact identity is zero",
		},
		{
			name:        "panics before checking",
			op:          func() error { panic("nil map") },
			wantFailure: "panicked instead of refusing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failure := run(t, tt.op)
			if tt.wantFailure == "" {
				if failure != "" {
					t.Errorf("assertion failed on a conforming store: %s", failure)
				}
				return
			}
			if !strings.Contains(failure, tt.wantFailure) {
				t.Errorf("failure = %q, want it to mention %q", failure, tt.wantFailure)
			}
		})
	}
}
