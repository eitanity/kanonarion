package reachability_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
)

// A call-site read the run's cancellation stopped is not a graph that could not
// be read, and is not logged as one; a read that genuinely failed still is.
func TestAnnotateRecord_ReadStoppedByTheCancellationIsNotLogged(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		err       error
		cancelled bool
	}{
		{"cancelled", fmt.Errorf("reading call sites: %w", context.Canceled), true},
		{"genuine failure", errors.New("call graph unreadable"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reader := &fakeCallSiteReader{fail: map[string]error{"example.com/dep@v1.2.3": tc.err}}
			var logs bytes.Buffer
			annotator := reachability.NewDispatchAnnotator(reader, slog.New(slog.NewTextHandler(&logs, nil)))
			ctx, cancel := context.WithCancel(t.Context())
			if tc.cancelled {
				cancel()
			}
			defer cancel()
			annotator.AnnotateRecord(ctx, recordWithRoute(theRoute()))
			logged := strings.Contains(logs.String(), "could not read the call graph")
			if tc.cancelled == logged {
				t.Errorf("cancelled=%v but logged=%v:\n%s", tc.cancelled, logged, logs.String())
			}
		})
	}
}
