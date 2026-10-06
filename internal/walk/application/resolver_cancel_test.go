package application_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/interrupt"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
	"github.com/eitanity/kanonarion/internal/walk/application"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// cancellingFetcher cancels the run when it is asked for one module, and
// returns the cancellation for it, the way a fetch in flight sees an operator's
// interrupt.
type cancellingFetcher struct {
	*fakeModuleFetcher
	stop   string
	cancel context.CancelFunc
}

func (f *cancellingFetcher) EnsureFetchedReplacing(ctx context.Context, c, original coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	if c.Path() == f.stop {
		f.cancel()
		return walkports.ModuleFetchResult{}, fmt.Errorf("fetching module: querying fetch records: %w", context.Canceled)
	}
	return f.fakeModuleFetcher.EnsureFetchedReplacing(ctx, c, original)
}

// logLines returns the lines of buf that carry msg=event.
func logLines(buf *bytes.Buffer, event string) []string {
	var out []string
	for line := range strings.SplitSeq(buf.String(), "\n") {
		if strings.Contains(line, "msg="+event+" ") || strings.HasSuffix(line, "msg="+event) {
			out = append(out, line)
		}
	}
	return out
}

// An interrupted walk reports a cancelled fetch as cancelled, at debug, and
// never under the failure's event name; a module that genuinely could not be
// fetched in the same run still is a failure, at WARN.
func TestResolveProject_CancelledFetchIsNotAFailure(t *testing.T) {
	interrupt.Reset()
	t.Cleanup(interrupt.Reset)

	blobs := newFakeBlobStore()
	inner := newFakeFetcher()
	inner.add(t, "example.com/ok", "v1.0.0", "module example.com/ok\n", blobs)
	inner.addError("example.com/broken", "v1.0.0", errors.New("proxy: 404 Not Found"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetcher := &cancellingFetcher{fakeModuleFetcher: inner, stop: "example.com/stopped", cancel: cancel}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	bl := walkports.BuildList{
		GoVersion: "go1.26.4",
		Modules: []walkports.BuildListModule{
			{Path: "example.com/project", Main: true},
			{Path: "example.com/ok", Version: "v1.0.0"},
			{Path: "example.com/broken", Version: "v1.0.0"},
			{Path: "example.com/stopped", Version: "v1.0.0"},
		},
	}
	acq := &fakeStdlibAcquirer{err: fmt.Errorf("reading stdlib facts: %w", context.Canceled)}
	r := application.NewGraphResolver(xmod.New(), fetcher, blobs, fixedClock{fixedNow}, "", logger).
		WithBuildListResolver(&fakeBuildListResolver{list: bl}).
		WithStdlibAcquirer(acq, false)

	target := coord("example.com/project", coordinate.LocalVersion)
	if _, err := r.ResolveProject(ctx, target, nil, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false, false); err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}

	failed := logLines(&logs, "walk.fetch.failed")
	if len(failed) != 1 || !strings.Contains(failed[0], "example.com/broken") || !strings.Contains(failed[0], "level=WARN") {
		t.Errorf("want exactly one WARN walk.fetch.failed, for the genuinely broken module; got %q", failed)
	}
	cancelled := logLines(&logs, "walk.fetch.cancelled")
	if len(cancelled) != 1 || !strings.Contains(cancelled[0], "example.com/stopped") || !strings.Contains(cancelled[0], "level=DEBUG") {
		t.Errorf("want one DEBUG walk.fetch.cancelled for the stopped module; got %q", cancelled)
	}
	if got := logLines(&logs, "walk.stdlib.custody_unavailable"); len(got) != 0 {
		t.Errorf("a custody check stopped by the cancellation was reported as unavailable: %q", got)
	}
	if got := logLines(&logs, "walk.stdlib.custody_cancelled"); len(got) != 1 || !strings.Contains(got[0], "level=DEBUG") {
		t.Errorf("want one DEBUG walk.stdlib.custody_cancelled; got %q", got)
	}
	want := "stopped with 1 module fetch, 1 stdlib custody check in flight"
	if got := interrupt.Statement(nil); !strings.Contains(got, want) {
		t.Errorf("interruption statement = %q, want it to contain %q", got, want)
	}
}

// Without an interruption the failures keep their names: a fetch the proxy
// cannot serve and a custody check that timed out are both reported at WARN.
func TestResolveProject_GenuineFailuresKeepTheirEvents(t *testing.T) {
	interrupt.Reset()
	t.Cleanup(interrupt.Reset)

	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.addError("example.com/broken", "v1.0.0", fmt.Errorf("proxy download: %w", errors.New("410 Gone")))
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	bl := walkports.BuildList{
		GoVersion: "go1.26.4",
		Modules: []walkports.BuildListModule{
			{Path: "example.com/project", Main: true},
			{Path: "example.com/broken", Version: "v1.0.0"},
		},
	}
	acq := &fakeStdlibAcquirer{err: fmt.Errorf("reading the manifest: %w", context.DeadlineExceeded)}
	r := application.NewGraphResolver(xmod.New(), fetcher, blobs, fixedClock{fixedNow}, "", logger).
		WithBuildListResolver(&fakeBuildListResolver{list: bl}).
		WithStdlibAcquirer(acq, false)

	target := coord("example.com/project", coordinate.LocalVersion)
	g, err := r.ResolveProject(context.Background(), target, nil, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	if got := logLines(&logs, "walk.fetch.failed"); len(got) != 1 || !strings.Contains(got[0], "level=WARN") {
		t.Errorf("want one WARN walk.fetch.failed; got %q", got)
	}
	if got := logLines(&logs, "walk.stdlib.custody_unavailable"); len(got) != 1 || !strings.Contains(got[0], "level=WARN") {
		t.Errorf("want one WARN walk.stdlib.custody_unavailable; got %q", got)
	}
	if !g.Partial || g.PartialReason == "" {
		t.Errorf("a walk with an unfetchable module must be partial; got partial=%v reason=%q", g.Partial, g.PartialReason)
	}
	if got := interrupt.Statement(nil); got != "interrupted" {
		t.Errorf("an uninterrupted walk counted operations as cancelled: %q", got)
	}
}
