package application_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/staleness/application"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

// settlingProxy is a ports.RoundResolver. Paths in slow answer unsettled on
// their first ask; Settle then answers them from versions (absent when missing)
// unless they are also in never, which stay unsettled past the window.
type settlingProxy struct {
	versions map[string]string
	slow     map[string]bool
	never    map[string]bool

	mu     sync.Mutex
	events []string
	inline []string
}

func (s *settlingProxy) answer(path string) (ports.LatestInfo, error) {
	v, ok := s.versions[path]
	if !ok {
		return ports.LatestInfo{}, fmt.Errorf("%w: %s", ports.ErrPathAbsent, path)
	}
	return ports.LatestInfo{Version: v, Time: time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)}, nil
}

// LatestInfo is the inline, waiting path. A round must never use it.
func (s *settlingProxy) LatestInfo(_ context.Context, path string) (ports.LatestInfo, error) {
	s.mu.Lock()
	s.inline = append(s.inline, path)
	s.mu.Unlock()
	return s.answer(path)
}

func (s *settlingProxy) AskOnce(_ context.Context, path string) ports.RoundAnswer {
	s.mu.Lock()
	s.events = append(s.events, "ask "+path)
	s.mu.Unlock()
	if s.slow[path] {
		return ports.RoundAnswer{Path: path, Err: &fetchdomain.ProxyEmptyResponseError{Path: path}, Unsettled: true, Attempts: 1}
	}
	info, err := s.answer(path)
	return ports.RoundAnswer{Path: path, Info: info, Err: err, Attempts: 1}
}

func (s *settlingProxy) Settle(_ context.Context, pending []ports.RoundAnswer, _ int) []ports.RoundAnswer {
	paths := make([]string, 0, len(pending))
	out := make([]ports.RoundAnswer, 0, len(pending))
	for _, a := range pending {
		paths = append(paths, a.Path)
		if s.never[a.Path] {
			out = append(out, a)
			continue
		}
		info, err := s.answer(a.Path)
		out = append(out, ports.RoundAnswer{Path: a.Path, Info: info, Err: err, Attempts: a.Attempts + 1})
	}
	s.mu.Lock()
	s.events = append(s.events, "settle "+strings.Join(paths, ","))
	s.mu.Unlock()
	return out
}

func (s *settlingProxy) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...)
}

// More unsettled paths than the pool is wide: the round asks every one of them
// once, finishes, and only then does the settle pass take them all together.
// Nothing waits inline in a pool slot.
func TestRoundFinishesBeforeTheSettlePass(t *testing.T) {
	const width = 2
	mods := scopeOf(6)
	proxy := &settlingProxy{slow: map[string]bool{}}
	var slowPaths []string
	for _, m := range mods {
		proxy.slow[m.Path+"/v2"] = true
		slowPaths = append(slowPaths, m.Path+"/v2")
	}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batchFor(mods), mods, width)

	for _, m := range mods {
		a, err := r.Resolve(context.Background(), m.Path, m.Version)
		if err != nil {
			t.Fatalf("Resolve(%s): %v", m.Path, err)
		}
		if !a.NewerMajor.Probed || a.NewerMajor.Path != "" {
			t.Errorf("%s newer major = %+v, want probed with none found", m.Path, a.NewerMajor)
		}
	}
	if len(proxy.inline) != 0 {
		t.Errorf("asked inline (waiting in a pool slot): %v", proxy.inline)
	}
	events := proxy.log()
	if len(events) != len(mods)+1 {
		t.Fatalf("events = %v, want %d asks then one settle", events, len(mods))
	}
	for _, e := range events[:len(mods)] {
		if !strings.HasPrefix(e, "ask ") {
			t.Errorf("event %q before the round finished, want only asks", e)
		}
	}
	slices.Sort(slowPaths)
	if want := "settle " + strings.Join(slowPaths, ","); events[len(mods)] != want {
		t.Errorf("last event = %q, want %q", events[len(mods)], want)
	}
}

// A candidate whose answer arrived only in the settle pass still continues the
// walk: round two asks the next major above it.
func TestRoundTwoFollowsAPredecessorThatSettledLate(t *testing.T) {
	mods := []ports.PinnedModule{{Path: "example.com/mod", Version: "v1.0.0"}}
	proxy := &settlingProxy{
		versions: map[string]string{"example.com/mod/v2": "v2.4.0"},
		slow:     map[string]bool{"example.com/mod/v2": true},
	}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batchFor(mods), mods, 4)

	a, err := r.Resolve(context.Background(), "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !a.NewerMajor.Probed || a.NewerMajor.Path != "example.com/mod/v2" || a.NewerMajor.Version != "v2.4.0" {
		t.Errorf("newer major = %+v, want example.com/mod/v2 v2.4.0", a.NewerMajor)
	}
	want := []string{"ask example.com/mod/v2", "settle example.com/mod/v2", "ask example.com/mod/v3"}
	if got := proxy.log(); !slices.Equal(got, want) {
		t.Errorf("events = %v, want %v", got, want)
	}
	if len(proxy.inline) != 0 {
		t.Errorf("asked inline: %v", proxy.inline)
	}
}

// A path still unsettled when the window closes leaves its module unprobed, as
// a failed probe always has, and its neighbours keep their answers.
func TestUnsettledAtTheDeadlineStaysUnprobed(t *testing.T) {
	mods := []ports.PinnedModule{{Path: "example.com/a", Version: "v1.0.0"}, {Path: "example.com/b", Version: "v1.0.0"}}
	proxy := &settlingProxy{
		slow:  map[string]bool{"example.com/a/v2": true},
		never: map[string]bool{"example.com/a/v2": true},
	}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batchFor(mods), mods, 4)

	a, err := r.Resolve(context.Background(), "example.com/a", "v1.0.0")
	if err == nil || errors.Is(err, ports.ErrPathAbsent) {
		t.Fatalf("Resolve(a) error = %v, want the unsettled failure", err)
	}
	if a.NewerMajor.Probed {
		t.Errorf("a newer major = %+v, want unprobed", a.NewerMajor)
	}
	b, err := r.Resolve(context.Background(), "example.com/b", "v1.0.0")
	if err != nil || !b.NewerMajor.Probed {
		t.Errorf("Resolve(b) = %+v, %v; want probed", b.NewerMajor, err)
	}
	if len(proxy.inline) != 0 {
		t.Errorf("asked inline: %v", proxy.inline)
	}
}

// The control: definitive first answers, 404s included, make no settle pass.
func TestDefinitiveRoundMakesNoSettlePass(t *testing.T) {
	mods := scopeOf(5)
	proxy := &settlingProxy{}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batchFor(mods), mods, 2)

	for _, m := range mods {
		if _, err := r.Resolve(context.Background(), m.Path, m.Version); err != nil {
			t.Fatalf("Resolve(%s): %v", m.Path, err)
		}
	}
	for _, e := range proxy.log() {
		if strings.HasPrefix(e, "settle") {
			t.Errorf("settle pass ran with nothing unsettled: %v", proxy.log())
		}
	}
	if got := len(proxy.log()); got != len(mods) {
		t.Errorf("asks = %d, want one per module (%d)", got, len(mods))
	}
}
