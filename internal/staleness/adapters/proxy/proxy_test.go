package proxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	directproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	staleproxy "github.com/eitanity/kanonarion/internal/staleness/adapters/proxy"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

func bridgeFor(t *testing.T, handler http.HandlerFunc) *staleproxy.Bridge {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	p, err := directproxy.New(srv.URL, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return staleproxy.New(p)
}

// The distinction the probe's bound rests on: an absent path is a definitive
// answer that stops the walk, a failing one is not.
func TestLatestInfo_ClassifiesAbsenceApartFromFailure(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		wantAbsent bool
	}{
		{"404 is absent", http.StatusNotFound, true},
		{"410 gone is absent", http.StatusGone, true},
		{"429 is a failure", http.StatusTooManyRequests, false},
		{"500 is a failure", http.StatusInternalServerError, false},
		{"403 is a failure", http.StatusForbidden, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := bridgeFor(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			})
			_, err := b.LatestInfo(context.Background(), "example.com/mod/v9")
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := errors.Is(err, ports.ErrPathAbsent); got != tc.wantAbsent {
				t.Errorf("errors.Is(err, ErrPathAbsent) = %v, want %v (err: %v)", got, tc.wantAbsent, err)
			}
		})
	}
}

func TestLatestInfo_ResolvesAVersion(t *testing.T) {
	b := bridgeFor(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/@latest") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"Version": "v7.2.1", "Time": "2026-01-19T08:00:00Z"})
	})
	got, err := b.LatestInfo(context.Background(), "example.com/mod/v7")
	if err != nil {
		t.Fatalf("LatestInfo: %v", err)
	}
	if got.Version != "v7.2.1" {
		t.Errorf("Version = %q, want v7.2.1", got.Version)
	}
	if got.Time.IsZero() {
		t.Error("expected the publication time to survive")
	}
}

// TestLatestInfo_ProbeOutcomesAreThreeWay pins the split the major probe rests
// on, from the caller's side rather than the transport's.
//
// The probe has three outcomes, not two. A /vN path that does not exist is the
// ORDINARY case for most modules and is a measured negative; a lookup that
// could not be made is the one an operator can act on. They used to be told
// apart only by which error text came back, so an empty proxy response surfaced
// as "decoding latest response for <mod>/v2: EOF" — a decoder's position stated
// where the reason the question went unanswered belonged.
func TestLatestInfo_ProbeOutcomesAreThreeWay(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		// exactly one of these is expected
		wantAbsent bool
		wantFailed bool
		wantOK     bool
	}{
		{
			name: "a resolving path is an answer",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"Version": "v2.1.30"})
			},
			wantOK: true,
		},
		{
			name: "a path that does not exist is a measured negative",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "not found: module example.com/mod/v2: no matching versions", http.StatusNotFound)
			},
			wantAbsent: true,
		},
		{
			name: "an empty response settles nothing and is a failed lookup",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantFailed: true,
		},
		{
			name: "a proxy error is a failed lookup",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
			},
			wantFailed: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := bridgeFor(t, tc.handler)
			_, err := b.LatestInfo(context.Background(), "example.com/mod/v2")
			switch {
			case tc.wantOK:
				if err != nil {
					t.Fatalf("LatestInfo: %v", err)
				}
				return
			case err == nil:
				t.Fatal("expected an error")
			}
			absent := errors.Is(err, ports.ErrPathAbsent)
			failed := errors.Is(err, ports.ErrLookupFailed)
			if absent == failed {
				t.Fatalf("outcome is %v/%v — absence and failure must be told apart (err: %v)", absent, failed, err)
			}
			if absent != tc.wantAbsent || failed != tc.wantFailed {
				t.Fatalf("absent=%v failed=%v, want absent=%v failed=%v (err: %v)", absent, failed, tc.wantAbsent, tc.wantFailed, err)
			}
			if !failed {
				return
			}
			// The message an operator reads says the lookup failed, and does
			// not lead with a decoder's position.
			if !strings.Contains(err.Error(), "module proxy lookup failed") {
				t.Errorf("message does not say the lookup failed: %v", err)
			}
			if strings.Contains(err.Error(), "EOF") {
				t.Errorf("message names EOF rather than what happened to the lookup: %v", err)
			}
		})
	}
}
