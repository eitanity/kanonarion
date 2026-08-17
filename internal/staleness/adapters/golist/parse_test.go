package golist

import (
	"testing"
	"time"
)

// The bytes below are `go list -m -u -json` output, copied from a real run on
// this host. They carry the three shapes the reader has to tell apart: a module
// with an update, a module without one, and a module that declares itself
// deprecated.
const goListOutput = `{
	"Path": "github.com/caddyserver/caddy/v2",
	"Main": true,
	"Dir": "/tmp/caddy"
}
{
	"Path": "golang.org/x/mod",
	"Version": "v0.37.0",
	"Time": "2026-06-08T15:10:58Z",
	"Update": {
		"Path": "golang.org/x/mod",
		"Version": "v0.40.0",
		"Time": "2026-08-13T19:09:22Z"
	}
}
{
	"Path": "cloud.google.com/go/auth/oauth2adapt",
	"Version": "v0.2.8",
	"Time": "2025-03-20T15:18:21Z"
}
{
	"Path": "github.com/aws/aws-sdk-go",
	"Version": "v1.55.8",
	"Time": "2025-07-31T16:05:54Z",
	"Deprecated": "aws-sdk-go is deprecated. Use aws-sdk-go-v2.\nSee https://aws.amazon.com/blogs/developer/x."
}
{
	"Path": "example.com/nodate",
	"Version": "v1.0.0"
}
`

func TestParseReadsEveryShape(t *testing.T) {
	got, err := parseGoListModules([]byte(goListOutput))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// The main module is not a dependency of itself and has no published latest.
	if _, ok := got["github.com/caddyserver/caddy/v2"]; ok {
		t.Error("the main module was reported as a dependency")
	}
	if len(got) != 4 {
		t.Fatalf("parsed %d modules, want 4", len(got))
	}

	// An Update names the latest, WITH its publication time — the date the
	// rendered "released N days ago" and the ledger's latest_published_at both
	// depend on, and the reason the update object is read rather than only its
	// version string.
	upd := got["golang.org/x/mod"]
	if upd.Version != "v0.40.0" {
		t.Errorf("latest = %q, want v0.40.0 (the UPDATE's version, not the pinned one)", upd.Version)
	}
	if want := time.Date(2026, 8, 13, 19, 9, 22, 0, time.UTC); !upd.Time.Equal(want) {
		t.Errorf("latest date = %v, want %v (the update's time, not the pin's)", upd.Time, want)
	}
	if upd.Deprecated != "" {
		t.Errorf("a module declaring no deprecation carried %q", upd.Deprecated)
	}

	// No Update means the module IS at its newest version, so the latest is its
	// own — read from the same record rather than filled in by a caller from its
	// own pin.
	cur := got["cloud.google.com/go/auth/oauth2adapt"]
	if cur.Version != "v0.2.8" {
		t.Errorf("latest for a current module = %q, want its own version v0.2.8", cur.Version)
	}
	if want := time.Date(2025, 3, 20, 15, 18, 21, 0, time.UTC); !cur.Time.Equal(want) {
		t.Errorf("latest date = %v, want %v", cur.Time, want)
	}

	// The notice is reproduced, not interpreted: the successor is whichever one
	// the author named, and the newline they wrote is still there.
	dep := got["github.com/aws/aws-sdk-go"]
	const notice = "aws-sdk-go is deprecated. Use aws-sdk-go-v2.\nSee https://aws.amazon.com/blogs/developer/x."
	if dep.Deprecated != notice {
		t.Errorf("deprecation notice = %q, want it verbatim: %q", dep.Deprecated, notice)
	}

	// A date is never fabricated for a module the go command supplied none for.
	if nd := got["example.com/nodate"]; !nd.Time.IsZero() {
		t.Errorf("a module with no publication time acquired one: %v", nd.Time)
	}
}
