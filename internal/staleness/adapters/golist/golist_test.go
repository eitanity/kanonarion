package golist_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/goenv"
	"github.com/eitanity/kanonarion/internal/staleness/adapters/golist"
)

// TestBatchRefusesWhenTheNetworkIsForbidden is the guard on the one way this
// adapter can produce a confident wrong answer about an entire dependency set.
//
// Under GOPROXY=off, `go list -m -u -json` exits 0, writes nothing to stderr,
// and omits the "Update" key from every module. That output is byte-identical to
// "every one of these modules is at its newest version". Measured on this host
// against a 553-module build list: exit 0, 553 modules, 0 updates, 0
// deprecations, empty stderr — the same shape a fully up-to-date project
// produces.
//
// So the adapter must refuse BEFORE the call rather than interpret its output,
// and this test asserts the refusal is what comes back. Offline the ledger is
// what answers: a recorded lookup inside the TTL is served with its own lookup
// time, and a module without one is refused rather than called current.
func TestBatchRefusesWhenTheNetworkIsForbidden(t *testing.T) {
	t.Setenv("GOPROXY", "off")

	got, err := golist.New(t.TempDir(), "").LatestBatch(context.Background(), []string{"example.com/mod"})
	if !errors.Is(err, golist.ErrNoUpdateCheck) {
		t.Fatalf("LatestBatch under GOPROXY=off: err = %v, want ErrNoUpdateCheck", err)
	}
	if !errors.Is(err, goenv.ErrNetworkForbidden) {
		t.Errorf("refusal does not wrap the no-network fact: %v", err)
	}
	if got != nil {
		t.Errorf("a refusal returned %d answers; a refused batch answers nothing", len(got))
	}
}

// TestOffFirstInAChainRefuses: `off` terminates GOPROXY's chain in the go
// command, so nothing after it is ever tried and no update is ever checked.
func TestOffFirstInAChainRefuses(t *testing.T) {
	t.Setenv("GOPROXY", "off,https://proxy.golang.org")

	if _, err := golist.New(t.TempDir(), "").LatestBatch(context.Background(),
		[]string{"example.com/mod"}); !errors.Is(err, golist.ErrNoUpdateCheck) {
		t.Fatalf("err = %v, want ErrNoUpdateCheck", err)
	}
}

// TestGoproxyOverrideRefuses: the --goproxy flag is read under the same grammar
// as the environment, so `--goproxy off` refuses exactly as GOPROXY=off does
// rather than being handed to the child as a proxy URL.
func TestGoproxyOverrideRefuses(t *testing.T) {
	t.Setenv("GOPROXY", "https://proxy.golang.org")

	if _, err := golist.New(t.TempDir(), "off").LatestBatch(context.Background(),
		[]string{"example.com/mod"}); !errors.Is(err, golist.ErrNoUpdateCheck) {
		t.Fatalf("err = %v, want ErrNoUpdateCheck", err)
	}
}

// TestEmptyRequestIsNotACall: nothing to ask about is answered without shelling
// out, and without the refusal either — there is no set to be wrong about.
func TestEmptyRequestIsNotACall(t *testing.T) {
	t.Setenv("GOPROXY", "off")

	got, err := golist.New(t.TempDir(), "").LatestBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty batch answered %d modules", len(got))
	}
}
