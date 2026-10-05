package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/stdlib/application"
)

// nothingServable is the store's answer when every held measurement was set
// aside: held, but none this build can serve.
func nothingServable() error {
	return &recordseal.NothingServable{Kind: "stdlib custody measurement", ID: "go1.26.4",
		Aside: &recordseal.SetAside{Rows: []recordseal.SetAsideRow{{
			ID: "go1.26.4", ContentHash: "sha256:aa", Reason: recordseal.Drift(errors.New("mismatch")),
		}}}}
}

// Both acquirers measure afresh when every held measurement was set aside, so
// the build writes one it can serve rather than failing on what it cannot read.
func TestAcquire_EverythingSetAsideRemeasures(t *testing.T) {
	tb := buildTarball(t, nil)
	store := newMemStore()
	store.getErr = nothingServable()
	acq := newAcquirer(t, fakeManifest{}, &fakeTarball{data: tb}, &fakeCommits{}, fakeLicense{}, store, nil)
	if _, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{}); err != nil {
		t.Fatalf("Acquire = %v, want a fresh measurement", err)
	}
	if store.puts != 1 {
		t.Errorf("store.puts = %d, want 1", store.puts)
	}

	local := newMemStore()
	local.getErr = nothingServable()
	lacq := newLocalAcquirer(t, &fakeToolchain{goRoot: "/opt/go", version: "go1.26.4"},
		fakeSource{fsys: stdlibSrcFS(), license: []byte("x")}, fakeLicense{}, local)
	if _, err := lacq.Acquire(context.Background(), "go1.26.4", application.Options{}); err != nil {
		t.Fatalf("LocalAcquire = %v, want a fresh measurement", err)
	}
	if local.puts != 1 {
		t.Errorf("local puts = %d, want 1", local.puts)
	}
}
