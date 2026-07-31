package domain_test

import (
	"bytes"
	"testing"

	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestWalkRecord_ProjectDirIsNotIdentity pins the decision behind the field: the
// directory a walk was taken from is machine-local provenance, so two walks that
// differ only by where they were taken from are the same walk. If it ever joins
// the canonical shape this fails, and it should: admitting it would change the
// identity of every project walk for good and owe a PipelineVersion bump.
func TestWalkRecord_ProjectDirIsNotIdentity(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}

	here := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(t), domain3.DefaultDepthPolicy(), "")
	here.ProjectDir = "/home/alice/src/proj"
	here, err := hasher.SetContentHash(here)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	there := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(t), domain3.DefaultDepthPolicy(), "")
	there.ProjectDir = "/build/ci/workspace/proj"
	there, err = hasher.SetContentHash(there)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	if here.ContentHash != there.ContentHash {
		t.Errorf("the same walk taken from two directories hashes differently:\n  %s\n  %s",
			here.ContentHash, there.ContentHash)
	}

	// A record carrying no directory at all — a walk of a published coordinate,
	// and every walk written before the field existed — must hash to the same
	// thing, or the field would have retroactively broken the store.
	none := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(t), domain3.DefaultDepthPolicy(), "")
	none, err = hasher.SetContentHash(none)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if none.ContentHash != here.ContentHash {
		t.Errorf("a walk with no project directory hashes differently from one with a directory: %s vs %s",
			none.ContentHash, here.ContentHash)
	}

	data, err := hasher.Marshal(here)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(data, []byte("project_dir")) || bytes.Contains(data, []byte("/home/alice")) {
		t.Errorf("the project directory reached the sealed bytes: %s", data)
	}
}
