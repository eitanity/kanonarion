package domain_test

import (
	"bytes"
	"testing"

	domain3 "code.eitanity.com/kanonarion/internal/walk/domain"
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

// analysedRootRecord is buildOutcome's walk with the root analysed from the
// working tree; rootPath is what a walk written before the root stopped
// carrying its directory put on the node, "" what one written since does.
func analysedRootRecord(t *testing.T, rootPath string) domain3.WalkRecord {
	t.Helper()
	outcome := buildOutcome(t)
	outcome.Graph.Nodes[0].ResolutionSource = domain3.ResolutionLocalAnalysed
	outcome.Graph.Nodes[0].LocalPath = rootPath
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0",
		domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	rec, err := domain3.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return rec
}

// TestWalkRecord_AnalysedRootWithoutPathIsOneIdentity: an analysed root carries
// no directory, so two checkouts of one tree are one identity and one walk.
// A walk stored with the directory on its root is a different identity (it is
// set aside from reuse once) and still decodes and verifies.
func TestWalkRecord_AnalysedRootWithoutPathIsOneIdentity(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}

	here := analysedRootRecord(t, "")
	here.ProjectDir = "/home/alice/src/proj"
	there := analysedRootRecord(t, "")
	there.ProjectDir = "/build/ci/workspace/proj"
	hereID, err := hasher.IdentityHash(here)
	if err != nil {
		t.Fatalf("IdentityHash: %v", err)
	}
	thereID, err := hasher.IdentityHash(there)
	if err != nil {
		t.Fatalf("IdentityHash: %v", err)
	}
	if hereID != thereID {
		t.Errorf("one tree analysed from two directories has two identities:\n  %s\n  %s", hereID, thereID)
	}

	stored := analysedRootRecord(t, "/home/alice/src/proj")
	storedID, err := hasher.IdentityHash(stored)
	if err != nil {
		t.Fatalf("IdentityHash: %v", err)
	}
	if storedID == hereID {
		t.Errorf("a stored walk with the directory on its root shares the new identity %s", storedID)
	}

	data, err := hasher.Marshal(stored)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(data, []byte(`"local_path":"/home/alice/src/proj"`)) {
		t.Fatalf("fixture does not carry local_path on its root: %s", data)
	}
	decoded, err := hasher.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal of a stored walk carrying local_path: %v", err)
	}
	if verr := hasher.VerifyContentHash(decoded); verr != nil {
		t.Errorf("a stored walk carrying local_path no longer verifies: %v", verr)
	}
	for _, n := range decoded.Graph.Nodes {
		if n.Coordinate == targetCoord && n.LocalPath != "/home/alice/src/proj" {
			t.Errorf("decoded root LocalPath = %q, want the stored directory", n.LocalPath)
		}
	}

	fresh, err := hasher.Marshal(here)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(fresh, []byte("local_path")) {
		t.Errorf("a walk with an analysed root carries local_path: %s", fresh)
	}
}
