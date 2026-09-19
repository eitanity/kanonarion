package domain_test

import (
	"bytes"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
)

const toolchainReason = "go list -m -mod=readonly -json all: exit status 1\n" +
	"go: example.com/dep@v1.0.0: missing go.sum entry for go.mod file"

// TestWalkRecordHasher_BuildListUnavailableRoundTrip: the toolchain's reason is
// sealed with the record and comes back out of it, so a walk read months later
// still says which module set it covered and why.
func TestWalkRecordHasher_BuildListUnavailableRoundTrip(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(t), domain3.DefaultDepthPolicy(), "")
	rec.Graph.BuildListUnavailable = toolchainReason
	rec.Graph.Partial = true
	rec.Graph.PartialReason = domain3.BuildListUnavailableReason

	rec, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := hasher.VerifyContentHash(rec); err != nil {
		t.Fatalf("VerifyContentHash: %v", err)
	}
	data, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := hasher.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Graph.BuildListUnavailable != toolchainReason {
		t.Errorf("BuildListUnavailable after round-trip = %q, want %q",
			back.Graph.BuildListUnavailable, toolchainReason)
	}
}

// TestWalkRecordHasher_BuildListUnavailableOmittedWhenEmpty: a walk whose build
// list resolved carries no such key, so every record written before the field
// existed still hashes and verifies exactly as it did.
func TestWalkRecordHasher_BuildListUnavailableOmittedWhenEmpty(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec, err := hasher.SetContentHash(
		domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(t), domain3.DefaultDepthPolicy(), ""),
	)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(data, []byte("build_list_unavailable")) {
		t.Errorf("an empty BuildListUnavailable must be omitted from canonical JSON, got: %s", data)
	}
}

// TestWalkRecordHasher_BuildListUnavailableNamesTheWalk: two walks that fell
// back for different reasons are different analyses, so identity must not serve
// one in place of the other — the second would report the first's reason.
func TestWalkRecordHasher_BuildListUnavailableNamesTheWalk(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	identity := func(reason string) string {
		t.Helper()
		rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(t), domain3.DefaultDepthPolicy(), "")
		rec.Graph.BuildListUnavailable = reason
		h, err := hasher.IdentityHash(rec)
		if err != nil {
			t.Fatalf("IdentityHash: %v", err)
		}
		return h
	}
	missingSum := identity(toolchainReason)
	noToolchain := identity("exec: \"go\": executable file not found in $PATH")
	resolved := identity("")

	if missingSum == noToolchain {
		t.Error("two different toolchain reasons produced one identity")
	}
	if resolved == missingSum || resolved == noToolchain {
		t.Error("a walk whose build list resolved shares an identity with one that fell back")
	}
}

// TestFilterGraphToScope_KeepsTheBuildListGap: a scope is a projection of the
// module set, so narrowing one cannot turn a require-list fallback into a
// resolved build. Scoped walks are the default (`walk --gomod`), so dropping it
// here would lose it on the commonest path.
func TestFilterGraphToScope_KeepsTheBuildListGap(t *testing.T) {
	main, err := coordinate.NewLocalCoordinate("example.com/project")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	g := domain3.Graph{
		Target:               main,
		Nodes:                []domain3.GraphNode{{Coordinate: main, ResolutionSource: domain3.ResolutionLocalMainModule}},
		Partial:              true,
		PartialReason:        domain3.BuildListUnavailableReason,
		BuildListUnavailable: toolchainReason,
	}
	got := domain3.FilterGraphToScope(g, main.Path(), nil)
	if got.BuildListUnavailable != toolchainReason {
		t.Errorf("BuildListUnavailable after scope filter = %q, want %q",
			got.BuildListUnavailable, toolchainReason)
	}
}

// TestPartialReasonTokens covers what the walk-status rule reads: reasons
// accumulate as "a; b" and each may carry a payload, so the rule must see the
// names and nothing else. The empty case is called out because a caller that
// reads no tokens as "nothing is wrong" reintroduces the bug this splits for.
func TestPartialReasonTokens(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
		want   []string
	}{
		{"one bare token", domain3.FetchFailedReason, []string{"fetch_failed"}},
		{"payload is dropped", domain3.DepthBoundedReason(3), []string{"depth_bounded"}},
		{"the build-list token", domain3.BuildListUnavailableReason, []string{"build_list_unavailable"}},
		{"two reasons", domain3.BuildListUnavailableReason + "; " + domain3.FetchFailedReason,
			[]string{"build_list_unavailable", "fetch_failed"}},
		{"three, mixed payloads", domain3.ShallowReason + "; " + domain3.DepthBoundedReason(1) + "; " + domain3.ParseFailedReason,
			[]string{"shallow", "depth_bounded", "parse_failed"}},
		{"empty yields nothing", "", nil},
		{"whitespace yields nothing", "   ", nil},
		{"a stray separator contributes no empty token", "fetch_failed; ; parse_failed",
			[]string{"fetch_failed", "parse_failed"}},
		{"a bare colon names nothing", ":payload", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := domain3.PartialReasonTokens(tc.reason)
			if len(got) != len(tc.want) {
				t.Fatalf("tokens = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("token %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
