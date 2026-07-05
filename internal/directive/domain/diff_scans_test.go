package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/directive/domain"
)

func mkReplace(line int, oldPath, newPath, newVer string, class domain.RiskClass, outcome string, blocking bool) domain.Directive {
	return domain.Directive{
		Kind:           domain.KindReplace,
		Source:         "go.mod",
		Line:           line,
		OldPath:        oldPath,
		NewPath:        newPath,
		NewVersion:     newVer,
		Applied:        true,
		Class:          class,
		PolicyOutcome:  outcome,
		PolicyBlocking: blocking,
	}
}

// a directive present in B but not in A is reported as Added.
func TestDiffScans_Added(t *testing.T) {
	scanA := domain.Record{ID: "a"}
	scanB := domain.Record{ID: "b", Directives: []domain.Directive{
		mkReplace(7, "example.com/foo", "example.com/fork", "v1.0.0", domain.RiskHigh, "warn", true),
	}}

	diff := domain.DiffScans(scanA, scanB)
	if len(diff.Added) != 1 {
		t.Fatalf("Added = %d, want 1", len(diff.Added))
	}
	if diff.Added[0].OldPath != "example.com/foo" {
		t.Errorf("Added[0].OldPath = %q, want example.com/foo", diff.Added[0].OldPath)
	}
	if len(diff.Removed) != 0 || len(diff.Reclassified) != 0 {
		t.Errorf("expected no removed/reclassified, got removed=%d reclassified=%d", len(diff.Removed), len(diff.Reclassified))
	}
}

// a directive present in A but not in B is reported as Removed.
func TestDiffScans_Removed(t *testing.T) {
	d := mkReplace(7, "example.com/foo", "example.com/fork", "v1.0.0", domain.RiskHigh, "warn", true)
	scanA := domain.Record{ID: "a", Directives: []domain.Directive{d}}
	scanB := domain.Record{ID: "b"}

	diff := domain.DiffScans(scanA, scanB)
	if len(diff.Removed) != 1 {
		t.Fatalf("Removed = %d, want 1", len(diff.Removed))
	}
	if diff.Removed[0].OldPath != "example.com/foo" {
		t.Errorf("Removed[0].OldPath = %q, want example.com/foo", diff.Removed[0].OldPath)
	}
}

// same directive identity, changed classification → Reclassified.
func TestDiffScans_ReclassifiedOnClass(t *testing.T) {
	before := mkReplace(7, "example.com/foo", "example.com/fork", "v1.0.0", domain.RiskMedium, "allow", false)
	after := mkReplace(7, "example.com/foo", "example.com/fork", "v1.0.0", domain.RiskHigh, "warn", true)

	scanA := domain.Record{ID: "a", Directives: []domain.Directive{before}}
	scanB := domain.Record{ID: "b", Directives: []domain.Directive{after}}

	diff := domain.DiffScans(scanA, scanB)
	if len(diff.Reclassified) != 1 {
		t.Fatalf("Reclassified = %d, want 1", len(diff.Reclassified))
	}
	if diff.Reclassified[0].Before.Class != domain.RiskMedium {
		t.Errorf("Before.Class = %v, want medium", diff.Reclassified[0].Before.Class)
	}
	if diff.Reclassified[0].After.Class != domain.RiskHigh {
		t.Errorf("After.Class = %v, want high", diff.Reclassified[0].After.Class)
	}
	if len(diff.Added) != 0 || len(diff.Removed) != 0 {
		t.Errorf("identity matched: expected no added/removed, got added=%d removed=%d", len(diff.Added), len(diff.Removed))
	}
}

// same directive, only the policy outcome flipped → Reclassified.
func TestDiffScans_ReclassifiedOnPolicy(t *testing.T) {
	before := mkReplace(7, "example.com/foo", "example.com/fork", "v1.0.0", domain.RiskMedium, "allow", false)
	after := mkReplace(7, "example.com/foo", "example.com/fork", "v1.0.0", domain.RiskMedium, "warn", true)

	diff := domain.DiffScans(
		domain.Record{Directives: []domain.Directive{before}},
		domain.Record{Directives: []domain.Directive{after}},
	)
	if len(diff.Reclassified) != 1 {
		t.Fatalf("Reclassified = %d, want 1", len(diff.Reclassified))
	}
}

// identical scans report no changes (HasChanges == false).
func TestDiffScans_NoChanges(t *testing.T) {
	d := mkReplace(7, "example.com/foo", "example.com/fork", "v1.0.0", domain.RiskHigh, "warn", true)
	r := domain.Record{Directives: []domain.Directive{d}}

	diff := domain.DiffScans(r, r)
	if diff.HasChanges() {
		t.Errorf("HasChanges = true for identical scans, want false")
	}
}

// Identity must NOT consider class / policy / applied so a directive
// that flips classification across scans is matched and reported as
// Reclassified, not as a paired (Removed, Added).
func TestDiffScans_IdentityIgnoresClassAndPolicy(t *testing.T) {
	a := domain.Directive{Kind: domain.KindReplace, Source: "go.mod", Line: 7,
		OldPath: "example.com/foo", NewPath: "example.com/fork", NewVersion: "v1",
		Class: domain.RiskMedium, PolicyOutcome: "allow", PolicyBlocking: false, Applied: true}
	b := a
	b.Class = domain.RiskHigh
	b.PolicyOutcome = "warn"
	b.PolicyBlocking = true
	b.Applied = false // even Applied is identity-neutral

	if domain.Identity(a) != domain.Identity(b) {
		t.Fatalf("Identity changed across class/policy/applied: %q vs %q", domain.Identity(a), domain.Identity(b))
	}
}

// an exclude and a replace targeting the same module are NOT the
// same entity — their Kind must take part in Identity.
func TestDiffScans_IdentitySeparatesKinds(t *testing.T) {
	excl := domain.Directive{Kind: domain.KindExclude, Source: "go.mod", Line: 5,
		OldPath: "example.com/foo", OldVersion: "v1.0.0"}
	repl := domain.Directive{Kind: domain.KindReplace, Source: "go.mod", Line: 5,
		OldPath: "example.com/foo", OldVersion: "v1.0.0",
		NewPath: "example.com/fork", NewVersion: "v1.0.0"}

	if domain.Identity(excl) == domain.Identity(repl) {
		t.Fatalf("exclude vs replace on same coordinate share Identity %q — DiffScans would fold the two", domain.Identity(excl))
	}
	diff := domain.DiffScans(
		domain.Record{Directives: []domain.Directive{excl}},
		domain.Record{Directives: []domain.Directive{repl}},
	)
	if len(diff.Added) != 1 || len(diff.Removed) != 1 {
		t.Errorf("expected exclude removed + replace added; got added=%d removed=%d reclassified=%d",
			len(diff.Added), len(diff.Removed), len(diff.Reclassified))
	}
}

// when one scan has multiple distinct directives that all appear
// in the other, DiffScans returns no changes — same identities match across
// scans regardless of declaration order.
func TestDiffScans_MultipleMatchOutOfOrder(t *testing.T) {
	a := mkReplace(7, "example.com/a", "example.com/a-fork", "v1", domain.RiskHigh, "warn", true)
	b := mkReplace(9, "example.com/b", "example.com/b-fork", "v1", domain.RiskHigh, "warn", true)

	diff := domain.DiffScans(
		domain.Record{Directives: []domain.Directive{a, b}},
		domain.Record{Directives: []domain.Directive{b, a}},
	)
	if diff.HasChanges() {
		t.Errorf("reordered identical scans reported as changed: %+v", diff)
	}
}

// output ordering is stable regardless of input ordering — multiple
// adds in arbitrary order produce a deterministic Added slice.
func TestDiffScans_DeterministicSort(t *testing.T) {
	a := mkReplace(1, "example.com/a", "example.com/a-fork", "v1", domain.RiskHigh, "warn", true)
	b := mkReplace(2, "example.com/b", "example.com/b-fork", "v1", domain.RiskHigh, "warn", true)
	c := mkReplace(3, "example.com/c", "example.com/c-fork", "v1", domain.RiskHigh, "warn", true)

	d1 := domain.DiffScans(domain.Record{}, domain.Record{Directives: []domain.Directive{c, a, b}})
	d2 := domain.DiffScans(domain.Record{}, domain.Record{Directives: []domain.Directive{b, c, a}})

	if len(d1.Added) != 3 || len(d2.Added) != 3 {
		t.Fatalf("Added counts = %d, %d, want 3, 3", len(d1.Added), len(d2.Added))
	}
	for i := range d1.Added {
		if d1.Added[i].OldPath != d2.Added[i].OldPath {
			t.Errorf("sort not deterministic at i=%d: %q vs %q", i, d1.Added[i].OldPath, d2.Added[i].OldPath)
		}
	}
}
