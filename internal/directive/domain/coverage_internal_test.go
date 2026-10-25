package domain

import "testing"

func TestRiskClassString_EveryClass(t *testing.T) {
	for c, want := range map[RiskClass]string{
		RiskHighest: "highest", RiskHigh: "high", RiskMedium: "medium", RiskLow: "low", RiskUnknown: "unknown",
	} {
		if got := c.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", c, got, want)
		}
	}
}

func TestClassify_UnknownKindIsUnknown(t *testing.T) {
	if got := Classify(Directive{Kind: "retract"}, ""); got != RiskUnknown {
		t.Errorf("Classify(unknown kind) = %v, want unknown", got)
	}
}

func TestDiffScans_ReportsARemovedDirective(t *testing.T) {
	gone := Directive{Kind: KindExclude, Source: "go.mod", OldPath: "example.com/a", OldVersion: "v1.0.0"}
	d := DiffScans(Record{Directives: []Directive{gone}}, Record{})
	if len(d.Removed) != 1 || d.Removed[0] != gone || !d.HasChanges() {
		t.Errorf("removed directive not reported: %+v", d)
	}
}

func TestCompareByIdentity_EqualIsZero(t *testing.T) {
	d := Directive{Kind: KindReplace, OldPath: "example.com/a"}
	if got := compareByIdentity(d, d); got != 0 {
		t.Errorf("compareByIdentity(d, d) = %d, want 0", got)
	}
}

// Build metadata compares equal as a version but is a different spelling, and
// the spelling breaks the tie.
func TestDirectiveLess_VersionsEqualBySemverOrderBySpelling(t *testing.T) {
	a := Directive{Kind: KindReplace, OldPath: "example.com/a", OldVersion: "v1.0.0+a", NewVersion: "v1.0.0+a"}
	b := a
	b.OldVersion = "v1.0.0+b"
	if !DirectiveLess(a, b) || DirectiveLess(b, a) {
		t.Error("old versions equal by semver are not ordered by spelling")
	}
	b = a
	b.NewVersion = "v1.0.0+b"
	if !DirectiveLess(a, b) || DirectiveLess(b, a) {
		t.Error("new versions equal by semver are not ordered by spelling")
	}
}

func TestDiffScans_OrdersReclassifications(t *testing.T) {
	x := Directive{Kind: KindReplace, Source: "go.mod", OldPath: "example.com/x", PolicyOutcome: "allow"}
	y := Directive{Kind: KindReplace, Source: "go.mod", OldPath: "example.com/y", PolicyOutcome: "allow"}
	x2, y2 := x, y
	x2.PolicyOutcome, y2.PolicyOutcome = "warn", "warn"
	d := DiffScans(Record{Directives: []Directive{y, x}}, Record{Directives: []Directive{y2, x2}})
	if len(d.Reclassified) != 2 || d.Reclassified[0].After.OldPath != "example.com/x" {
		t.Errorf("reclassifications not ordered by identity: %+v", d.Reclassified)
	}
}
