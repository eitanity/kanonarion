package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

func TestLookupObligations_KnownPermissive(t *testing.T) {
	t.Run("MIT", func(t *testing.T) {
		o := domain.LookupObligations("MIT")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if !o.IncludeNotice {
			t.Error("MIT: IncludeNotice should be true")
		}
		if !o.IncludeLicenseText {
			t.Error("MIT: IncludeLicenseText should be true")
		}
		if o.StateChanges {
			t.Error("MIT: StateChanges should be false")
		}
		if o.DiscloseSource {
			t.Error("MIT: DiscloseSource should be false")
		}
		if o.SameLicense != domain.CopyleftNone {
			t.Errorf("MIT: SameLicense should be none, got %s", o.SameLicense)
		}
		if o.NetworkUseTrigger {
			t.Error("MIT: NetworkUseTrigger should be false")
		}
		if o.NoTrademarkUse {
			t.Error("MIT: NoTrademarkUse should be false")
		}
		if o.ExplicitPatentGrant {
			t.Error("MIT: ExplicitPatentGrant should be false")
		}
	})

	t.Run("BSD-3-Clause", func(t *testing.T) {
		o := domain.LookupObligations("BSD-3-Clause")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if !o.IncludeNotice {
			t.Error("BSD-3-Clause: IncludeNotice should be true")
		}
		if !o.IncludeLicenseText {
			t.Error("BSD-3-Clause: IncludeLicenseText should be true")
		}
		if !o.NoTrademarkUse {
			t.Error("BSD-3-Clause: NoTrademarkUse should be true (clause 3)")
		}
		if o.SameLicense != domain.CopyleftNone {
			t.Errorf("BSD-3-Clause: SameLicense should be none, got %s", o.SameLicense)
		}
		if o.DiscloseSource {
			t.Error("BSD-3-Clause: DiscloseSource should be false")
		}
	})

	t.Run("Apache-2.0", func(t *testing.T) {
		o := domain.LookupObligations("Apache-2.0")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if !o.IncludeNotice {
			t.Error("Apache-2.0: IncludeNotice should be true")
		}
		if !o.IncludeLicenseText {
			t.Error("Apache-2.0: IncludeLicenseText should be true")
		}
		if !o.StateChanges {
			t.Error("Apache-2.0: StateChanges should be true (§4b)")
		}
		if !o.NoTrademarkUse {
			t.Error("Apache-2.0: NoTrademarkUse should be true (§6)")
		}
		if !o.ExplicitPatentGrant {
			t.Error("Apache-2.0: ExplicitPatentGrant should be true (§3)")
		}
		if o.DiscloseSource {
			t.Error("Apache-2.0: DiscloseSource should be false")
		}
		if o.SameLicense != domain.CopyleftNone {
			t.Errorf("Apache-2.0: SameLicense should be none, got %s", o.SameLicense)
		}
	})
}

func TestLookupObligations_WeakCopyleft(t *testing.T) {
	t.Run("MPL-2.0", func(t *testing.T) {
		o := domain.LookupObligations("MPL-2.0")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if o.SameLicense != domain.CopyleftWeak {
			t.Errorf("MPL-2.0: SameLicense should be weak, got %s", o.SameLicense)
		}
		if !o.DiscloseSource {
			t.Error("MPL-2.0: DiscloseSource should be true (file-level)")
		}
		if !o.ExplicitPatentGrant {
			t.Error("MPL-2.0: ExplicitPatentGrant should be true (§2.1)")
		}
		if o.NetworkUseTrigger {
			t.Error("MPL-2.0: NetworkUseTrigger should be false")
		}
	})

	t.Run("LGPL-2.1-only", func(t *testing.T) {
		o := domain.LookupObligations("LGPL-2.1-only")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if o.SameLicense != domain.CopyleftWeak {
			t.Errorf("LGPL-2.1-only: SameLicense should be weak, got %s", o.SameLicense)
		}
		if !o.DiscloseSource {
			t.Error("LGPL-2.1-only: DiscloseSource should be true")
		}
	})
}

func TestLookupObligations_StrongCopyleft(t *testing.T) {
	t.Run("GPL-3.0-only", func(t *testing.T) {
		o := domain.LookupObligations("GPL-3.0-only")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if o.SameLicense != domain.CopyleftStrong {
			t.Errorf("GPL-3.0-only: SameLicense should be strong, got %s", o.SameLicense)
		}
		if !o.DiscloseSource {
			t.Error("GPL-3.0-only: DiscloseSource should be true")
		}
		if !o.ExplicitPatentGrant {
			t.Error("GPL-3.0-only: ExplicitPatentGrant should be true (§11)")
		}
		if o.NetworkUseTrigger {
			t.Error("GPL-3.0-only: NetworkUseTrigger should be false")
		}
	})
}

func TestLookupObligations_NetworkCopyleft(t *testing.T) {
	t.Run("AGPL-3.0-only", func(t *testing.T) {
		o := domain.LookupObligations("AGPL-3.0-only")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if o.SameLicense != domain.CopyleftNetwork {
			t.Errorf("AGPL-3.0-only: SameLicense should be network, got %s", o.SameLicense)
		}
		if !o.NetworkUseTrigger {
			t.Error("AGPL-3.0-only: NetworkUseTrigger should be true (§13)")
		}
		if !o.DiscloseSource {
			t.Error("AGPL-3.0-only: DiscloseSource should be true")
		}
		if !o.ExplicitPatentGrant {
			t.Error("AGPL-3.0-only: ExplicitPatentGrant should be true")
		}
	})
}

func TestLookupObligations_StoreGapsFilled(t *testing.T) {
	// Identifiers that appeared as "unknown" when auditing real-world dependencies (v1.1.0 additions).
	t.Run("LGPL-3.0 deprecated form", func(t *testing.T) {
		o := domain.LookupObligations("LGPL-3.0")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if o.SameLicense != domain.CopyleftWeak {
			t.Errorf("LGPL-3.0: SameLicense should be weak, got %s", o.SameLicense)
		}
		if !o.DiscloseSource {
			t.Error("LGPL-3.0: DiscloseSource should be true")
		}
	})

	t.Run("GPL-2.0 deprecated form", func(t *testing.T) {
		o := domain.LookupObligations("GPL-2.0")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if o.SameLicense != domain.CopyleftStrong {
			t.Errorf("GPL-2.0: SameLicense should be strong, got %s", o.SameLicense)
		}
		if !o.DiscloseSource {
			t.Error("GPL-2.0: DiscloseSource should be true")
		}
	})

	t.Run("GPL-3.0 deprecated form", func(t *testing.T) {
		o := domain.LookupObligations("GPL-3.0")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if o.SameLicense != domain.CopyleftStrong {
			t.Errorf("GPL-3.0: SameLicense should be strong, got %s", o.SameLicense)
		}
		if !o.ExplicitPatentGrant {
			t.Error("GPL-3.0: ExplicitPatentGrant should be true")
		}
	})

	t.Run("BSD-2-Clause-Views", func(t *testing.T) {
		o := domain.LookupObligations("BSD-2-Clause-Views")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if !o.IncludeNotice || !o.IncludeLicenseText {
			t.Error("BSD-2-Clause-Views: IncludeNotice and IncludeLicenseText should be true")
		}
		if o.SameLicense != domain.CopyleftNone {
			t.Errorf("BSD-2-Clause-Views: SameLicense should be none, got %s", o.SameLicense)
		}
	})

	t.Run("CC-BY-4.0", func(t *testing.T) {
		o := domain.LookupObligations("CC-BY-4.0")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if !o.IncludeNotice || !o.IncludeLicenseText {
			t.Error("CC-BY-4.0: IncludeNotice and IncludeLicenseText should be true")
		}
		if !o.StateChanges {
			t.Error("CC-BY-4.0: StateChanges should be true (§3(a)(1)(B))")
		}
		if !o.NoTrademarkUse {
			t.Error("CC-BY-4.0: NoTrademarkUse should be true")
		}
		if o.SameLicense != domain.CopyleftNone {
			t.Errorf("CC-BY-4.0: SameLicense should be none, got %s", o.SameLicense)
		}
	})

	t.Run("OFL-1.1", func(t *testing.T) {
		o := domain.LookupObligations("OFL-1.1")
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("expected known, got %s", o.Status)
		}
		if !o.IncludeNotice || !o.IncludeLicenseText {
			t.Error("OFL-1.1: IncludeNotice and IncludeLicenseText should be true")
		}
		if o.SameLicense != domain.CopyleftWeak {
			t.Errorf("OFL-1.1: SameLicense should be weak (font-level), got %s", o.SameLicense)
		}
		if !o.NoTrademarkUse {
			t.Error("OFL-1.1: NoTrademarkUse should be true (reserved font name clause)")
		}
	})
}

func TestLookupObligations_CCBYSA30(t *testing.T) {
	o := domain.LookupObligations("CC-BY-SA-3.0")
	if o.Status != domain.ObligationStatusKnown {
		t.Fatalf("expected known, got %s", o.Status)
	}
	if !o.IncludeNotice || !o.IncludeLicenseText {
		t.Error("CC-BY-SA-3.0: IncludeNotice and IncludeLicenseText should be true")
	}
	if !o.StateChanges {
		t.Error("CC-BY-SA-3.0: StateChanges should be true (§4(b))")
	}
	if o.SameLicense != domain.CopyleftStrong {
		t.Errorf("CC-BY-SA-3.0: SameLicense should be strong (ShareAlike), got %s", o.SameLicense)
	}
	if !o.NoTrademarkUse {
		t.Error("CC-BY-SA-3.0: NoTrademarkUse should be true")
	}
}

func TestLookupObligations_Unknown(t *testing.T) {
	unknown := domain.LookupObligations("LicenseRef-custom-proprietary")
	if unknown.Status != domain.ObligationStatusUnknown {
		t.Fatalf("expected unknown status, got %s", unknown.Status)
	}
	// absence of catalogue entry must be explicit, not silently zero.
	if unknown.Status.String() != "unknown" {
		t.Errorf("expected string 'unknown', got %q", unknown.Status.String())
	}
}

func TestObligationStatusString(t *testing.T) {
	if domain.ObligationStatusKnown.String() != "known" {
		t.Errorf("expected 'known', got %q", domain.ObligationStatusKnown.String())
	}
	if domain.ObligationStatusUnknown.String() != "unknown" {
		t.Errorf("expected 'unknown', got %q", domain.ObligationStatusUnknown.String())
	}
}

func TestLookupObligations_AllCatalogueEntriesHaveKnownStatus(t *testing.T) {
	// Spot-check all licenses in the compat engine — they must all be in the catalogue.
	knownLicenses := []string{
		"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib",
		"0BSD", "Unlicense", "CC0-1.0", "BlueOak-1.0.0", "BSD-4-Clause",
		"MPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only",
		"LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
		"EPL-1.0", "EPL-2.0", "EUPL-1.2", "CDDL-1.0",
		"GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
		"EUPL-1.1", "BUSL-1.1", "SSPL-1.0", "Elastic-2.0",
		"AGPL-3.0-only", "AGPL-3.0-or-later", "OSL-3.0",
	}
	for _, spdx := range knownLicenses {
		o := domain.LookupObligations(spdx)
		if o.Status != domain.ObligationStatusKnown {
			t.Errorf("%s: expected known status, got %s", spdx, o.Status)
		}
	}
}

func TestLookupObligations_PublicDomainNoConditions(t *testing.T) {
	for _, spdx := range []string{"0BSD", "Unlicense", "CC0-1.0"} {
		o := domain.LookupObligations(spdx)
		if o.Status != domain.ObligationStatusKnown {
			t.Fatalf("%s: expected known, got %s", spdx, o.Status)
		}
		if o.IncludeNotice || o.IncludeLicenseText || o.StateChanges ||
			o.DiscloseSource || o.NetworkUseTrigger || o.NoTrademarkUse || o.ExplicitPatentGrant {
			t.Errorf("%s: public domain licences should have no conditions", spdx)
		}
		if o.SameLicense != domain.CopyleftNone {
			t.Errorf("%s: SameLicense should be none, got %s", spdx, o.SameLicense)
		}
	}
}

// TestUnionObligations_AnyArmRequiringADutyMakesItOwed pins the first union
// rule on the expression that exposed the defect: gopkg.in/yaml.v3 is
// "Apache-2.0 AND MIT", and MIT alone answers false to three duties Apache-2.0
// imposes. Under a conjunction both licences bind, so all three are owed.
func TestUnionObligations_AnyArmRequiringADutyMakesItOwed(t *testing.T) {
	// Each case names the arm that imposes the duty, and the arms are given in
	// their sorted order, so the imposing arm is sometimes first and sometimes
	// not: a merge that reads one arm and stops drops a named duty here.
	for _, tc := range []struct {
		arms     []string
		duty     string
		owedBy   string
		read     func(domain.Obligations) bool
		wantOwed bool
	}{
		{[]string{"Apache-2.0", "MIT"}, "StateChanges", "Apache-2.0",
			func(o domain.Obligations) bool { return o.StateChanges }, true},
		{[]string{"Apache-2.0", "MIT"}, "ExplicitPatentGrant", "Apache-2.0",
			func(o domain.Obligations) bool { return o.ExplicitPatentGrant }, true},
		{[]string{"MIT", "OFL-1.1"}, "NoTrademarkUse", "OFL-1.1",
			func(o domain.Obligations) bool { return o.NoTrademarkUse }, true},
		{[]string{"MIT", "GPL-3.0-only"}, "DiscloseSource", "GPL-3.0-only",
			func(o domain.Obligations) bool { return o.DiscloseSource }, true},
		{[]string{"MIT", "OFL-1.1"}, "ExplicitPatentGrant", "neither arm",
			func(o domain.Obligations) bool { return o.ExplicitPatentGrant }, false},
		{[]string{"Apache-2.0", "MIT"}, "NetworkUseTrigger", "neither arm",
			func(o domain.Obligations) bool { return o.NetworkUseTrigger }, false},
	} {
		u := domain.UnionObligations(tc.arms)
		if u.Status != domain.ObligationStatusKnown {
			t.Fatalf("%v: Status = %s, want known: every arm is in the catalogue", tc.arms, u.Status)
		}
		switch got := tc.read(u); {
		case tc.wantOwed && !got:
			t.Errorf("%s: %s is false, but the %s arm requires it — the union dropped a duty "+
				"the consumer owes", strings.Join(tc.arms, " AND "), tc.duty, tc.owedBy)
		case !tc.wantOwed && got:
			t.Errorf("%s: %s is true, but %s requires it — the union invented a duty",
				strings.Join(tc.arms, " AND "), tc.duty, tc.owedBy)
		}
	}
}

// TestUnionObligations_ArmOrderDoesNotDecide is the other half of the rule: no
// arm is privileged, so the merged set is the same whichever arm comes first.
// Taking one arm's set as the answer — which is what PrimarySPDX did — fails
// here as well as above.
func TestUnionObligations_ArmOrderDoesNotDecide(t *testing.T) {
	for _, pair := range [][2]string{
		{"Apache-2.0", "MIT"},
		{"MIT", "OFL-1.1"},
		{"Apache-2.0", "BSD-3-Clause"},
		{"MIT", "GPL-3.0-only"},
	} {
		forward := domain.UnionObligations([]string{pair[0], pair[1]})
		reverse := domain.UnionObligations([]string{pair[1], pair[0]})
		if forward != reverse {
			t.Errorf("%s AND %s: union depends on arm order (%+v vs %+v)",
				pair[0], pair[1], forward, reverse)
		}
	}
}

// TestUnionObligations_SameLicenseTakesTheStrongestArm pins the second rule.
// SameLicense is a strength, not a boolean, and the strictest propagation is
// the one that governs the combined work: chroma/v2's "MIT AND OFL-1.1" is
// OFL's weak, not MIT's none.
func TestUnionObligations_SameLicenseTakesTheStrongestArm(t *testing.T) {
	for _, tc := range []struct {
		arms []string
		want domain.CopyleftStrength
	}{
		{[]string{"MIT", "OFL-1.1"}, domain.CopyleftWeak},
		{[]string{"MIT", "Apache-2.0"}, domain.CopyleftNone},
		{[]string{"MPL-2.0", "GPL-3.0-only"}, domain.CopyleftStrong},
		{[]string{"MIT", "AGPL-3.0-only"}, domain.CopyleftNetwork},
	} {
		got := domain.UnionObligations(tc.arms).SameLicense
		if got != tc.want {
			t.Errorf("UnionObligations(%v).SameLicense = %s, want %s — the union must take the "+
				"strongest arm's propagation, not the weakest", tc.arms, got, tc.want)
		}
	}
}

// TestUnionObligations_OneUncataloguedArmMakesTheMergeUnknown pins the third
// rule. A merge that saw only the arms it recognised has part of what binds,
// and reporting it as known would publish that part as the whole.
func TestUnionObligations_OneUncataloguedArmMakesTheMergeUnknown(t *testing.T) {
	u := domain.UnionObligations([]string{"MIT", "LicenseRef-custom-proprietary"})
	if u.Status != domain.ObligationStatusUnknown {
		t.Errorf("Status = %s, want unknown: LicenseRef-custom-proprietary is not in the catalogue, "+
			"so the merged set is incomplete", u.Status)
	}
	if !u.IncludeNotice {
		t.Error("the MIT arm's duties must still be carried; unknown says the set is incomplete, " +
			"not that nothing was found")
	}
}

// TestUnionObligations_DegenerateArmCounts covers the two inputs that are not
// conjunctions: nothing to merge is unknown, never "no obligations", and one
// arm is that arm.
func TestUnionObligations_DegenerateArmCounts(t *testing.T) {
	if got := domain.UnionObligations(nil); got.Status != domain.ObligationStatusUnknown {
		t.Errorf("UnionObligations(nil).Status = %s, want unknown", got.Status)
	}
	for _, id := range []string{"MIT", "Apache-2.0", "AGPL-3.0-only", "LicenseRef-nope"} {
		if got, want := domain.UnionObligations([]string{id}), domain.LookupObligations(id); got != want {
			t.Errorf("UnionObligations([%q]) = %+v, want the licence's own set %+v", id, got, want)
		}
	}
}

// TestMaximalObligations_MergesTheSameFieldsAsTheUnion pins that the two
// readings differ only in what they make of an uncatalogued arm: the duties
// merged are the same.
func TestMaximalObligations_MergesTheSameFieldsAsTheUnion(t *testing.T) {
	for _, arms := range [][]string{
		{"Apache-2.0", "MIT"},
		{"MIT", "OFL-1.1"},
		{"Apache-2.0", "BSD-3-Clause"},
		{"MIT", "AGPL-3.0-only"},
	} {
		u, m := domain.UnionObligations(arms), domain.MaximalObligations(arms)
		u.Status, m.Status = 0, 0
		if u != m {
			t.Errorf("%v: maximal and union merged different duties (%+v vs %+v)", arms, m, u)
		}
	}
}

// TestMaximalObligations_OneUncataloguedArmDoesNotDegradeTheSet is the rule
// that separates it from UnionObligations. go-digest's Apache-2.0 arm covers
// the code and is catalogued at full confidence; CC-BY-SA-4.0 covers
// LICENSE.docs and is not. Because those arms are separable, the uncatalogued
// one is news about that arm, carried on that arm's own row.
func TestMaximalObligations_OneUncataloguedArmDoesNotDegradeTheSet(t *testing.T) {
	arms := []string{"Apache-2.0", "CC-BY-SA-4.0"}
	if got := domain.MaximalObligations(arms).Status; got != domain.ObligationStatusKnown {
		t.Errorf("MaximalObligations(%v).Status = %s, want known: one arm is catalogued and the "+
			"arms are separable, so the record must not degrade", arms, got)
	}
	if got := domain.UnionObligations(arms).Status; got != domain.ObligationStatusUnknown {
		t.Errorf("UnionObligations(%v).Status = %s, want unknown: read as inseparable the merge "+
			"saw part of what binds", arms, got)
	}
	// Nothing catalogued at all is unknown under either reading.
	none := []string{"LicenseRef-a", "LicenseRef-b"}
	if got := domain.MaximalObligations(none).Status; got != domain.ObligationStatusUnknown {
		t.Errorf("MaximalObligations(%v).Status = %s, want unknown", none, got)
	}
	if got := domain.MaximalObligations(nil).Status; got != domain.ObligationStatusUnknown {
		t.Errorf("MaximalObligations(nil).Status = %s, want unknown", got)
	}
}

// TestArmsAreSeparatelyGranted_ReadsOnlyTheRecordedBasis pins that the
// classification comes from the basis the pipeline wrote, and from the exact
// string it writes.
func TestArmsAreSeparatelyGranted_ReadsOnlyTheRecordedBasis(t *testing.T) {
	if !domain.ArmsAreSeparatelyGranted(domain.BasisSeparateGrants) {
		t.Error("the constant the pipeline writes is not recognised by the reader")
	}
	for _, basis := range []string{
		"",
		"split: is licensed under",
		"split: covered by two different licenses",
		"split: the following files",
		"conservative: no statement of how the grants relate",
		"election: one file per licence (APLv2, LICENSE)",
	} {
		if domain.ArmsAreSeparatelyGranted(basis) {
			t.Errorf("basis %q read as separately granted", basis)
		}
	}
}

// TestArmGrants_NamesTheFileThatGrantsEachArm pins the coverage evidence, and
// that only files which built the expression can supply it.
func TestArmGrants_NamesTheFileThatGrantsEachArm(t *testing.T) {
	entries := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "Apache-2.0"},
		{Path: "LICENSE.libyaml", SPDX: "MIT"},
		{Path: "NOTICE", SPDX: "Apache-2.0"},
		{Path: "contrib/other/LICENSE", SPDX: "MIT"},
		{Path: "vendor/x/LICENSE", SPDX: "MIT", IsVendored: true},
	}
	got := domain.ArmGrants("Apache-2.0 AND MIT", entries)
	want := map[string][]string{"Apache-2.0": {"LICENSE"}, "MIT": {"LICENSE.libyaml"}}
	if len(got) != len(want) {
		t.Fatalf("ArmGrants = %v, want %v", got, want)
	}
	for arm, paths := range want {
		if len(got[arm]) != 1 || got[arm][0] != paths[0] {
			t.Errorf("ArmGrants[%q] = %v, want %v — a NOTICE, a nested licence and a vendored "+
				"file granted no arm and must not be published as coverage", arm, got[arm], paths)
		}
	}
	if domain.ArmGrants("MIT", entries) != nil {
		t.Error("a single identifier has no arms to attribute")
	}
	if domain.ArmGrants("Apache-2.0 OR MIT", entries) != nil {
		t.Error("a disjunction is an election, not a set of separately granted arms")
	}
}
