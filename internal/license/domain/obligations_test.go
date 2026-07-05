package domain_test

import (
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
