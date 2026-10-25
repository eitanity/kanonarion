package domain

import (
	"strings"
	"testing"
)

// Each governance block refuses an outcome outside allow, notify and warn, and
// ValidateGovernance reports the first block that does.
func TestGovernance_RefusesAnUnknownOutcome(t *testing.T) {
	const bad PolicyOutcome = "block"
	for _, tc := range []struct {
		cfg  Config
		want string
	}{
		{Config{DirectivePolicy: DirectivePolicy{Default: bad}}, "directive_policy.default"},
		{Config{GoDebugPolicy: GoDebugPolicy{Red: bad}}, "godebug_policy.red"},
		{Config{VendorPolicy: VendorPolicy{OnDrift: bad}}, "vendor_policy.on_drift"},
		{Config{FIPSPolicy: FIPSPolicy{OnDeviation: bad}}, "fips_policy.on_deviation"},
	} {
		if err := tc.cfg.ValidateGovernance(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", tc.want, err)
		}
	}
}

// Every directive category reads its own outcome; an unknown GODEBUG tier
// takes the configured red posture.
func TestGovernance_EvaluateReadsEachCategory(t *testing.T) {
	d := DirectivePolicy{
		LocalPathReplace: PolicyOutcomeWarn, ModulePathReplace: PolicyOutcomeNotify, VersionReplace: PolicyOutcomeWarn,
		ExcludeNewer: PolicyOutcomeNotify, ExcludeOlder: PolicyOutcomeWarn,
	}
	for cat, want := range map[string]PolicyOutcome{
		DirectiveLocalPathReplace: PolicyOutcomeWarn, DirectiveModulePathReplace: PolicyOutcomeNotify,
		DirectiveVersionReplace: PolicyOutcomeWarn, DirectiveExcludeNewer: PolicyOutcomeNotify, DirectiveExcludeOlder: PolicyOutcomeWarn,
	} {
		if got := d.Evaluate(cat); got != want {
			t.Errorf("directive %s = %q, want %q", cat, got, want)
		}
	}
	if got := (GoDebugPolicy{Red: PolicyOutcomeNotify}).Evaluate("unclassified"); got != PolicyOutcomeNotify {
		t.Errorf("unknown tier = %q, want the red posture", got)
	}
	if got := (GoDebugPolicy{}).Evaluate("unclassified"); got != PolicyOutcomeWarn {
		t.Errorf("unknown tier with no red posture = %q, want warn", got)
	}
	if got := (VendorPolicy{}).Evaluate(VendorInconsistency); got != PolicyOutcomeAllow {
		t.Errorf("unset inconsistency posture = %q, want allow", got)
	}
	if err := (FIPSPolicy{OnDeviation: PolicyOutcomeWarn}).Validate(); err != nil {
		t.Errorf("a valid FIPS posture was refused: %v", err)
	}
}

// An unknown vendor finding takes the stricter posture, unset counting as warn.
func TestStricterOutcome(t *testing.T) {
	for _, tc := range []struct{ a, b, want PolicyOutcome }{
		{PolicyOutcomeNotify, PolicyOutcomeAllow, PolicyOutcomeNotify},
		{PolicyOutcomeAllow, PolicyOutcomeNotify, PolicyOutcomeNotify},
		{PolicyOutcomeAllow, "", PolicyOutcomeWarn},
		{"", PolicyOutcomeAllow, PolicyOutcomeWarn},
	} {
		if got := stricterOutcome(tc.a, tc.b); got != tc.want {
			t.Errorf("stricterOutcome(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// An override needs its identifier, and all of its provenance or none of it.
func TestLicenseOverride_Validate(t *testing.T) {
	full := LicenseOverride{SPDX: "MIT", DeclaredBy: "a", DeclaredOn: "2026-01-31", Basis: "README"}
	for _, tc := range []struct {
		o    LicenseOverride
		want string
	}{
		{LicenseOverride{}, "spdx is required"},
		{LicenseOverride{SPDX: "MIT"}, ""},
		{full, ""},
		{LicenseOverride{SPDX: "MIT", DeclaredBy: "a"}, "declared_on is required"},
		{LicenseOverride{SPDX: "MIT", DeclaredBy: "a", DeclaredOn: "31/01/2026", Basis: "b"}, "must be an ISO 8601 date"},
	} {
		err := tc.o.Validate()
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%+v: err = %v, want %q", tc.o, err, tc.want)
		}
	}
	if !full.Attributed() || (LicenseOverride{SPDX: "MIT"}).Attributed() {
		t.Error("Attributed does not follow the provenance fields")
	}
}

// Production fails closed on an undetermined licence; every other scope warns.
func TestDefaultUnknownLicense(t *testing.T) {
	if DefaultUnknownLicense("production") != UnknownLicenseBlock || DefaultUnknownLicense("tool") != UnknownLicenseWarn {
		t.Error("DefaultUnknownLicense")
	}
}
