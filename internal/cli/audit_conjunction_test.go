package cli

import (
	"testing"

	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// TestAuditRow_ConjunctionIsEvaluatedArmByArm pins the fix for the module this
// repo's own audit exited 5 on. A conjunction binds the consumer to every arm,
// so the row is the strictest arm's outcome — never an undetermined licence,
// which is what a fully determined "Apache-2.0 AND MIT" was reported as.
//
// The permissive pair is the release case and the restricted pair is the proof
// that the fold is an evaluation rather than a blanket allow: the permissive
// case alone would pass on code that ignored the arms entirely.
func TestAuditRow_ConjunctionIsEvaluatedArmByArm(t *testing.T) {
	cases := []struct {
		name          string
		path, version string
		expr, primary string
		wantPolicy    string
		wantGoverning string
		wantResolved  bool
		wantBlocking  bool
	}{
		{
			name: "permissive arms allow and name no governing arm",
			path: "gopkg.in/yaml.v3", version: "v3.0.1",
			expr: "Apache-2.0 AND MIT", primary: "MIT",
			wantPolicy: "allow [permissive]", wantResolved: true,
		},
		{
			name: "the restricted arm governs the permissive one",
			path: "example.com/mixed", version: "v1.0.0",
			expr: "MIT AND GPL-3.0-only", primary: "MIT",
			wantPolicy:    "warn [strong_copyleft] [governing: GPL-3.0-only]",
			wantGoverning: "GPL-3.0-only",
			wantResolved:  true,
		},
		{
			name: "an arm the policy has no category for is not folded",
			path: "example.com/unclassified", version: "v1.0.0",
			expr: "Apache-2.0 AND CC-BY-SA-4.0", primary: "Apache-2.0",
			wantPolicy: "warn [BLOCKED: multiple]", wantBlocking: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := auditRowForLicence(t, tc.path, tc.version, licdomain.LicenseRecord{
				PrimarySPDX:   tc.primary,
				Expression:    tc.expr,
				OverallStatus: licdomain.LicenseStatusMultiple,
			}, nil)

			if got := auditPolicyCell(res); got != tc.wantPolicy {
				t.Errorf("policy cell = %q, want %q", got, tc.wantPolicy)
			}
			if res.LicenseResolved != tc.wantResolved {
				t.Errorf("LicenseResolved = %v, want %v", res.LicenseResolved, tc.wantResolved)
			}
			if res.PolicyBlocking != tc.wantBlocking {
				t.Errorf("PolicyBlocking = %v, want %v", res.PolicyBlocking, tc.wantBlocking)
			}
			if len(res.LicenseElectableArms) != 0 {
				t.Errorf("electable arms = %v, want none: a conjunction offers no election", res.LicenseElectableArms)
			}
			switch {
			case tc.wantGoverning == "" && len(res.LicenseGoverningArms) != 0:
				t.Errorf("governing arms = %v, want none", res.LicenseGoverningArms)
			case tc.wantGoverning != "" &&
				(len(res.LicenseGoverningArms) != 1 || res.LicenseGoverningArms[0] != tc.wantGoverning):
				t.Errorf("governing arms = %v, want [%s]", res.LicenseGoverningArms, tc.wantGoverning)
			}
		})
	}
}

// TestAuditRow_ConjunctionWithUnclassifiedArmIsUnchanged holds the boundary the
// fold was narrowed to. The two modules whose conjunctions name a licence the
// shipped policy has no category for — a documentation licence and an embedded
// font licence — must read exactly as they did before conjunctions were
// evaluated at all: whether such an arm should govern the code outcome is a
// separate question, and folding them would have invented an answer to it.
func TestAuditRow_ConjunctionWithUnclassifiedArmIsUnchanged(t *testing.T) {
	for _, tc := range []struct{ path, version, expr, primary string }{
		{"github.com/opencontainers/go-digest", "v1.0.0", "Apache-2.0 AND CC-BY-SA-4.0", "Apache-2.0"},
		{"github.com/alecthomas/chroma/v2", "v2.27.0", "MIT AND OFL-1.1", "MIT"},
	} {
		res := auditRowForLicence(t, tc.path, tc.version, licdomain.LicenseRecord{
			PrimarySPDX:   tc.primary,
			Expression:    tc.expr,
			OverallStatus: licdomain.LicenseStatusMultiple,
		}, nil)

		if res.LicenseResolved {
			t.Errorf("%s: LicenseResolved = true; an unclassified arm leaves the composite unmeasured", tc.path)
		}
		if got := auditPolicyCell(res); got != "warn [BLOCKED: multiple]" {
			t.Errorf("%s: policy cell = %q, want warn [BLOCKED: multiple] (unchanged)", tc.path, got)
		}
		if len(res.LicenseGoverningArms) != 0 {
			t.Errorf("%s: governing arms = %v, want none: nothing was folded", tc.path, res.LicenseGoverningArms)
		}
	}
}
