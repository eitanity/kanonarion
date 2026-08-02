package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestPolicyScopeForWalkScope pins the walk→policy scope translation. The two
// vocabularies share only "tool"; before the translation the default walk
// scope ("code") reached the policy engine verbatim, matched no rule, and
// every licence resolved to an implicit allow.
func TestPolicyScopeForWalkScope(t *testing.T) {
	cases := []struct {
		in   walkdomain.WalkScope
		want string
	}{
		{walkdomain.WalkScopeCode, "production"},
		{walkdomain.WalkScopeComplete, "production"},
		{walkdomain.WalkScopeTool, "tool"},
		// An unknown walk scope passes through so the policy engine's
		// unmatched-scope guard reports it rather than this function guessing.
		{walkdomain.WalkScope("mystery"), "mystery"},
	}
	for _, tc := range cases {
		if got := policyScopeForWalkScope(tc.in); got != tc.want {
			t.Errorf("policyScopeForWalkScope(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDefaultScopeEvaluatesStrongCopyleftAsWarn is the KN-regression the
// translation exists for: under the shipped config, the default walk scope
// must evaluate a GPL-3.0 module under the production rule (strong_copyleft →
// warn), never resolve it to allow because no rule matched. --tool keeps its
// own rule; --project evaluates as production.
func TestDefaultScopeEvaluatesStrongCopyleftAsWarn(t *testing.T) {
	policy := configdomain.DefaultConfig().LicensePolicy

	for _, tc := range []struct {
		walkScope walkdomain.WalkScope
		wantScope string
		wantOut   configdomain.PolicyOutcome
	}{
		{walkdomain.WalkScopeCode, "production", configdomain.PolicyOutcomeWarn},
		{walkdomain.WalkScopeComplete, "production", configdomain.PolicyOutcomeWarn},
		{walkdomain.WalkScopeTool, "tool", configdomain.PolicyOutcomeAllow},
	} {
		eval := policy.EvaluateLicense("GPL-3.0-only", policyScopeForWalkScope(tc.walkScope))
		if eval.Scope != tc.wantScope {
			t.Errorf("%s: evaluated scope = %q, want %q", tc.walkScope, eval.Scope, tc.wantScope)
		}
		if eval.Outcome != tc.wantOut {
			t.Errorf("%s: outcome = %q, want %q", tc.walkScope, eval.Outcome, tc.wantOut)
		}
		if eval.Unevaluated {
			t.Errorf("%s: gate reported unevaluated; the translation should always reach a rule", tc.walkScope)
		}
	}

	// A permissive licence under a matching rule still allows.
	if eval := policy.EvaluateLicense("MIT", policyScopeForWalkScope(walkdomain.WalkScopeCode)); eval.Outcome != configdomain.PolicyOutcomeAllow {
		t.Errorf("MIT under production = %q, want allow", eval.Outcome)
	}
}

// TestAuditLicenceResolution_MultipleIsUnresolved guards the audit rule that a
// Multiple licence status resolves no single SPDX, and that an identified
// disjunction is handed to the caller as arms rather than as an uncertainty.
func TestAuditLicenceResolution_MultipleIsUnresolved(t *testing.T) {
	rec := licdomain.LicenseRecord{
		PrimarySPDX:   "GPL-3.0",
		Expression:    "Apache-2.0 OR GPL-3.0",
		OverallStatus: licdomain.LicenseStatusMultiple,
	}
	display, status, resolved, reason, arms := auditLicenceResolution(rec, true, nil, "(not run)", "(not run)")
	if resolved != "" {
		t.Errorf("resolvedSPDX = %q, want empty (Multiple settles on no single identity)", resolved)
	}
	if reason != "multiple" {
		t.Errorf("uncertaintyReason = %q, want multiple", reason)
	}
	if display != "GPL-3.0" || status != "Multiple" {
		t.Errorf("display/status = %q/%q, want GPL-3.0/Multiple (display keeps the fact)", display, status)
	}
	if len(arms) != 2 || arms[0] != "Apache-2.0" || arms[1] != "GPL-3.0" {
		t.Errorf("arms = %v, want [Apache-2.0 GPL-3.0]", arms)
	}

	// A Multiple whose expression is conjunctive offers no election: no arms,
	// so the row keeps riding the unknown-licence machinery.
	conj := licdomain.LicenseRecord{
		PrimarySPDX:   "MIT",
		Expression:    "MIT AND BSD-3-Clause",
		OverallStatus: licdomain.LicenseStatusMultiple,
	}
	if _, _, _, _, arms = auditLicenceResolution(conj, true, nil, "(not run)", "(not run)"); arms != nil {
		t.Errorf("conjunction arms = %v, want none", arms)
	}

	// A determined single licence still resolves.
	det := licdomain.LicenseRecord{PrimarySPDX: "MIT", OverallStatus: licdomain.LicenseStatusDetected}
	_, _, resolved, _, arms = auditLicenceResolution(det, true, nil, "(not run)", "(not run)")
	if resolved != "MIT" || arms != nil {
		t.Errorf("Detected record resolvedSPDX = %q arms %v, want MIT/none", resolved, arms)
	}

	// A read error keeps the placeholders and resolves nothing.
	_, status, resolved, _, _ = auditLicenceResolution(licdomain.LicenseRecord{}, false, errors.New("boom"), "(not run)", "(not run)")
	if resolved != "" || status != "(not run)" {
		t.Errorf("errored lookup = resolved %q status %q, want empty/(not run)", resolved, status)
	}
}

// TestAuditBlockingErr_UnevaluatedNamesTheScopeGap guards that an unevaluated
// gate exits non-zero with a diagnostic naming the scope in force and the
// scopes that do carry rules.
func TestAuditBlockingErr_UnevaluatedNamesTheScopeGap(t *testing.T) {
	results := []auditModuleResult{
		{
			Coordinate:        "example.com/m@v1.0.0",
			PolicyBlocking:    true,
			PolicyUnevaluated: true,
			policyScope:       "mystery",
			policyRuleScopes:  []string{"production", "tool"},
		},
	}
	err := auditBlockingErr(results)
	if err == nil {
		t.Fatal("an unevaluated gate must not exit clean")
	}
	var exitErr *exitError
	if !errors.As(err, &exitErr) || exitErr.code != ExitPolicy {
		t.Fatalf("expected ExitPolicy exit error, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"unevaluated", `"mystery"`, "production, tool"} {
		if !strings.Contains(msg, want) {
			t.Errorf("diagnostic %q missing %q", msg, want)
		}
	}
}

// TestPrintAuditTable_UnevaluatedRow guards the table rendering: an
// unevaluated row names the scope gap instead of showing a bare outcome word.
func TestPrintAuditTable_UnevaluatedRow(t *testing.T) {
	var buf bytes.Buffer
	results := []auditModuleResult{
		{
			Coordinate:        "example.com/m@v1.0.0",
			PolicyOutcome:     "unevaluated",
			PolicyBlocking:    true,
			PolicyUnevaluated: true,
			policyScope:       "mystery",
			LicenseResolved:   true,
		},
	}
	if err := printAuditTable(&buf, results); err != nil {
		t.Fatalf("printAuditTable: %v", err)
	}
	if !strings.Contains(buf.String(), "unevaluated [no rule for scope mystery]") {
		t.Errorf("table output %q missing the unevaluated scope diagnostic", buf.String())
	}
}

// TestBuildStdlibAuditResult_FactlessAdoptsKnownLicence guards the decided
// factless behaviour: a stdlib node without custody facts reports the
// published BSD-3-Clause constant — the same answer the SBOM and
// license-compat give — labelled as knowledge ("stdlib-known"), while the
// custody gap itself stays visible in the verification column.
func TestBuildStdlibAuditResult_FactlessAdoptsKnownLicence(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	activeConfig = configdomain.DefaultConfig()

	coord, err := coordinate.NewModuleCoordinate("std", "v1.26.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	node := walkdomain.GraphNode{Coordinate: coord, ResolutionSource: walkdomain.ResolutionStdlib}
	ctr := &Container{QueryVuln: testfakes.NewFakeQueryVuln()}

	res := buildStdlibAuditResult(context.Background(), coord, node, "production", "walk-1", ctr)
	if res.License != walkdomain.StdlibLicenseSPDX {
		t.Errorf("License = %q, want %q", res.License, walkdomain.StdlibLicenseSPDX)
	}
	if res.LicenseSource != "stdlib-known" {
		t.Errorf("LicenseSource = %q, want stdlib-known (published knowledge, not extracted facts)", res.LicenseSource)
	}
	if res.LicenseStatus != "Known" {
		t.Errorf("LicenseStatus = %q, want Known", res.LicenseStatus)
	}
	if res.Verification != "(custody unavailable)" {
		t.Errorf("Verification = %q, want (custody unavailable) — the custody gap stays visible", res.Verification)
	}
	if !res.LicenseResolved || res.PolicyBlocking {
		t.Errorf("factless stdlib must evaluate cleanly: resolved=%v blocking=%v", res.LicenseResolved, res.PolicyBlocking)
	}
	if res.PolicyOutcome != string(configdomain.PolicyOutcomeAllow) {
		t.Errorf("PolicyOutcome = %q, want allow (BSD-3-Clause is permissive)", res.PolicyOutcome)
	}

	// With facts present the row relays the extracted evidence instead.
	node.Stdlib = &walkdomain.StdlibFacts{LicenseSPDX: "BSD-3-Clause", VerificationStatus: "VerifiedGoDevChecksum"}
	res = buildStdlibAuditResult(context.Background(), coord, node, "production", "walk-1", ctr)
	if res.LicenseSource != "stdlib-tarball" || res.LicenseStatus != "Detected" {
		t.Errorf("facts present: source/status = %q/%q, want stdlib-tarball/Detected", res.LicenseSource, res.LicenseStatus)
	}
	if res.Verification != "VerifiedGoDevChecksum" {
		t.Errorf("Verification = %q, want VerifiedGoDevChecksum", res.Verification)
	}
}
