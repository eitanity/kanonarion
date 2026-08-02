package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// unfetchedQueryFetch reports every module as never fetched: these cases turn
// on the licence gate alone, so the verification column is deliberately inert.
type unfetchedQueryFetch struct{}

func (unfetchedQueryFetch) GetFetchRecord(context.Context, coordinate.ModuleCoordinate, string) (fetchdomain.CompositeRecord, bool, error) {
	return fetchdomain.CompositeRecord{}, false, nil
}

func (unfetchedQueryFetch) ComposeFetchRecord(context.Context, coordinate.ModuleCoordinate) (fetchdomain.CompositeRecord, bool, error) {
	return fetchdomain.CompositeRecord{}, false, nil
}

// auditRowForLicence builds one audit row for a module carrying the given
// licence record under the shipped default policy, so the disjunction cases can
// be exercised through the same path the command uses.
func auditRowForLicence(t *testing.T, path, version string, rec licdomain.LicenseRecord, overrides map[string]string) auditModuleResult {
	t.Helper()
	prev := activeConfig
	t.Cleanup(func() { activeConfig = prev })
	activeConfig = configdomain.DefaultConfig()

	coord, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	lic := testfakes.NewFakeQueryLicense()
	lic.AddRecord(coord, licapp.PipelineVersion, rec)
	ctr := &Container{
		QueryFetch:   unfetchedQueryFetch{},
		QueryLicense: lic,
		QueryVuln:    testfakes.NewFakeQueryVuln(),
	}
	node := walkdomain.GraphNode{Coordinate: coord}

	res, err := buildAuditResult(context.Background(), node, vulnFrameAnchor{walkID: "walk-1"}, "production",
		licdomain.NewLicenseOverrideSet(overrides), nil, ctr, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("buildAuditResult: %v", err)
	}
	return res
}

// TestAuditRow_AllowedDisjunctionDoesNotBlock pins one of the two modules
// kanonarion's own audit blocked on: a choice of licences every arm of which
// the production rule allows must read as an allow, not as an undetermined
// licence. (The other, klauspost/compress, is covered by
// TestAuditRow_MultipleWithOneIdentifierResolves — its record carries a single
// identifier, not a disjunction.)
func TestAuditRow_AllowedDisjunctionDoesNotBlock(t *testing.T) {
	cases := []struct {
		path, version string
		expr, primary string
		wantArms      string
	}{
		{
			path: "gopkg.in/yaml.v3", version: "v3.0.1",
			expr: "Apache-2.0 OR MIT", primary: "MIT",
			wantArms: "Apache-2.0 or MIT",
		},
	}
	for _, tc := range cases {
		res := auditRowForLicence(t, tc.path, tc.version, licdomain.LicenseRecord{
			PrimarySPDX:   tc.primary,
			Expression:    tc.expr,
			OverallStatus: licdomain.LicenseStatusMultiple,
		}, nil)

		if res.PolicyOutcome != string(configdomain.PolicyOutcomeAllow) {
			t.Errorf("%s: policy outcome = %q, want allow", tc.path, res.PolicyOutcome)
		}
		if res.PolicyBlocking {
			t.Errorf("%s: row is blocking; every arm is allowed", tc.path)
		}
		if !res.LicenseResolved || res.LicenseUncertainty != "" {
			t.Errorf("%s: resolved=%v uncertainty=%q, want resolved with no uncertainty",
				tc.path, res.LicenseResolved, res.LicenseUncertainty)
		}
		if res.LicenseStatus != "Multiple" {
			t.Errorf("%s: licence status = %q, want Multiple (the display fact is kept)", tc.path, res.LicenseStatus)
		}
		if got := strings.Join(res.LicenseElectableArms, " or "); got != tc.wantArms {
			t.Errorf("%s: electable arms = %q, want %q", tc.path, got, tc.wantArms)
		}
		if err := auditBlockingErr([]auditModuleResult{res}); err != nil {
			t.Errorf("%s: audit exits non-zero: %v", tc.path, err)
		}

		var buf bytes.Buffer
		if err := printAuditTable(&buf, []auditModuleResult{res}); err != nil {
			t.Fatalf("printAuditTable: %v", err)
		}
		if !strings.Contains(buf.String(), "electable: "+tc.wantArms) {
			t.Errorf("%s: table %q does not name the electable arms", tc.path, buf.String())
		}
	}
}

// TestAuditRow_DisjunctionOutcomes covers the remaining decided cases: a single
// permissive arm carries the choice, a disjunction with no allowed arm keeps
// the least-bad arm's outcome rather than escalating to a block, an
// unidentified status still blocks, and a recorded election settles the row
// wholesale.
func TestAuditRow_DisjunctionOutcomes(t *testing.T) {
	multiple := func(primary, expr string) licdomain.LicenseRecord {
		return licdomain.LicenseRecord{PrimarySPDX: primary, Expression: expr, OverallStatus: licdomain.LicenseStatusMultiple}
	}

	tests := []struct {
		name         string
		rec          licdomain.LicenseRecord
		overrides    map[string]string
		wantOutcome  configdomain.PolicyOutcome
		wantBlocking bool
		wantArms     []string
		wantCategory string
	}{
		{
			name:         "permissive arm carries a copyleft choice",
			rec:          multiple("GPL-3.0-only", "Apache-2.0 OR GPL-3.0-only"),
			wantOutcome:  configdomain.PolicyOutcomeAllow,
			wantArms:     []string{"Apache-2.0"},
			wantCategory: "permissive",
		},
		{
			name:         "no allowed arm warns, as a single restricted licence would",
			rec:          multiple("GPL-3.0-only", "GPL-2.0-only OR GPL-3.0-only"),
			wantOutcome:  configdomain.PolicyOutcomeWarn,
			wantArms:     []string{"GPL-2.0-only", "GPL-3.0-only"},
			wantCategory: "strong_copyleft",
		},
		{
			name:         "an unclassified licence still blocks",
			rec:          licdomain.LicenseRecord{OverallStatus: licdomain.LicenseStatusUnclassified},
			wantOutcome:  configdomain.PolicyOutcomeWarn,
			wantBlocking: true,
		},
		{
			name:         "a conjunction is not an election and still blocks",
			rec:          multiple("MIT", "BSD-3-Clause AND MIT"),
			wantOutcome:  configdomain.PolicyOutcomeWarn,
			wantBlocking: true,
		},
		{
			name:        "a recorded election settles the row wholesale",
			rec:         multiple("GPL-3.0-only", "Apache-2.0 OR GPL-3.0-only"),
			overrides:   map[string]string{"example.com/mod": "GPL-3.0-only"},
			wantOutcome: configdomain.PolicyOutcomeWarn,
			// The elected licence is the whole answer: no arms remain to elect.
			wantCategory: "strong_copyleft",
		},
	}

	for _, tc := range tests {
		res := auditRowForLicence(t, "example.com/mod", "v1.0.0", tc.rec, tc.overrides)
		if res.PolicyOutcome != string(tc.wantOutcome) {
			t.Errorf("%s: outcome = %q, want %q", tc.name, res.PolicyOutcome, tc.wantOutcome)
		}
		if res.PolicyBlocking != tc.wantBlocking {
			t.Errorf("%s: blocking = %v, want %v", tc.name, res.PolicyBlocking, tc.wantBlocking)
		}
		if strings.Join(res.LicenseElectableArms, ",") != strings.Join(tc.wantArms, ",") {
			t.Errorf("%s: electable arms = %v, want %v", tc.name, res.LicenseElectableArms, tc.wantArms)
		}
		if res.LicenseCategory != tc.wantCategory {
			t.Errorf("%s: category = %q, want %q", tc.name, res.LicenseCategory, tc.wantCategory)
		}
	}
}

// TestAuditRow_MultipleWithOneIdentifierResolves pins the second module
// kanonarion's own audit blocked on. github.com/klauspost/compress ships one
// LICENSE file bundling third-party texts, so its status is Multiple while its
// derived expression names a single licence — Apache-2.0, which the production
// rule allows. The row must read that licence rather than treating a settled
// identity as an unknown.
func TestAuditRow_MultipleWithOneIdentifierResolves(t *testing.T) {
	res := auditRowForLicence(t, "github.com/klauspost/compress", "v1.19.0", licdomain.LicenseRecord{
		PrimarySPDX:   "Apache-2.0",
		Expression:    "Apache-2.0",
		OverallStatus: licdomain.LicenseStatusMultiple,
	}, nil)

	if res.PolicyOutcome != string(configdomain.PolicyOutcomeAllow) || res.PolicyBlocking {
		t.Errorf("outcome = %q blocking = %v, want allow/false", res.PolicyOutcome, res.PolicyBlocking)
	}
	if !res.LicenseResolved || res.LicenseUncertainty != "" {
		t.Errorf("resolved = %v uncertainty = %q, want resolved with no uncertainty",
			res.LicenseResolved, res.LicenseUncertainty)
	}
	if res.LicenseCategory != "permissive" {
		t.Errorf("category = %q, want permissive", res.LicenseCategory)
	}
	if len(res.LicenseElectableArms) != 0 {
		t.Errorf("electable arms = %v, want none — there is nothing to elect", res.LicenseElectableArms)
	}
	if res.LicenseStatus != "Multiple" {
		t.Errorf("licence status = %q, want Multiple (the display fact is kept)", res.LicenseStatus)
	}
	if err := auditBlockingErr([]auditModuleResult{res}); err != nil {
		t.Errorf("audit exits non-zero: %v", err)
	}
}
