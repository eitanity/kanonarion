package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	domain "github.com/eitanity/kanonarion/internal/license/domain"
)

// contextLicenseOf builds the `context` licence section from a record with the
// given expression and primary shim, the way the command builds it from the
// store.
func contextLicenseOf(t *testing.T, expression, primary string) contextLicense {
	t.Helper()
	rec := conjunctionRecord(t, expression, primary)
	uc := testfakes.NewFakeQueryLicense()
	uc.AddRecord(rec.Coordinate, licapp.PipelineVersion, rec)
	return buildLicense(context.Background(), rec.Coordinate, uc, nil)
}

// conjunctionRecord is the shape the store actually holds for a conjunction:
// a correct Expression naming both arms, and a PrimarySPDX shim holding one of
// them — for gopkg.in/yaml.v3 the second arm, not even the first.
func conjunctionRecord(t *testing.T, expression, primary string) domain.LicenseRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return domain.LicenseRecord{
		Coordinate:    coord,
		OverallStatus: domain.LicenseStatusMultiple,
		PrimarySPDX:   primary,
		Expression:    expression,
	}
}

// separateGrantsRecord is the other stored shape: one root licence file per
// arm, and the basis the pipeline writes when it reads that. files maps a path
// to the arm it grants.
func separateGrantsRecord(t *testing.T, expression, primary string, files map[string]string) domain.LicenseRecord {
	t.Helper()
	r := conjunctionRecord(t, expression, primary)
	r.ExpressionBasis = domain.BasisSeparateGrants
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		r.LicenseFiles = append(r.LicenseFiles,
			domain.LicenseFileEntry{Path: p, SPDX: files[p], Confidence: 1})
	}
	return r
}

// obligationRowsUnder returns the obligation rows printed under the first
// heading containing marker, so a test can ask what a named section said
// rather than what the whole document happened to contain.
func obligationRowsUnder(t *testing.T, out, marker string) map[string]string {
	t.Helper()
	lines := strings.Split(out, "\n")
	start := -1
	for i, l := range lines {
		if strings.Contains(l, marker) {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("no section heading containing %q in:\n%s", marker, out)
	}
	rows := map[string]string{}
	for _, l := range lines[start:] {
		trimmed := strings.TrimSpace(l)
		label, value, ok := strings.Cut(trimmed, ":")
		if !ok || !strings.HasPrefix(l, "    ") {
			break
		}
		rows[label] = strings.TrimSpace(value)
	}
	if len(rows) == 0 {
		t.Fatalf("section %q printed no obligation rows in:\n%s", marker, out)
	}
	return rows
}

// TestPrintLicenseRecord_ConjunctionReportsEveryArmsObligations is the control
// for gopkg.in/yaml.v3@v3.0.1: its expression is "Apache-2.0 AND MIT" and its
// PrimarySPDX is MIT, so deriving obligations from the shim reported MIT's
// silence on state changes, trademarks and patents as the module's answer.
func TestPrintLicenseRecord_ConjunctionReportsEveryArmsObligations(t *testing.T) {
	r := conjunctionRecord(t, "Apache-2.0 AND MIT", "MIT")
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, false, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	union := obligationRowsUnder(t, out, "obligations (Apache-2.0 AND MIT")
	for _, duty := range []string{"state-changes", "no-trademark-use", "explicit-patent-grant"} {
		if union[duty] != "true" {
			t.Errorf("union %s = %q, want true: the Apache-2.0 arm requires it and a conjunction "+
				"binds every arm at once\n%s", duty, union[duty], out)
		}
	}

	// The union alone is a verdict. Each arm's own set must be published beside
	// it so a reader can see which licence imposed which duty.
	apache := obligationRowsUnder(t, out, "obligations required by Apache-2.0")
	if apache["state-changes"] != "true" || apache["explicit-patent-grant"] != "true" {
		t.Errorf("the Apache-2.0 arm is not named as requiring the duties it imposes:\n%s", out)
	}
	mit := obligationRowsUnder(t, out, "obligations required by MIT")
	if mit["state-changes"] != "false" || mit["explicit-patent-grant"] != "false" {
		t.Errorf("the MIT arm's own set was not published unchanged:\n%s", out)
	}
	if strings.Contains(out, "obligations (MIT, catalogue") {
		t.Errorf("the primary shim is still rendered as the module's obligation set:\n%s", out)
	}
}

// TestPrintLicenseRecord_ConjunctionSameLicenseTakesTheStrongestArm is the
// chroma/v2@v2.27.0 control: "MIT AND OFL-1.1" propagates at OFL's weak, not
// MIT's none, and does so whichever arm the PrimarySPDX shim happens to hold.
func TestPrintLicenseRecord_ConjunctionSameLicenseTakesTheStrongestArm(t *testing.T) {
	for _, primary := range []string{"OFL-1.1", "MIT"} {
		r := conjunctionRecord(t, "MIT AND OFL-1.1", primary)
		var buf bytes.Buffer
		if err := printLicenseRecord(r, false, false, &buf); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		union := obligationRowsUnder(t, out, "obligations (MIT AND OFL-1.1")
		if union["same-license"] != "weak" {
			t.Errorf("primary %s: union same-license = %q, want weak — the strictest arm's "+
				"propagation governs\n%s", primary, union["same-license"], out)
		}
		if union["no-trademark-use"] != "true" {
			t.Errorf("primary %s: union no-trademark-use = %q, want true (OFL-1.1 requires it)\n%s",
				primary, union["no-trademark-use"], out)
		}
	}
}

// TestLicenseJSON_ConjunctionPublishesTheUnionAndItsArms is the same control on
// the machine-readable surface.
func TestLicenseJSON_ConjunctionPublishesTheUnionAndItsArms(t *testing.T) {
	r := conjunctionRecord(t, "Apache-2.0 AND MIT", "MIT")
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, true, &buf); err != nil {
		t.Fatal(err)
	}
	doc := obligationsDocOf(t, buf.Bytes())
	if got, want := string(doc.Obligations), obligationsWire(t, domain.UnionObligations([]string{"Apache-2.0", "MIT"})); got != want {
		t.Errorf("obligations = %s, want the union of both arms %s", got, want)
	}
	if len(doc.BindingObligations) != 2 {
		t.Fatalf("binding_obligations = %v, want both arms named", doc.BindingObligations)
	}
	for _, arm := range []string{"Apache-2.0", "MIT"} {
		if got, want := string(doc.BindingObligations[arm]), obligationsWire(t, domain.LookupObligations(arm)); got != want {
			t.Errorf("binding_obligations[%q] = %s, want the arm's own set %s", arm, got, want)
		}
	}
	if len(doc.Elective) != 0 {
		t.Errorf("elective_obligations = %v, want absent: a conjunction offers no election", doc.Elective)
	}
}

// obligationsDoc is the part of `license --json` these controls read. The
// obligation sets stay raw so they are compared as published bytes, not as a
// re-parse: Obligations marshals through a wire type and has no inverse.
type obligationsDoc struct {
	Obligations        json.RawMessage            `json:"obligations"`
	BindingObligations map[string]json.RawMessage `json:"binding_obligations"`
	Elective           map[string]json.RawMessage `json:"elective_obligations"`
}

func obligationsDocOf(t *testing.T, raw []byte) obligationsDoc {
	t.Helper()
	var doc obligationsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Obligations = compactJSON(t, doc.Obligations)
	for k, v := range doc.BindingObligations {
		doc.BindingObligations[k] = compactJSON(t, v)
	}
	for k, v := range doc.Elective {
		doc.Elective[k] = compactJSON(t, v)
	}
	return doc
}

// compactJSON strips the command's indentation so a section is compared on its
// content rather than on how the encoder laid it out.
func compactJSON(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	if len(raw) == 0 {
		return raw
	}
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func obligationsWire(t *testing.T, ob domain.Obligations) string {
	t.Helper()
	b, err := json.Marshal(ob)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestLicenseJSON_NonConjunctionsAreUntouched is the control that shows the
// 1,671 records this change does not reach did not move: a single identifier
// still answers with its own set and no arms, and a disjunction still publishes
// exactly the elective arms it did before, with nothing binding.
func TestLicenseJSON_NonConjunctionsAreUntouched(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expression string
		primary    string
		elective   []string
	}{
		{"single identifier", "Apache-2.0", "Apache-2.0", nil},
		{"disjunction", "Apache-2.0 OR MIT", "Apache-2.0", []string{"Apache-2.0", "MIT"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := conjunctionRecord(t, tc.expression, tc.primary)
			var buf bytes.Buffer
			if err := printLicenseRecord(r, false, true, &buf); err != nil {
				t.Fatal(err)
			}
			doc := obligationsDocOf(t, buf.Bytes())
			if got, want := string(doc.Obligations), obligationsWire(t, domain.LookupObligations(tc.primary)); got != want {
				t.Errorf("obligations = %s, want the primary's own set %s", got, want)
			}
			if len(doc.BindingObligations) != 0 {
				t.Errorf("binding_obligations = %v, want absent: nothing here is a conjunction",
					doc.BindingObligations)
			}
			if len(doc.Elective) != len(tc.elective) {
				t.Fatalf("elective_obligations = %v, want %v", doc.Elective, tc.elective)
			}
			for _, arm := range tc.elective {
				if got, want := string(doc.Elective[arm]), obligationsWire(t, domain.LookupObligations(arm)); got != want {
					t.Errorf("elective_obligations[%q] = %s, want %s", arm, got, want)
				}
			}
		})
	}
}

// TestContextLicense_ConjunctionReportsEveryArmsObligations is the third
// surface: `context --json` derived its obligations section from the same shim.
func TestContextLicense_ConjunctionReportsEveryArmsObligations(t *testing.T) {
	l := contextLicenseOf(t, "Apache-2.0 AND MIT", "MIT")
	if l.Obligations == nil {
		t.Fatal("no obligations section")
	}
	for _, duty := range []struct {
		name string
		got  bool
	}{
		{"state_changes", l.Obligations.StateChanges},
		{"no_trademark_use", l.Obligations.NoTrademarkUse},
		{"explicit_patent_grant", l.Obligations.ExplicitPatentGrant},
	} {
		if !duty.got {
			t.Errorf("%s = false, but the Apache-2.0 arm requires it", duty.name)
		}
	}
	if len(l.BindingObligations) != 2 {
		t.Fatalf("binding_obligations = %v, want both arms named", l.BindingObligations)
	}
	if arm := l.BindingObligations["MIT"]; arm == nil || arm.StateChanges {
		t.Errorf("the MIT arm's own set is missing or altered: %+v", arm)
	}
}

// TestContextLicense_SingleIdentifierIsUntouched is the same control for the
// context surface: a single-licence module's section does not move.
func TestContextLicense_SingleIdentifierIsUntouched(t *testing.T) {
	l := contextLicenseOf(t, "Apache-2.0", "Apache-2.0")
	if l.Obligations == nil {
		t.Fatal("no obligations section")
	}
	if !l.Obligations.StateChanges || l.Obligations.SameLicense != "none" {
		t.Errorf("Apache-2.0's own set changed: %+v", l.Obligations)
	}
	if len(l.BindingObligations) != 0 {
		t.Errorf("binding_obligations = %v, want absent for a single identifier", l.BindingObligations)
	}
}

// TestPrintLicenseRecord_ConjunctionWithUncataloguedArmSaysSo covers the shape
// two stored records have: github.com/docker/go-metrics and
// github.com/opencontainers/go-digest are "Apache-2.0 AND CC-BY-SA-4.0", and
// CC-BY-SA-4.0 has no catalogue entry. The merge then saw part of what binds,
// so it must not be published as the answer — while the arm it did recognise
// is still named.
func TestPrintLicenseRecord_ConjunctionWithUncataloguedArmSaysSo(t *testing.T) {
	r := conjunctionRecord(t, "Apache-2.0 AND CC-BY-SA-4.0", "Apache-2.0")
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, false, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "obligations (Apache-2.0 AND CC-BY-SA-4.0): incomplete") {
		t.Errorf("the merged set is published as though it were complete:\n%s", out)
	}
	if !strings.Contains(out, "obligations required by CC-BY-SA-4.0: unknown") {
		t.Errorf("the uncatalogued arm is not named:\n%s", out)
	}
	apache := obligationRowsUnder(t, out, "obligations required by Apache-2.0")
	if apache["explicit-patent-grant"] != "true" {
		t.Errorf("the arm that IS catalogued lost its duties:\n%s", out)
	}
}

// TestPrintLicenseRecord_SeparateGrantsNameTheFileAndDoNotAssertAnOwedSet is
// the control for a conjunction of arms that each grant CODE: LICENSE grants
// Apache-2.0 over the module's own source and LICENSE.perl grants Artistic-2.0
// over a component it carries. Both cover code, so neither is set aside; which
// of them binds depends on whether the covered artefact reaches the consumer's
// binary, and no licence record answers that.
//
// The fixture used to be go-digest's LICENSE beside LICENSE.docs. That pairing
// is no longer this case: coverage says the documentation licence does not
// govern the code, so it leaves the expression entirely rather than joining a
// merged upper bound — see TestSeparateGrants_ADocsArmLeavesRatherThanMerging.
func TestPrintLicenseRecord_SeparateGrantsNameTheFileAndDoNotAssertAnOwedSet(t *testing.T) {
	r := separateGrantsRecord(t, "Apache-2.0 AND Artistic-2.0", "Apache-2.0", map[string]string{
		"LICENSE":      "Apache-2.0",
		"LICENSE.perl": "Artistic-2.0",
	})
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, false, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Decision: each arm is published with the path that grants it — the
	// coverage evidence already in the record.
	if !strings.Contains(out, "obligations required by Apache-2.0, granted by LICENSE (catalogue") {
		t.Errorf("the Apache-2.0 arm does not name the file that grants it:\n%s", out)
	}
	if !strings.Contains(out, "obligations required by Artistic-2.0, granted by LICENSE.perl: unknown") {
		t.Errorf("the Artistic-2.0 arm does not name the file that grants it:\n%s", out)
	}
	// The merged set is present but must say what it is.
	if !strings.Contains(out, "an upper bound,") || !strings.Contains(out, "not what you owe") {
		t.Errorf("the merged set is not labelled as an upper bound:\n%s", out)
	}
	if strings.Contains(out, "every arm binds at once") {
		t.Errorf("separately granted arms are rendered as though they all bind:\n%s", out)
	}
	// Decision: an uncatalogued separately granted arm must not degrade the
	// record. The Apache-2.0 arm is known at full confidence and covers the code.
	if strings.Contains(out, "incomplete — an arm is not in catalogue") {
		t.Errorf("a separately granted arm degraded the record-level answer:\n%s", out)
	}
	apache := obligationRowsUnder(t, out, "obligations required by Apache-2.0")
	if apache["explicit-patent-grant"] != "true" || apache["state-changes"] != "true" {
		t.Errorf("the Apache-2.0 arm lost its own duties:\n%s", out)
	}
}

// TestLicenseJSON_SeparateGrantsPublishPathsAndDoNotDegrade is the same
// control on the machine-readable surface, and pins decision 4: the
// record-level status stays known because one arm is known.
func TestLicenseJSON_SeparateGrantsPublishPathsAndDoNotDegrade(t *testing.T) {
	r := separateGrantsRecord(t, "Apache-2.0 AND Artistic-2.0", "Apache-2.0", map[string]string{
		"LICENSE":      "Apache-2.0",
		"LICENSE.perl": "Artistic-2.0",
	})
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, true, &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ArmGrants map[string][]string `json:"arm_grants"`
		Reading   string              `json:"obligations_reading"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.ArmGrants["Apache-2.0"]; len(got) != 1 || got[0] != "LICENSE" {
		t.Errorf("arm_grants[Apache-2.0] = %v, want [LICENSE]", got)
	}
	if got := doc.ArmGrants["Artistic-2.0"]; len(got) != 1 || got[0] != "LICENSE.perl" {
		t.Errorf("arm_grants[Artistic-2.0] = %v, want [LICENSE.perl]", got)
	}
	if doc.Reading != obligationsReadingMaximal {
		t.Errorf("obligations_reading = %q, want the maximal statement — without it a reader "+
			"takes the merged set as owed", doc.Reading)
	}

	raw := obligationsDocOf(t, buf.Bytes())
	if want := obligationsWire(t, domain.MaximalObligations([]string{"Apache-2.0", "Artistic-2.0"})); string(raw.Obligations) != want {
		t.Errorf("obligations = %s, want the maximal set %s", raw.Obligations, want)
	}
	var record struct {
		Obligations struct {
			Status string `json:"status"`
		} `json:"obligations"`
		Binding map[string]struct {
			Status string `json:"status"`
		} `json:"binding_obligations"`
	}
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Obligations.Status != "known" {
		t.Errorf("record-level status = %q, want known: the Apache-2.0 arm covers the code and "+
			"is catalogued; an uncatalogued arm must not degrade it", record.Obligations.Status)
	}
	if record.Binding["Artistic-2.0"].Status != "unknown" {
		t.Error("the uncatalogued arm must still report unknown on its own row")
	}
}

// TestSeparateGrants_ADocsArmLeavesRatherThanMerging is go-digest@v1.0.0 and
// docker/go-metrics@v0.0.1 under the coverage reading. A documentation licence
// is not an arm whose duties a consumer might owe depending on what they ship:
// it does not govern the code at all, so it leaves the expression, and the
// maximal-upper-bound machinery has nothing to qualify.
func TestSeparateGrants_ADocsArmLeavesRatherThanMerging(t *testing.T) {
	r := separateGrantsRecord(t, "Apache-2.0 AND CC-BY-SA-4.0", "Apache-2.0", map[string]string{
		"LICENSE":      "Apache-2.0",
		"LICENSE.docs": "CC-BY-SA-4.0",
	})
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, true, &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Expression string              `json:"expression"`
		Basis      string              `json:"expression_basis"`
		Primary    string              `json:"primary_spdx"`
		ArmGrants  map[string][]string `json:"arm_grants"`
		Binding    map[string]any      `json:"binding_obligations"`
		Reading    string              `json:"obligations_reading"`
		Files      []struct {
			Path     string `json:"path"`
			Coverage string `json:"coverage"`
		} `json:"license_files"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Expression != "Apache-2.0" || doc.Primary != "Apache-2.0" {
		t.Errorf("expression=%q primary=%q, want Apache-2.0 for both", doc.Expression, doc.Primary)
	}
	if !strings.Contains(doc.Basis, "coverage:") || !strings.Contains(doc.Basis, "CC-BY-SA-4.0") {
		t.Errorf("expression_basis = %q, must say coverage took part and name the arm it set aside", doc.Basis)
	}
	if len(doc.ArmGrants) != 0 || len(doc.Binding) != 0 || doc.Reading != "" {
		t.Errorf("arm_grants=%v binding=%v reading=%q, want all absent: there is no conjunction left",
			doc.ArmGrants, doc.Binding, doc.Reading)
	}
	want := map[string]string{"LICENSE": "ModuleCode", "LICENSE.docs": "Documentation"}
	for _, f := range doc.Files {
		if f.Coverage != want[f.Path] {
			t.Errorf("license_files[%s].coverage = %q, want %q", f.Path, f.Coverage, want[f.Path])
		}
	}
}

// TestLicenseJSON_SeparateGrantsAcrossTheStoredShapes walks the arm-to-path
// attribution for the other separately granted expressions in the store, where
// the second file is vendored code rather than documentation.
func TestLicenseJSON_SeparateGrantsAcrossTheStoredShapes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expression string
		primary    string
		files      map[string]string
		want       map[string]string
	}{
		{
			name:       "vendored C beside the module's own Apache grant",
			expression: "Apache-2.0 AND MIT",
			primary:    "Apache-2.0",
			files:      map[string]string{"LICENSE": "Apache-2.0", "LICENSE.libyaml": "MIT", "NOTICE": "Apache-2.0"},
			want:       map[string]string{"Apache-2.0": "LICENSE", "MIT": "LICENSE.libyaml"},
		},
		{
			name:       "vendored Go beside the module's own Apache grant",
			expression: "Apache-2.0 AND BSD-3-Clause",
			primary:    "Apache-2.0",
			files:      map[string]string{"LICENSE": "Apache-2.0", "LICENSE.Golang": "BSD-3-Clause"},
			want:       map[string]string{"Apache-2.0": "LICENSE", "BSD-3-Clause": "LICENSE.Golang"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := separateGrantsRecord(t, tc.expression, tc.primary, tc.files)
			var buf bytes.Buffer
			if err := printLicenseRecord(r, false, true, &buf); err != nil {
				t.Fatal(err)
			}
			var doc struct {
				ArmGrants map[string][]string `json:"arm_grants"`
			}
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.ArmGrants) != len(tc.want) {
				t.Fatalf("arm_grants = %v, want one path per arm %v", doc.ArmGrants, tc.want)
			}
			for arm, path := range tc.want {
				if got := doc.ArmGrants[arm]; len(got) != 1 || got[0] != path {
					t.Errorf("arm_grants[%q] = %v, want [%s]", arm, got, path)
				}
			}
			// A NOTICE is not a grant of an arm; it did not build the
			// expression and must not be published as coverage evidence.
			for arm, paths := range doc.ArmGrants {
				for _, p := range paths {
					if p == "NOTICE" {
						t.Errorf("arm_grants[%q] names NOTICE, which granted no arm", arm)
					}
				}
			}
		})
	}
}

// TestSeparateGrants_TheBasisDecides pins decision 1: the same files and the
// same expression read two ways, and only the recorded basis tells them apart.
func TestSeparateGrants_TheBasisDecides(t *testing.T) {
	files := map[string]string{"LICENSE": "Apache-2.0", "LICENSE.perl": "Artistic-2.0"}

	separate := separateGrantsRecord(t, "Apache-2.0 AND Artistic-2.0", "Apache-2.0", files)
	inseparable := separate
	inseparable.ExpressionBasis = "split: is licensed under"

	if got := readLicenceObligations(separate); !got.Maximal || got.Grants == nil {
		t.Errorf("basis %q read as inseparable", separate.ExpressionBasis)
	}
	if got := readLicenceObligations(inseparable); got.Maximal || got.Grants != nil {
		t.Errorf("basis %q read as separately granted — only the basis may decide this, "+
			"never the file list, which is identical here", inseparable.ExpressionBasis)
	}
	// And the two readings differ where it counts: the inseparable one degrades
	// on the uncatalogued arm, the separately granted one does not.
	if readLicenceObligations(separate).Set.Status != domain.ObligationStatusKnown {
		t.Error("separately granted: the catalogued arm must keep the record known")
	}
	if readLicenceObligations(inseparable).Set.Status != domain.ObligationStatusUnknown {
		t.Error("inseparable: an uncatalogued arm means the merged set is incomplete")
	}
}

// TestContextLicense_SeparateGrantsCarryPathsAndTheReading is the third
// surface.
func TestContextLicense_SeparateGrantsCarryPathsAndTheReading(t *testing.T) {
	rec := separateGrantsRecord(t, "Apache-2.0 AND Artistic-2.0", "Apache-2.0", map[string]string{
		"LICENSE":      "Apache-2.0",
		"LICENSE.perl": "Artistic-2.0",
	})
	uc := testfakes.NewFakeQueryLicense()
	uc.AddRecord(rec.Coordinate, licapp.PipelineVersion, rec)
	l := buildLicense(context.Background(), rec.Coordinate, uc, nil)

	if l.Obligations == nil || l.Obligations.Status != "known" {
		t.Fatalf("record-level obligations = %+v, want status known", l.Obligations)
	}
	if got := l.ArmGrants["Artistic-2.0"]; len(got) != 1 || got[0] != "LICENSE.perl" {
		t.Errorf("arm_grants[Artistic-2.0] = %v, want [LICENSE.perl]", got)
	}
	if l.ObligationsReading != obligationsReadingMaximal {
		t.Errorf("obligations_reading = %q, want the maximal statement", l.ObligationsReading)
	}
	if arm := l.BindingObligations["Artistic-2.0"]; arm == nil || arm.Status != "unknown" {
		t.Errorf("the uncatalogued arm must report unknown on its own row: %+v", arm)
	}
}

// TestInseparableConjunctionsCarryNoGrantsOrReading is the control that the
// nine inseparable records did not move: no arm_grants, no reading, and the
// union still qualified as the owed set.
func TestInseparableConjunctionsCarryNoGrantsOrReading(t *testing.T) {
	for _, basis := range []string{
		"", // records written before the field existed
		"split: is licensed under",
		"split: covered by two different licenses",
		"split: the following files",
		"conservative: no statement of how the grants relate",
	} {
		r := conjunctionRecord(t, "Apache-2.0 AND MIT", "MIT")
		r.ExpressionBasis = basis
		r.LicenseFiles = []domain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "MIT", Confidence: 1},
			{Path: "NOTICE", SPDX: "Apache-2.0", Confidence: 1},
		}
		var buf bytes.Buffer
		if err := printLicenseRecord(r, false, true, &buf); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			ArmGrants map[string][]string `json:"arm_grants"`
			Reading   string              `json:"obligations_reading"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.ArmGrants) != 0 || doc.Reading != "" {
			t.Errorf("basis %q: published arm_grants=%v reading=%q, but nothing in this record "+
				"attributes coverage to a file", basis, doc.ArmGrants, doc.Reading)
		}
		raw := obligationsDocOf(t, buf.Bytes())
		if want := obligationsWire(t, domain.UnionObligations([]string{"Apache-2.0", "MIT"})); string(raw.Obligations) != want {
			t.Errorf("basis %q: obligations = %s, want the union %s", basis, raw.Obligations, want)
		}
	}
}
