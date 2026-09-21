package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	licports "github.com/eitanity/kanonarion/internal/license/ports"
)

// --- the enum filter ---

// Every value the enum can hold is accepted, in either spelling the flag takes,
// and a repeat of one is not a second filter.
func TestCopyrightStatusFilter_AcceptsTheFourAndDeduplicates(t *testing.T) {
	got, err := copyrightStatusFilter([]string{"found", "none_found", "extraction_failed", "not_analysed"})
	if err != nil {
		t.Fatalf("copyrightStatusFilter: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("parsed %v, want all four statuses", got)
	}
	for _, want := range []licdomain.CopyrightStatus{
		licdomain.CopyrightStatusFound, licdomain.CopyrightStatusNoneFound,
		licdomain.CopyrightStatusExtractionFailed, licdomain.CopyrightStatusNotAnalysed,
	} {
		if !containsStatus(got, want) {
			t.Errorf("%s was not parsed", want)
		}
	}

	dedup, err := copyrightStatusFilter([]string{"none_found", " none_found ", ""})
	if err != nil {
		t.Fatalf("copyrightStatusFilter: %v", err)
	}
	if len(dedup) != 1 || dedup[0] != licdomain.CopyrightStatusNoneFound {
		t.Errorf("repeated and blank values parsed to %v, want one none_found", dedup)
	}
}

// A value outside the enum is refused, at the exit code that says the
// invocation was wrong, naming every value that would have worked.
//
// It must not be passed through to match nothing: in a list, two good values
// and one typo returns rows, and the rows the typo should have added are
// missing with nothing in the output to say so.
func TestCopyrightStatusFilter_RefusesAValueOutsideTheEnum(t *testing.T) {
	_, err := copyrightStatusFilter([]string{"none_found", "nonsense"})
	if err == nil {
		t.Fatal("a value outside the enum was accepted")
	}
	var exit *exitError
	if !errors.As(err, &exit) {
		t.Fatalf("want an *exitError, got %T: %v", err, err)
	}
	if exit.code != ExitConfig {
		t.Errorf("exit code = %d, want %d", exit.code, ExitConfig)
	}
	for _, name := range []string{"found", "none_found", "extraction_failed", "not_analysed"} {
		if !strings.Contains(exit.msg, name) {
			t.Errorf("the refusal does not name %q: %s", name, exit.msg)
		}
	}
}

// --- the scope flags ---

// Two scopes at once is refused rather than resolved by precedence: each names
// a different build, and silently picking one answers a question nobody asked.
func TestLicenceScopeFlags_TwoScopesAreRefused(t *testing.T) {
	err := licenceScopeFlags{packagePattern: "./cmd/x", walkID: "01ARZ3NDEKTSV4RRFFQ69G5FAV"}.validate()
	if err == nil {
		t.Fatal("--package with --walk-id was accepted")
	}
	var exit *exitError
	if !errors.As(err, &exit) {
		t.Fatalf("want an *exitError, got %T: %v", err, err)
	}
	if exit.code != ExitConfig {
		t.Errorf("exit code = %d, want %d", exit.code, ExitConfig)
	}
	for _, f := range []licenceScopeFlags{
		{packagePattern: "./cmd/x"}, {gomodPath: "./go.mod"}, {walkID: "01ARZ3NDEKTSV4RRFFQ69G5FAV"}, {},
	} {
		if verr := f.validate(); verr != nil {
			t.Errorf("one scope (%+v) was refused: %v", f, verr)
		}
	}
}

// --- the row's new fields ---

// listSummary is one row of the fake store's corpus.
func listSummary(path string, pipeline string, status licdomain.CopyrightStatus) licports.LicenseSummary {
	return licports.LicenseSummary{
		ModulePath: path, ModuleVersion: "v1.0.0", PipelineVersion: pipeline,
		PrimarySPDX: "MIT", OverallStatus: licdomain.LicenseStatusDetected, CopyrightStatus: status,
	}
}

// licenseListDoc runs the listing under --json and decodes the document.
func licenseListDoc(t *testing.T, f licenseListFlags, scope *licenceListScope, uc QueryLicenseUseCase) map[string]any {
	t.Helper()
	withJSON(t, true)
	var stdout, stderr bytes.Buffer
	if err := runLicenseList(context.Background(), f, scope, uc,
		licdomain.NewLicenseOverrideSet(nil), &stdout, &stderr); err != nil {
		t.Fatalf("runLicenseList: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("a listing under --json wrote to stderr: %q", stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("decoding listing document: %v\n%s", err, stdout.String())
	}
	return doc
}

func licenseListText(t *testing.T, f licenseListFlags, scope *licenceListScope, uc QueryLicenseUseCase) string {
	t.Helper()
	withJSON(t, false)
	var stdout, stderr bytes.Buffer
	if err := runLicenseList(context.Background(), f, scope, uc,
		licdomain.NewLicenseOverrideSet(nil), &stdout, &stderr); err != nil {
		t.Fatalf("runLicenseList: %v", err)
	}
	return stdout.String()
}

// The three facts a row could not previously state are on every row, in both
// renderings, at the values that are answers rather than absences: `superseded`
// false and `not_analysed`.
//
// A consumer reading only the true `superseded` flags could not tell a servable
// record from one the pair was never computed for, and a row that omitted
// `not_analysed` would leave "extraction has not run" indistinguishable from a
// build that does not derive the field.
func TestRunLicenseList_EveryRowStatesCopyrightGenerationAndSupersession(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/analysed", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
		listSummary("example.com/unanalysed", licapp.PipelineVersion, licdomain.CopyrightStatusNotAnalysed),
	})

	doc := licenseListDoc(t, licenseListFlags{limit: 50}, nil, uc)
	records, _ := doc["records"].([]any)
	if len(records) != 2 {
		t.Fatalf("listed %d rows, want 2: %v", len(records), doc)
	}
	want := map[string]string{"example.com/analysed": "found", "example.com/unanalysed": "not_analysed"}
	for _, raw := range records {
		row, _ := raw.(map[string]any)
		for _, key := range []string{"copyright_status", "pipeline_version", "superseded"} {
			if _, ok := row[key]; !ok {
				t.Errorf("row %v carries no %q", row["module"], key)
			}
		}
		if got := row["copyright_status"]; got != want[row["module"].(string)] {
			t.Errorf("%v copyright_status = %v, want %v", row["module"], got, want[row["module"].(string)])
		}
		if row["superseded"] != false {
			t.Errorf("%v superseded = %v, want false — the record is at the served version",
				row["module"], row["superseded"])
		}
		if row["pipeline_version"] != licapp.PipelineVersion {
			t.Errorf("%v pipeline_version = %v, want %s", row["module"], row["pipeline_version"], licapp.PipelineVersion)
		}
	}

	text := licenseListText(t, licenseListFlags{limit: 50}, nil, uc)
	for _, want := range []string{"found", "not_analysed"} {
		if !strings.Contains(text, want) {
			t.Errorf("the text listing does not state %q:\n%s", want, text)
		}
	}
}

// The default asks the store for one generation, and says on every listing which
// one. Without the line a reader cannot tell a restricted count from a whole one.
func TestRunLicenseList_DefaultRestrictsToTheServedGenerationAndSaysSo(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/served", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
		listSummary("example.com/old", "1.2.0", licdomain.CopyrightStatusFound),
	})

	text := licenseListText(t, licenseListFlags{limit: 50}, nil, uc)
	if strings.Contains(text, "example.com/old@") {
		t.Errorf("the default listing shows a superseded record:\n%s", text)
	}
	if !strings.Contains(text, "listing license records at pipeline "+licapp.PipelineVersion) {
		t.Errorf("the listing does not say which generation it drew from:\n%s", text)
	}
}

// --all-generations includes the earlier records and marks each one, on both
// paths, and says how many were marked.
func TestRunLicenseList_AllGenerationsMarksTheSupersededRows(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/served", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
		listSummary("example.com/old", "1.2.0", licdomain.CopyrightStatusFound),
	})
	f := licenseListFlags{limit: 50, allGenerations: true}

	text := licenseListText(t, f, nil, uc)
	if !strings.Contains(text, "example.com/old@v1.0.0") {
		t.Errorf("--all-generations dropped the superseded record:\n%s", text)
	}
	if !strings.Contains(text, "[superseded generation 1.2.0]") {
		t.Errorf("the superseded row is not marked:\n%s", text)
	}
	if !strings.Contains(text, "1 of 2 listed record(s) were extracted at a superseded pipeline version") {
		t.Errorf("the listing does not count what it marked:\n%s", text)
	}

	doc := licenseListDoc(t, f, nil, uc)
	records, _ := doc["records"].([]any)
	marked := 0
	for _, raw := range records {
		if row, _ := raw.(map[string]any); row["superseded"] == true {
			marked++
		}
	}
	if marked != 1 {
		t.Errorf("--all-generations marked %d rows, want 1", marked)
	}
}

// --- the scope ---

func licenceScopeOf(t *testing.T, kind, value string, paths ...string) *licenceListScope {
	t.Helper()
	s := &licenceListScope{kind: kind, value: value}
	for _, p := range paths {
		c, err := coordinate.NewModuleCoordinate(p, "v1.0.0")
		if err != nil {
			t.Fatalf("NewModuleCoordinate: %v", err)
		}
		s.mods = append(s.mods, scopeModule{coord: c})
	}
	return s
}

// A module in scope that holds no licence record is NAMED, on both paths. It is
// the one that still has to be attributed, and dropping it makes it
// indistinguishable from a module that is not in the build at all.
func TestRunLicenseList_ScopeNamesTheModulesHoldingNoRecord(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/recorded", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
	})
	scope := licenceScopeOf(t, "package", "./cmd/x", "example.com/recorded", "example.com/missing")

	text := licenseListText(t, licenseListFlags{limit: 50}, scope, uc)
	if !strings.Contains(text, "scope: package ./cmd/x (2 module(s))") {
		t.Errorf("the listing does not state its scope:\n%s", text)
	}
	if !strings.Contains(text, "example.com/missing@v1.0.0") {
		t.Errorf("the module holding no record is not named:\n%s", text)
	}
	// The coordinate is filled in rather than left as a template: the line is
	// meant to be run as it stands.
	if !strings.Contains(text, "run 'kanonarion license example.com/missing@v1.0.0'") {
		t.Errorf("no remedy is offered for the module holding no record:\n%s", text)
	}

	doc := licenseListDoc(t, licenseListFlags{limit: 50}, scope, uc)
	got, _ := doc["scope"].(map[string]any)
	if got == nil {
		t.Fatalf("the document carries no scope: %v", doc)
	}
	if got["kind"] != "package" || got["value"] != "./cmd/x" || got["module_count"] != float64(2) {
		t.Errorf("scope = %v, want the package pattern and its module count", got)
	}
	without, _ := got["without_record"].([]any)
	if len(without) != 1 {
		t.Fatalf("without_record = %v, want the one module holding no record", got["without_record"])
	}
	entry, _ := without[0].(map[string]any)
	if entry["module"] != "example.com/missing" || entry["version"] != "v1.0.0" {
		t.Errorf("without_record[0] = %v, want the module holding no record", entry)
	}
	if entry["kind"] != absenceNotExtracted || entry["remedy"] != "run 'kanonarion license example.com/missing@v1.0.0'" {
		t.Errorf("without_record[0] = %v, want a not_extracted entry carrying the command that fills it", entry)
	}
	records, _ := doc["records"].([]any)
	if len(records) != 1 {
		t.Errorf("listed %d rows, want only the module in scope that holds a record", len(records))
	}
}

// A scope every one of whose modules has been extracted states an EMPTY
// without_record, not an absent one: the empty array is the measured answer
// that nothing is missing, and a consumer cannot read a key that is not there.
func TestRunLicenseList_ScopeWithEveryRecordStatesAnEmptyWithoutRecord(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/recorded", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
	})
	scope := licenceScopeOf(t, "go.mod", "./go.mod", "example.com/recorded")

	doc := licenseListDoc(t, licenseListFlags{limit: 50}, scope, uc)
	got, _ := doc["scope"].(map[string]any)
	without, ok := got["without_record"].([]any)
	if !ok {
		t.Fatalf("without_record is not an array: %v", got)
	}
	if len(without) != 0 {
		t.Errorf("without_record = %v, want an empty array", without)
	}

	text := licenseListText(t, licenseListFlags{limit: 50}, scope, uc)
	if strings.Contains(text, "hold no licence record") {
		t.Errorf("a scope with nothing missing claimed something was:\n%s", text)
	}
}

// A scope that narrows to a module the store holds no record for is a zero with
// a scope, and the document says both: an empty records array with the
// zero-result statement, and the scope that produced it.
func TestRunLicenseList_ScopedZeroCarriesBothStatements(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/elsewhere", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
	})
	scope := licenceScopeOf(t, "package", "./cmd/x", "example.com/missing")

	doc := licenseListDoc(t, licenseListFlags{limit: 50}, scope, uc)
	if records, _ := doc["records"].([]any); len(records) != 0 {
		t.Fatalf("listed %d rows over a scope holding no record", len(records))
	}
	zero, _ := doc["zero_result"].(map[string]any)
	if zero == nil {
		t.Fatalf("the zero page carries no zero_result: %v", doc)
	}
	// The corpus counted is the scope's, not the store's: the record the store
	// holds for another module explains nothing about this page.
	if zero["records_considered"] != float64(0) || zero["store_empty"] != true {
		t.Errorf("zero_result = %v, want a corpus of 0 over the scope", zero)
	}
	got, _ := doc["scope"].(map[string]any)
	if got == nil || got["module_count"] != float64(1) {
		t.Errorf("the zero page dropped the scope: %v", doc["scope"])
	}
}

// An over-paged request answers with an empty page that says paging, not a
// filter, emptied it — and still states the limit and the offsets a consumer
// pages on.
func TestRunLicenseList_OverPagedRequestNamesThePaging(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/a", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
		listSummary("example.com/b", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
	})

	doc := licenseListDoc(t, licenseListFlags{limit: 50, offset: 10}, nil, uc)
	if records, _ := doc["records"].([]any); len(records) != 0 {
		t.Fatalf("a page past the population returned %d rows", len(records))
	}
	zero, _ := doc["zero_result"].(map[string]any)
	if zero == nil || zero["paged_past"] != true {
		t.Fatalf("zero_result = %v, want paged_past true", zero)
	}
	if zero["records_considered"] != float64(2) || zero["store_empty"] != false {
		t.Errorf("zero_result = %v, want the population it paged past", zero)
	}
	if doc["limit"] != float64(50) || doc["offset"] != float64(10) || doc["next_offset"] != float64(60) {
		t.Errorf("the paging state is wrong: limit=%v offset=%v next_offset=%v",
			doc["limit"], doc["offset"], doc["next_offset"])
	}
	if _, present := doc["scope"]; present {
		t.Errorf("an unscoped listing carries a scope: %v", doc["scope"])
	}
}

// The status filter reaches the store rather than being applied to rows already
// fetched, so it costs no record load — and the listing that results is the
// blocking set for an attribution document.
func TestRunLicenseList_CopyrightStatusFilterReachesTheStore(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/published", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
		listSummary("example.com/blocking", licapp.PipelineVersion, licdomain.CopyrightStatusNoneFound),
	})

	doc := licenseListDoc(t, licenseListFlags{
		limit: 50, copyrightStatus: []licdomain.CopyrightStatus{licdomain.CopyrightStatusNoneFound},
	}, nil, uc)
	records, _ := doc["records"].([]any)
	if len(records) != 1 {
		t.Fatalf("listed %d rows, want only the blocking module: %v", len(records), doc)
	}
	row, _ := records[0].(map[string]any)
	if row["module"] != "example.com/blocking" || row["copyright_status"] != "none_found" {
		t.Errorf("listed %v, want the module whose record found no copyright", row)
	}
}

func containsStatus(in []licdomain.CopyrightStatus, want licdomain.CopyrightStatus) bool {
	for _, s := range in {
		if s == want {
			return true
		}
	}
	return false
}

// The scope is resolved by the code `notice` resolves with, so the two commands
// cannot come to disagree about which modules a build compiles. The walk branch
// is the one a test can drive without a toolchain, and it is the same call.
func TestResolveLicenceListScope_ResolvesThroughNoticesResolver(t *testing.T) {
	dep := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	other := coordinatetest.MustNew("example.com/other", "v2.0.0")
	ctr := &Container{QueryWalks: walksWithNodes("W1", dep, other)}

	scope, err := resolveLicenceListScope(context.Background(), licenceScopeFlags{walkID: "W1"}, ctr)
	if err != nil {
		t.Fatalf("resolveLicenceListScope: %v", err)
	}
	if scope == nil {
		t.Fatal("a named walk resolved to no scope")
	}
	if scope.kind != "walk" || scope.value != "W1" {
		t.Errorf("scope = %s %s, want walk W1", scope.kind, scope.value)
	}
	if len(scope.mods) != 2 {
		t.Fatalf("scope holds %d modules, want the walk's two", len(scope.mods))
	}
	// Ordered, so two runs page the same listing identically.
	if got := scope.coords(); got[0].String() != dep.String() || got[1].String() != other.String() {
		t.Errorf("scope coords = %v, want them ordered", got)
	}

	// No scope flag leaves the listing over the whole store, which is what it
	// has always been.
	none, err := resolveLicenceListScope(context.Background(), licenceScopeFlags{}, ctr)
	if err != nil {
		t.Fatalf("resolveLicenceListScope: %v", err)
	}
	if none != nil {
		t.Errorf("no scope flag resolved to %+v, want nil", none)
	}
}

// A status filter that matched nothing names itself and what it was compared
// against, so a reader does not go and check a spelling that was never the one
// that excluded their module.
func TestRunLicenseList_StatusFilterMissNamesTheFilter(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/published", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
	})

	text := licenseListText(t, licenseListFlags{
		limit:           50,
		copyrightStatus: []licdomain.CopyrightStatus{licdomain.CopyrightStatusNoneFound, licdomain.CopyrightStatusExtractionFailed},
	}, nil, uc)
	for _, want := range []string{`copyright status "none_found,extraction_failed"`, "recorded copyright status", matchExact} {
		if !strings.Contains(text, want) {
			t.Errorf("the zero-result statement does not carry %q:\n%s", want, text)
		}
	}
}

// A coordinate whose records disagree is listed — with the generation fields the
// row is now required to carry — and the run then fails. Deleting the answers
// for every other module would be the worse failure, and a licence in dispute
// must not read as a clean run.
func TestRunLicenseList_ConflictRowCarriesTheGenerationAndFailsTheRun(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/clean", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
		{
			ModulePath: "example.com/disputed", ModuleVersion: "v1.0.0",
			PipelineVersion: licapp.PipelineVersion,
			Conflict:        errors.New("primary_spdx disagrees"),
		},
	})

	withJSON(t, true)
	var stdout, stderr bytes.Buffer
	err := runLicenseList(context.Background(), licenseListFlags{limit: 50}, nil, uc,
		licdomain.NewLicenseOverrideSet(nil), &stdout, &stderr)
	if err == nil {
		t.Fatal("a disputed coordinate was reported as a clean run")
	}
	if !strings.Contains(err.Error(), "conflicting license records") {
		t.Errorf("the error does not name the disagreement: %v", err)
	}
	var doc struct {
		Records []map[string]any `json:"records"`
	}
	if jerr := json.Unmarshal(stdout.Bytes(), &doc); jerr != nil {
		t.Fatalf("decoding listing document: %v\n%s", jerr, stdout.String())
	}
	if len(doc.Records) != 2 {
		t.Fatalf("listed %d rows, want both the clean and the disputed module", len(doc.Records))
	}
	row := doc.Records[1]
	if row["status"] != "Conflict" || row["conflict"] != "primary_spdx disagrees" {
		t.Errorf("the disputed row = %v, want the disagreement on it", row)
	}
	if row["pipeline_version"] != licapp.PipelineVersion || row["superseded"] != false {
		t.Errorf("the disputed row does not carry the generation: %v", row)
	}
	if row["copyright_status"] != "not_analysed" {
		t.Errorf("the disputed row's copyright_status = %v; there is no served record, and the "+
			"row must still state a value rather than omit the key", row["copyright_status"])
	}

	// The text path prints the row and the remedy that shows the disagreement,
	// and fails afterwards for the same reason.
	withJSON(t, false)
	var text, textErr bytes.Buffer
	if terr := runLicenseList(context.Background(), licenseListFlags{limit: 50}, nil, uc,
		licdomain.NewLicenseOverrideSet(nil), &text, &textErr); terr == nil {
		t.Error("the text path reported a disputed coordinate as a clean run")
	}
	for _, want := range []string{"example.com/disputed@v1.0.0", "CONFLICT",
		"kanonarion license example.com/disputed@v1.0.0 --history"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("the text listing does not carry %q:\n%s", want, text.String())
		}
	}
}

// --- the generation statement in the document ---

// generationOf reads the document's generation object.
func generationOf(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	got, _ := doc["generation"].(map[string]any)
	if got == nil {
		t.Fatalf("the listing document carries no generation statement: %v", doc)
	}
	return got
}

// The text path says which generation answered and how to lift the restriction.
// The document must say the same: a consumer reading stdout that is told less
// than a person reading the terminal cannot tell that superseded records were
// excluded, and has nothing to name the flag that includes them.
//
// It is stated in all four states a listing can be in, because a field a
// consumer has to branch on is a field it cannot rely on.
func TestRunLicenseList_DocumentAlwaysStatesTheGeneration(t *testing.T) {
	populated := testfakes.NewFakeQueryLicense()
	populated.SetList([]licports.LicenseSummary{
		listSummary("example.com/served", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
		listSummary("example.com/old", "1.2.0", licdomain.CopyrightStatusFound),
	})
	scope := licenceScopeOf(t, "package", "./cmd/x", "example.com/served")

	for _, tc := range []struct {
		name     string
		flags    licenseListFlags
		scope    *licenceListScope
		uc       QueryLicenseUseCase
		all      bool
		wantRows int
	}{
		{"served generation", licenseListFlags{limit: 50}, nil, populated, false, 1},
		{"all generations", licenseListFlags{limit: 50, allGenerations: true}, nil, populated, true, 2},
		{"zero results", licenseListFlags{limit: 50, spdx: "NOSUCHLICENCE"}, nil, populated, false, 0},
		{"over-paged", licenseListFlags{limit: 50, offset: 10}, nil, populated, false, 0},
		{"scoped", licenseListFlags{limit: 50}, scope, populated, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := licenseListDoc(t, tc.flags, tc.scope, tc.uc)
			if records, _ := doc["records"].([]any); len(records) != tc.wantRows {
				t.Fatalf("listed %d rows, want %d", len(records), tc.wantRows)
			}
			gen := generationOf(t, doc)
			if gen["served"] != licapp.PipelineVersion {
				t.Errorf("generation.served = %v, want %s", gen["served"], licapp.PipelineVersion)
			}
			if gen["all_generations"] != tc.all {
				t.Errorf("generation.all_generations = %v, want %v", gen["all_generations"], tc.all)
			}
			// The remedy is the flag that lifts the restriction, and there is
			// nothing left to lift once it has been passed. conventions.md keeps
			// omitempty for strings on exactly that reading: an absent string
			// means "does not apply", and all_generations beside it names the
			// state.
			remedy, present := gen["remedy"]
			if tc.all {
				if present {
					t.Errorf("generation.remedy = %v under --all-generations, want it omitted", remedy)
				}
				return
			}
			if remedy != "--all-generations" {
				t.Errorf("generation.remedy = %v, want --all-generations", remedy)
			}
		})
	}
}

// The document's statement and the text path's line are the same fact, so a
// reader of either is told the same thing.
func TestRunLicenseList_TextAndDocumentAgreeOnTheGeneration(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/served", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
	})

	text := licenseListText(t, licenseListFlags{limit: 50}, nil, uc)
	gen := generationOf(t, licenseListDoc(t, licenseListFlags{limit: 50}, nil, uc))
	if !strings.Contains(text, gen["served"].(string)) || !strings.Contains(text, gen["remedy"].(string)) {
		t.Errorf("the text line and the document disagree:\n%s\n%v", text, gen)
	}
}

// Every other listing leaves the statement nil, so its document keeps exactly
// the key set it had. The generation field is license-list's, not a new key on
// every listing in the tree.
func TestListDocument_CarriesNoGenerationUnlessTheListingMakesOne(t *testing.T) {
	withJSON(t, true)
	var stdout bytes.Buffer
	if err := writeListDocument(&stdout, []int{1}, listTruncation{limit: 50, subject: "things"}, nil); err != nil {
		t.Fatalf("writeListDocument: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for _, key := range []string{"generation", "scope", "zero_result"} {
		if _, present := doc[key]; present {
			t.Errorf("a listing that makes no %s statement emitted one: %v", key, doc[key])
		}
	}
}

// --- the remedy for the modules holding no record ---

// A walk scope holds the walk id, which is the one argument that turns a
// per-module template into a command the reader can run once. The per-module
// form stays where there is no walk id: --package and --gomod are resolved by
// running `go list` over the working tree, which yields modules and no walk.
func TestRunLicenseList_WalkScopeNamesTheOneExtractionThatFillsThemAll(t *testing.T) {
	const walkID = "01M0VG1267S1XDJGDFZTVRPM84"
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		listSummary("example.com/recorded", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
	})
	walk := licenceScopeOf(t, "walk", walkID, "example.com/recorded", "example.com/missing")
	walk.walkID = walkID

	wantWalk := "kanonarion extract " + walkID + " --stages license"
	text := licenseListText(t, licenseListFlags{limit: 50}, walk, uc)
	if !strings.Contains(text, wantWalk) {
		t.Errorf("a walk scope does not name the extraction that fills every missing record:\n%s", text)
	}
	if strings.Contains(text, "<module>@<version>") {
		t.Errorf("a walk scope still prints a per-module template:\n%s", text)
	}
	if got := scopeEntry(t, walk, uc, "example.com/missing"); got["remedy"] != wantWalk {
		t.Errorf("the missing module's remedy = %v, want %q", got["remedy"], wantWalk)
	}

	// --package holds no walk id, so the per-module command is the only runnable
	// one and it is what both paths carry.
	pkg := licenceScopeOf(t, "package", "./cmd/x", "example.com/recorded", "example.com/missing")
	const wantPerModule = "run 'kanonarion license example.com/missing@v1.0.0'"
	pkgText := licenseListText(t, licenseListFlags{limit: 50}, pkg, uc)
	if !strings.Contains(pkgText, wantPerModule) {
		t.Errorf("a package scope does not name the per-module extraction:\n%s", pkgText)
	}
	if strings.Contains(pkgText, "kanonarion extract") {
		t.Errorf("a package scope named an extraction it holds no walk id for:\n%s", pkgText)
	}
	if got := scopeEntry(t, pkg, uc, "example.com/missing"); got["remedy"] != wantPerModule {
		t.Errorf("the missing module's remedy = %v, want %q", got["remedy"], wantPerModule)
	}
}

// scopeEntry reads one module's without_record entry out of the document.
func scopeEntry(t *testing.T, scope *licenceListScope, uc QueryLicenseUseCase, module string) map[string]any {
	t.Helper()
	got, _ := licenseListDoc(t, licenseListFlags{limit: 50}, scope, uc)["scope"].(map[string]any)
	without, _ := got["without_record"].([]any)
	for _, raw := range without {
		if e, _ := raw.(map[string]any); e["module"] == module {
			return e
		}
	}
	t.Fatalf("without_record holds no entry for %s: %v", module, got["without_record"])
	return nil
}

// A build holds four kinds of module with no licence record, and only ONE of
// them is filled by extracting the walk. Printing that extraction beside the
// other three is a remedy that runs and does not do the thing: an operator
// follows it, re-lists, and is shown the same three modules under the same
// line.
//
// So each kind carries its own statement, and the bulk extraction is offered
// with the count it actually fills.
func TestRunLicenseList_WithoutRecordIsPartitionedByWhyTheRecordIsAbsent(t *testing.T) {
	const walkID = "01M0VG1267S1XDJGDFZTVRPM84"
	uc := testfakes.NewFakeQueryLicense()

	root := coordinatetest.MustNew("example.com/proj", "local")
	replaced := coordinatetest.MustNew("example.com/proj/sub", "v0.0.0-20250630054201-94c0ba7b0952")
	stdlib := coordinatetest.MustNew("stdlib", "v1.26.6")
	dep := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	other := coordinatetest.MustNew("example.com/other", "v2.0.0")

	scope := &licenceListScope{kind: "walk", value: walkID, walkID: walkID, mods: []scopeModule{
		{coord: dep}, {coord: other},
		{original: replaced, localPath: "./sub"},
		{coord: root}, {coord: stdlib},
	}}

	doc := licenseListDoc(t, licenseListFlags{limit: 50}, scope, uc)
	got, _ := doc["scope"].(map[string]any)
	without, _ := got["without_record"].([]any)
	if len(without) != 5 {
		t.Fatalf("without_record holds %d entries, want all five modules", len(without))
	}
	byModule := map[string]map[string]any{}
	for _, raw := range without {
		e, _ := raw.(map[string]any)
		byModule[e["module"].(string)] = e
	}

	bulk := "kanonarion extract " + walkID + " --stages license"
	for _, tc := range []struct {
		module     string
		kind       string
		wantRemedy string
		reasonHas  string
	}{
		{"example.com/dep", absenceNotExtracted, bulk, "extraction has not produced"},
		{"example.com/other", absenceNotExtracted, bulk, "extraction has not produced"},
		// The local-path target and the main module are not published, so the
		// extraction above can never reach them whatever it is run over.
		{"example.com/proj/sub", absenceLocalReplace, "", "./sub"},
		{"example.com/proj", absenceLocalRoot, "", "main module"},
		// The standard library holds no record by design, and no invocation
		// produces one; the statement is notice's own.
		{"stdlib", absenceStdlib, "", "ships with the toolchain"},
	} {
		e := byModule[tc.module]
		if e == nil {
			t.Errorf("%s is not named in without_record", tc.module)
			continue
		}
		if e["kind"] != tc.kind {
			t.Errorf("%s kind = %v, want %s", tc.module, e["kind"], tc.kind)
		}
		if !strings.Contains(e["reason"].(string), tc.reasonHas) {
			t.Errorf("%s reason = %q, want it to say %q", tc.module, e["reason"], tc.reasonHas)
		}
		remedy, _ := e["remedy"].(string)
		if tc.wantRemedy != "" && remedy != tc.wantRemedy {
			t.Errorf("%s remedy = %q, want %q", tc.module, remedy, tc.wantRemedy)
		}
		if tc.wantRemedy == "" && remedy == bulk {
			t.Errorf("%s was given the bulk extraction, which can never produce its record", tc.module)
		}
	}
	// stdlib is the one the shared statement must word, so it is compared
	// against that statement rather than against a copy of the words.
	if byModule["stdlib"]["reason"] != licapp.StdlibMissingRecordReason(stdlib) {
		t.Errorf("the standard library's statement is not notice's: %q", byModule["stdlib"]["reason"])
	}

	// The text path groups by statement, so the bulk extraction is printed once,
	// with the count it fills — not the count of modules holding no record.
	text := licenseListText(t, licenseListFlags{limit: 50}, scope, uc)
	if !strings.Contains(text, "2 module(s): extraction has not produced a licence record for it") {
		t.Errorf("the bulk extraction does not name the 2 modules it fills:\n%s", text)
	}
	if !strings.Contains(text, "to produce them: "+bulk) {
		t.Errorf("the bulk extraction is not offered:\n%s", text)
	}
	if strings.Count(text, bulk) != 1 {
		t.Errorf("the bulk extraction is printed %d times, want once:\n%s", strings.Count(text, bulk), text)
	}
	if !strings.Contains(text, "no invocation produces this record") {
		t.Errorf("a group nothing can fill does not say so:\n%s", text)
	}
	for _, module := range []string{"example.com/proj/sub@", "example.com/proj@local", "stdlib@v1.26.6"} {
		if !strings.Contains(text, module) {
			t.Errorf("%s is not named on the text path:\n%s", module, text)
		}
	}
}
