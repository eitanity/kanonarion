package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"
)

// datedStalenessLookup answers with a latest version and a publication date, so
// a row can carry the age figure the ahead case has to suppress and the behind
// case has to keep.
type datedStalenessLookup struct {
	latest      string
	publishedAt time.Time
}

func (d datedStalenessLookup) Resolve(_ context.Context, path, _ string) (staleapp.Answer, error) {
	return staleapp.Answer{Record: staledomain.Record{
		ModulePath:        path,
		LatestVersion:     d.latest,
		LatestPublishedAt: d.publishedAt,
		LookedUpAt:        time.Now(),
	}}, nil
}

// pinAheadCases are the three shapes a pin ahead of @latest takes, each drawn
// from a coordinate measured in the real store, plus the controls that must be
// unaffected. Every one of the ahead rows previously rendered as
// "latest: <older version> (N days ago)" — an upgrade target that is a
// downgrade, with a nine-year age figure beside it.
var pinAheadCases = []struct {
	name string
	// pinned is what go.mod names; latest is what the proxy answers.
	pinned     string
	latest     string
	wantAhead  bool
	wantColumn string
}{
	{
		name:       "incompatible major above a vN-less latest",
		pinned:     "v3.3.4+incompatible",
		latest:     "v1.5.5",
		wantAhead:  true,
		wantColumn: "ahead of latest tag: v1.5.5",
	},
	{
		name:       "pseudo-version taken after the last tag",
		pinned:     "v1.0.1-0.20181226105442-5d4384ee4fb2",
		latest:     "v1.0.0",
		wantAhead:  true,
		wantColumn: "ahead of latest tag: v1.0.0",
	},
	{
		name:       "a plain tag above the latest one published",
		pinned:     "v1.1.5",
		latest:     "v0.5.5",
		wantAhead:  true,
		wantColumn: "ahead of latest tag: v0.5.5",
	},
	{
		// The non-zero control. A module that IS behind still names its target
		// and its age; the fix suppresses one row shape, not the column.
		name:       "genuinely behind still names the target and the age",
		pinned:     "v1.19.0",
		latest:     "v1.19.2",
		wantAhead:  false,
		wantColumn: "latest: v1.19.2 (30 days ago)",
	},
	{
		name:       "level",
		pinned:     "v1.6.0",
		latest:     "v1.6.0",
		wantAhead:  false,
		wantColumn: "current",
	},
}

// TestAuditStaleness_PinAheadOfLatestOffersNoTarget: the audit row. A pin that
// sorts above @latest reports no upgrade target and no age, and a pin that is
// behind is untouched.
func TestAuditStaleness_PinAheadOfLatestOffersNoTarget(t *testing.T) {
	published := time.Now().Add(-30 * 24 * time.Hour)
	for _, tc := range pinAheadCases {
		t.Run(tc.name, func(t *testing.T) {
			coord, err := coordinate.NewModuleCoordinate("example.com/mod", tc.pinned)
			if err != nil {
				t.Fatalf("NewModuleCoordinate: %v", err)
			}
			var res auditModuleResult
			var stderr bytes.Buffer
			applyAuditStaleness(context.Background(), &res, coord,
				datedStalenessLookup{latest: tc.latest, publishedAt: published}, &stderr)

			if res.IsLatest == nil {
				t.Fatalf("row is unmeasured (%q); the lookup answered", res.StalenessUnmeasured)
			}
			if res.PinAheadOfLatest == nil {
				t.Fatal("pin_ahead_of_latest is null on a measured row")
			}
			if *res.PinAheadOfLatest != tc.wantAhead {
				t.Errorf("pin_ahead_of_latest = %v, want %v", *res.PinAheadOfLatest, tc.wantAhead)
			}
			// The age is the figure that made is_latest:false read as "behind".
			if tc.wantAhead && res.LatestReleaseAgeDays != nil {
				t.Errorf("latest_release_age_days = %d on an ahead row; JSON and text must not disagree", *res.LatestReleaseAgeDays)
			}
			if !tc.wantAhead && !*res.IsLatest && res.LatestReleaseAgeDays == nil {
				t.Error("the non-zero control lost its age figure")
			}
			if got := auditStalenessCell(res); got != tc.wantColumn {
				t.Errorf("column = %q, want %q", got, tc.wantColumn)
			}
			if tc.wantAhead && strings.Contains(auditStalenessCell(res), "days ago") {
				t.Errorf("an age figure is rendered for a pin that is behind nothing: %q", auditStalenessCell(res))
			}
		})
	}
}

// TestAuditStaleness_PinAheadKeepsTheNewerMajorFact: the +incompatible shape is
// the majority of the class, and it is the one where "current" would be a lie —
// the module DOES have a newer major line, it simply does not live at a path
// @latest can answer from. The row says the pin is ahead of the latest tag AND
// states the newer major, because those are two facts and both are true.
func TestAuditStaleness_PinAheadKeepsTheNewerMajorFact(t *testing.T) {
	measured, ahead := false, true
	row := auditModuleResult{
		IsLatest:         &measured,
		PinAheadOfLatest: &ahead,
		LatestVersion:    "v1.5.5",
		MajorProbed:      true,
		NewerMajorModule: "example.com/mod/v5",
		NewerMajorLatest: "v5.2.3",
	}
	if got, want := auditStalenessCell(row), "ahead of latest tag: v1.5.5"; got != want {
		t.Errorf("column = %q, want %q", got, want)
	}
	if got, want := auditNewerMajorNote(row), "newer major: example.com/mod/v5@v5.2.3"; got != want {
		t.Errorf("newer-major fact = %q, want %q", got, want)
	}
}

// TestLatestRow_PinAheadOfLatestOffersNoTarget: the same defect on `latest`,
// which builds its row from its own copy of the comparison.
func TestLatestRow_PinAheadOfLatestOffersNoTarget(t *testing.T) {
	published := time.Now().Add(-30 * 24 * time.Hour)
	for _, tc := range pinAheadCases {
		t.Run(tc.name, func(t *testing.T) {
			row, _ := latestRowFor(context.Background(),
				datedStalenessLookup{latest: tc.latest, publishedAt: published},
				"example.com/mod", tc.pinned, io.Discard)
			if row.IsLatest == nil {
				t.Fatalf("row is unmeasured (%q); the lookup answered", row.StalenessUnmeasured)
			}
			if row.PinAheadOfLatest == nil {
				t.Fatal("pin_ahead_of_latest is null on a measured row")
			}
			if *row.PinAheadOfLatest != tc.wantAhead {
				t.Errorf("pin_ahead_of_latest = %v, want %v", *row.PinAheadOfLatest, tc.wantAhead)
			}
			if tc.wantAhead && row.LatestReleaseAgeDays != nil {
				t.Errorf("latest_release_age_days = %d on an ahead row; JSON and text must not disagree", *row.LatestReleaseAgeDays)
			}
			if !tc.wantAhead && !*row.IsLatest && row.LatestReleaseAgeDays == nil {
				t.Error("the non-zero control lost its age figure")
			}

			var out bytes.Buffer
			if err := printLatestTable(&out, []latestResult{row}); err != nil {
				t.Fatalf("printLatestTable: %v", err)
			}
			if tc.wantAhead {
				if !strings.Contains(out.String(), "ahead of latest tag: "+tc.latest) {
					t.Errorf("table does not state the pin is ahead:\n%s", out.String())
				}
				if strings.Contains(out.String(), "days ago") {
					t.Errorf("an age figure is rendered for a pin that is behind nothing:\n%s", out.String())
				}
			}
		})
	}
}

// TestFetchStaleness_PinAheadOfLatestOffersNoTarget: the third copy of the
// comparison, on `fetch`.
func TestFetchStaleness_PinAheadOfLatestOffersNoTarget(t *testing.T) {
	published := time.Now().Add(-3000 * 24 * time.Hour)
	for _, tc := range pinAheadCases {
		t.Run(tc.name, func(t *testing.T) {
			coord, err := coordinate.NewModuleCoordinate("example.com/mod", tc.pinned)
			if err != nil {
				t.Fatalf("NewModuleCoordinate: %v", err)
			}
			stale := fetchStalenessFor(context.Background(),
				stubLatestInfo{info: staleports.LatestInfo{Version: tc.latest, Time: published}},
				coord, tc.pinned, io.Discard)
			if stale.IsLatest == nil {
				t.Fatalf("staleness is unmeasured (%q); the proxy answered", stale.Unmeasured)
			}
			if stale.PinAheadOfLatest == nil {
				t.Fatal("pin_ahead_of_latest is null on a measured block")
			}
			if *stale.PinAheadOfLatest != tc.wantAhead {
				t.Errorf("pin_ahead_of_latest = %v, want %v", *stale.PinAheadOfLatest, tc.wantAhead)
			}
			note := fetchStalenessNote(stale)
			if tc.wantAhead {
				if note != " [ahead of latest tag: "+tc.latest+"]" {
					t.Errorf("note = %q, want an ahead-of-latest clause", note)
				}
				if stale.DaysSince != nil {
					t.Errorf("days_since = %d for a pin that is behind nothing", *stale.DaysSince)
				}
			}
		})
	}
}

// columnStarts returns the index at which each column of a padded row begins.
// Columns are separated by two or more spaces, which is the table's own
// separator, so two rows agree on alignment exactly when these agree.
func columnStarts(line string) []int {
	starts := []int{0}
	for i := 0; i+1 < len(line); i++ {
		if line[i] == ' ' && line[i+1] == ' ' {
			j := i
			for j < len(line) && line[j] == ' ' {
				j++
			}
			if j < len(line) {
				starts = append(starts, j)
			}
			i = j
		}
	}
	return starts
}

// TestPrintAuditTable_ColumnsLineUpAcrossEveryRowShape: the alignment defect.
//
// The columns were padded to constants, so any cell wider than its constant —
// which every "latest: vX (N days ago)" is, and every long licence expression —
// pushed each column to its right out of line ON THAT ROW ONLY. The widest
// value in the run now sets the width, and the two-fact staleness value, which
// is wider than the rest of the row put together, is stated in full on a
// continuation line rather than setting the column.
func TestPrintAuditTable_ColumnsLineUpAcrossEveryRowShape(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		t.Run(fmt.Sprintf("scope column=%v", scoped), func(t *testing.T) {
			assertAuditTableAligns(t, scoped)
		})
	}
}

func assertAuditTableAligns(t *testing.T, scoped bool) {
	t.Helper()
	current, behind := true, false
	results := []auditModuleResult{
		{
			Coordinate: "github.com/dustin/go-humanize@v1.0.1", Verification: "Verified",
			License: "MIT", LicenseStatus: "Detected", LicenseResolved: true,
			VulnStatus: "Clean", PolicyOutcome: "allow", LicenseCategory: "permissive",
			IsLatest: &current,
		},
		{
			Coordinate: "github.com/klauspost/compress@v1.19.0", Verification: "Verified",
			License: "Apache-2.0", LicenseStatus: "Multiple", LicenseResolved: true,
			VulnStatus: "Clean", PolicyOutcome: "allow", LicenseCategory: "permissive",
			IsLatest: &behind, LatestVersion: "v1.19.2", LatestReleaseAgeDays: measuredAgeDays(7),
		},
		{
			// The row that used to shift everything to its right.
			Coordinate: "modernc.org/libc@v1.73.5", Verification: "Verified",
			License: "BSD-3-Clause", LicenseStatus: "Detected", LicenseResolved: true,
			VulnStatus: "Clean", PolicyOutcome: "allow", LicenseCategory: "permissive",
			IsLatest: &behind, LatestVersion: "v1.75.3", LatestReleaseAgeDays: measuredAgeDays(5),
			MajorProbed: true, NewerMajorModule: "modernc.org/libc/v2", NewerMajorLatest: "v2.1.30",
		},
		{
			Coordinate: "stdlib@v1.26.5", Verification: "VerifiedGoDevChecksum",
			License: "BSD-3-Clause", LicenseStatus: "Detected", LicenseResolved: true,
			VulnStatus: "Clean", PolicyOutcome: "allow", LicenseCategory: "permissive",
			StalenessSource: stalenessSourceUnmeasured, StalenessUnmeasured: stalenessToolchainPinned,
		},
	}

	// The scope column shifts every index to its right, including the one the
	// continuation line is indented to, so both arities are exercised.
	if scoped {
		for i := range results {
			results[i].Scope = "code"
		}
	}

	var out bytes.Buffer
	if err := printAuditTable(&out, results); err != nil {
		t.Fatalf("printAuditTable: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")

	var want []int
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimLeft(line, " "), "newer major:") {
			continue
		}
		got := columnStarts(line)
		if want == nil {
			want = got
			continue
		}
		if len(got) != len(want) {
			t.Fatalf("row has %d columns, the first row has %d:\n%s", len(got), len(want), out.String())
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("column %d starts at %d on this row and %d on the first:\n%s", i, got[i], want[i], out.String())
			}
		}
	}

	// Nothing is truncated to fit: the two-fact value is still reported whole.
	if !strings.Contains(out.String(), "newer major: modernc.org/libc/v2@v2.1.30") {
		t.Errorf("the newer-major fact is not reported in full:\n%s", out.String())
	}
	// And it is stated under the staleness column it belongs to, not at the
	// left margin where it would read as another module's row.
	for _, line := range lines {
		if trimmed := strings.TrimLeft(line, " "); strings.HasPrefix(trimmed, "newer major:") {
			if indent := len(line) - len(trimmed); indent != want[len(want)-3] {
				t.Errorf("continuation indented to %d, want the staleness column at %d:\n%s", indent, want[len(want)-3], out.String())
			}
		}
	}
	// No row is padded past its last cell.
	for _, line := range lines {
		if strings.HasSuffix(line, " ") {
			t.Errorf("row carries trailing padding: %q", line)
		}
	}
}

// TestAuditStaleness_JSONAndTextAgreeOnTheAgeFigure
//
// The text column dropped the age on an ahead row and --json kept it, so a
// machine consumer reading is_latest:false beside latest_release_age_days:3868
// still concluded the project was nine years behind go-difflib — the original
// wrong answer surviving on the surface most likely to be read by a machine.
// The age is a distance, and a distance is only emitted where something is
// being offered to close it.
func TestAuditStaleness_JSONAndTextAgreeOnTheAgeFigure(t *testing.T) {
	published := time.Now().Add(-3868 * 24 * time.Hour)
	for _, tc := range pinAheadCases {
		t.Run(tc.name, func(t *testing.T) {
			coord, err := coordinate.NewModuleCoordinate("example.com/mod", tc.pinned)
			if err != nil {
				t.Fatalf("NewModuleCoordinate: %v", err)
			}
			var res auditModuleResult
			applyAuditStaleness(context.Background(), &res, coord,
				datedStalenessLookup{latest: tc.latest, publishedAt: published}, io.Discard)

			encoded, err := json.Marshal(res)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}

			// pin_ahead_of_latest is present on every measured row, false included.
			got, ok := decoded["pin_ahead_of_latest"]
			if !ok {
				t.Fatal("pin_ahead_of_latest is absent; a consumer cannot tell false from not-derived")
			}
			if got != tc.wantAhead {
				t.Errorf("pin_ahead_of_latest = %v, want %v", got, tc.wantAhead)
			}

			// "Carries an age" means a VALUE, not a key: the key is always
			// present now, and null there is the statement that there is none.
			age, present := decoded["latest_release_age_days"]
			if !present {
				t.Fatal("latest_release_age_days is absent; null and absent are different claims")
			}
			hasAge := age != nil
			textHasAge := strings.Contains(auditStalenessCell(res), "days ago")

			// The rule is about what the age travels WITH. Beside
			// is_latest:true it is the age of a release the project is already
			// on, which no consumer reads as a distance, and it is kept — the
			// text says "current" there and the two surfaces are not in
			// conflict. Beside is_latest:FALSE it reads as "you are this far
			// behind", so it must be present exactly when the text offers a
			// target and absent exactly when it does not.
			if *res.IsLatest {
				if !hasAge {
					t.Error("a current row dropped the release age, which is a fact about the release")
				}
				return
			}
			if hasAge != textHasAge {
				t.Errorf("beside is_latest:false the JSON carries an age (%v) and the text carries one (%v) — the surfaces disagree: %s / %s",
					hasAge, textHasAge, encoded, auditStalenessCell(res))
			}
			if tc.wantAhead && hasAge {
				t.Errorf("an ahead row emits an age beside is_latest:false: %s", encoded)
			}
		})
	}
}

// TestAuditStaleness_UnmeasuredRowAnswersNeitherQuestion: an unmeasured row
// made no comparison, so a bare false on pin_ahead_of_latest would answer a
// question nobody put — the same absence-as-answer is_latest was made a pointer
// to prevent.
func TestAuditStaleness_UnmeasuredRowAnswersNeitherQuestion(t *testing.T) {
	var row auditModuleResult
	row.markStalenessUnmeasured(stalenessToolchainPinned)

	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"is_latest", "pin_ahead_of_latest"} {
		v, ok := decoded[key]
		if !ok {
			t.Errorf("%s is absent; the key states the question was not answered", key)
		}
		if v != nil {
			t.Errorf("%s = %v on an unmeasured row, want null", key, v)
		}
	}
}
