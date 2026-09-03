package domain_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func sonicLoader() domain.ForeignModule {
	return domain.ForeignModule{Path: "github.com/bytedance/sonic/loader", Version: "v0.3.0"}
}

// TestForeignModule_StringNamesTheVersionOrSaysThereIsNone: an unversioned
// foreign module must not render as a bare "path@", which reads as a coordinate
// whose version was lost rather than one resolution never gave.
func TestForeignModule_StringNamesTheVersionOrSaysThereIsNone(t *testing.T) {
	t.Parallel()

	if got, want := sonicLoader().String(), "github.com/bytedance/sonic/loader@v0.3.0"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	unversioned := domain.ForeignModule{Path: "example.com/nested"}
	if got, want := unversioned.String(), "example.com/nested (no version resolved)"; got != want {
		t.Errorf("String() of an unversioned module = %q, want %q", got, want)
	}
}

// TestForeignModuleLess_IsTotalOverPathAndVersion pins the canonical ordering:
// one module path resolved at two versions in one analysis must still have a
// defined order, or the sealed bytes depend on emission order.
func TestForeignModuleLess_IsTotalOverPathAndVersion(t *testing.T) {
	t.Parallel()

	a := domain.ForeignModule{Path: "example.com/a", Version: "v2.0.0"}
	b := domain.ForeignModule{Path: "example.com/b", Version: "v1.0.0"}
	if !domain.ForeignModuleLess(a, b) || domain.ForeignModuleLess(b, a) {
		t.Error("path does not lead the ordering")
	}
	lo := domain.ForeignModule{Path: "example.com/a", Version: "v1.0.0"}
	if !domain.ForeignModuleLess(lo, a) || domain.ForeignModuleLess(a, lo) {
		t.Error("version does not break a tie on path")
	}
	if domain.ForeignModuleLess(a, a) {
		t.Error("a module compares less than itself")
	}
}

// TestForeignModuleOwning_MatchesOnPathSegments is the whole risk in the
// prefix test: "example.com/nested" must not claim a node of
// "example.com/nestedother", and must claim both its own root package's
// declarations and those of packages under it.
func TestForeignModuleOwning_MatchesOnPathSegments(t *testing.T) {
	t.Parallel()

	mods := []domain.ForeignModule{{Path: "example.com/nested", Version: "v1.2.3"}}
	for _, tc := range []struct {
		name string
		id   string
		want bool
	}{
		{"root package function", "example.com/nested.Fn", true},
		{"root package method", "example.com/nested.(*T).M", true},
		{"package below it", "example.com/nested/inner.Fn", true},
		{"a longer module path sharing the prefix", "example.com/nestedother.Fn", false},
		{"the parent itself", "example.com.Fn", false},
		{"an unrelated module", "example.com/other.Fn", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := domain.ForeignModuleOwning(mods, tc.id)
			if ok != tc.want {
				t.Fatalf("ForeignModuleOwning(%q) ok = %v, want %v", tc.id, ok, tc.want)
			}
			if ok && got.Version != "v1.2.3" {
				t.Errorf("the match lost the version: %+v", got)
			}
		})
	}
}

// TestForeignModuleOwning_EmptyPathClaimsNothing: an empty module path is a
// prefix of every string, so a zero entry that slipped into the set would claim
// every node in the answer.
func TestForeignModuleOwning_EmptyPathClaimsNothing(t *testing.T) {
	t.Parallel()

	if _, ok := domain.ForeignModuleOwning([]domain.ForeignModule{{}}, "example.com/m.Fn"); ok {
		t.Error("a zero-valued foreign module claimed a node")
	}
	if _, ok := domain.ForeignModuleOwning(nil, "example.com/m.Fn"); ok {
		t.Error("an empty set claimed a node")
	}
}

// TestForeignModulesBuilt_IsHashTransparentWhenEmpty is the acceptance the
// ticket's resolution rests on. VerifyContentHash re-marshals the struct rather
// than checking stored bytes, so a key present on a record that built no foreign
// module would move every stored record's digest. The field must be omitted, and
// the bytes must be byte-identical to those of a record that never had it.
func TestForeignModulesBuilt_IsHashTransparentWhenEmpty(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	rec := makeTestRecord()
	sealed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(data, []byte("foreign_modules_built")) {
		t.Errorf("a record that built no foreign module carries the key:\n%s", data)
	}
	// An explicitly empty slice is the same statement as a nil one and must seal
	// to the same bytes; nothing may distinguish them on the wire.
	rec.ForeignModulesBuilt = []domain.ForeignModule{}
	emptySealed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash on an empty slice: %v", err)
	}
	if emptySealed.ContentHash != sealed.ContentHash {
		t.Errorf("an empty slice sealed differently from nil: %q vs %q",
			emptySealed.ContentHash, sealed.ContentHash)
	}
}

// TestForeignModulesBuilt_SealsVerifiesAndRoundTrips: the populated case must
// survive the seal, the verification and the wire, with the versions intact —
// the version is the half the record could not previously state.
func TestForeignModulesBuilt_SealsVerifiesAndRoundTrips(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	rec := makeTestRecord()
	// Emitted out of order on purpose: canonical ordering is the hasher's job.
	rec.ForeignModulesBuilt = []domain.ForeignModule{
		sonicLoader(),
		{Path: "example.com/nested", Version: "v1.0.0"},
	}
	sealed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := h.VerifyContentHash(sealed); err != nil {
		t.Fatalf("a sealed record with foreign modules does not verify: %v", err)
	}
	data, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(back.ForeignModulesBuilt) != 2 {
		t.Fatalf("round trip returned %d foreign modules, want 2: %+v", len(back.ForeignModulesBuilt), back.ForeignModulesBuilt)
	}
	if got := back.ForeignModulesBuilt[0]; got.Path != "example.com/nested" || got.Version != "v1.0.0" {
		t.Errorf("first foreign module after the round trip = %+v; the sealed order is by path", got)
	}
	if got := back.ForeignModulesBuilt[1]; got != sonicLoader() {
		t.Errorf("second foreign module after the round trip = %+v, want %+v", got, sonicLoader())
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("the record read back off the wire does not verify: %v", err)
	}
}

// TestForeignModulesBuilt_EmissionOrderDoesNotChangeTheSeal: two analyses that
// found the same foreign modules in different orders describe one graph, and a
// seal that depended on emission order would make them disagree.
func TestForeignModulesBuilt_EmissionOrderDoesNotChangeTheSeal(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	mods := []domain.ForeignModule{
		{Path: "example.com/b", Version: "v1.0.0"},
		{Path: "example.com/a", Version: "v2.0.0"},
		{Path: "example.com/a", Version: "v1.0.0"},
	}
	first := makeTestRecord()
	first.ForeignModulesBuilt = mods
	second := makeTestRecord()
	second.ForeignModulesBuilt = []domain.ForeignModule{mods[2], mods[0], mods[1]}

	a, err := h.SetContentHash(first)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	b, err := h.SetContentHash(second)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if a.ContentHash != b.ContentHash {
		t.Errorf("emission order changed the seal: %q vs %q", a.ContentHash, b.ContentHash)
	}
}

// TestForeignModulesColumn_RoundTrips pins the denormalised rendering both ways.
// The column is a copy of what the blob holds, so a value that does not read
// back as it was written is a column that silently contradicts the record it
// copies — migration 9's defect, on a new field.
func TestForeignModulesColumn_RoundTrips(t *testing.T) {
	t.Parallel()

	mods := []domain.ForeignModule{
		{Path: "example.com/nested", Version: "v1.0.0"},
		sonicLoader(),
		// Resolution named no version: the entry keeps its shape and carries an
		// empty version rather than being dropped or rendered a second way.
		{Path: "example.com/replaced"},
	}
	col := domain.ForeignModulesColumn(mods)
	back, err := domain.ParseForeignModulesColumn(col)
	if err != nil {
		t.Fatalf("ParseForeignModulesColumn(%q): %v", col, err)
	}
	if len(back) != 3 {
		t.Fatalf("round trip returned %d modules, want 3: %+v", len(back), back)
	}
	want := []domain.ForeignModule{
		{Path: "example.com/nested", Version: "v1.0.0"},
		{Path: "example.com/replaced"},
		sonicLoader(),
	}
	for i := range want {
		if back[i] != want[i] {
			t.Errorf("round trip [%d] = %+v, want %+v", i, back[i], want[i])
		}
	}
}

// TestForeignModulesColumn_EmissionOrderDoesNotChangeTheColumn: the column is
// compared and read as a value, so two records holding the same set must render
// the same string whatever order the analyser emitted them in.
func TestForeignModulesColumn_EmissionOrderDoesNotChangeTheColumn(t *testing.T) {
	t.Parallel()

	a := domain.ForeignModulesColumn([]domain.ForeignModule{
		{Path: "example.com/b", Version: "v1.0.0"},
		{Path: "example.com/a", Version: "v2.0.0"},
	})
	b := domain.ForeignModulesColumn([]domain.ForeignModule{
		{Path: "example.com/a", Version: "v2.0.0"},
		{Path: "example.com/b", Version: "v1.0.0"},
	})
	if a != b {
		t.Errorf("emission order changed the column: %q vs %q", a, b)
	}
}

// TestForeignModulesColumn_EmptySetIsTheEmptyString: the column's empty value has
// exactly one meaning, and the back-fill is what earns it. Nothing here may
// invent a second rendering for "none".
func TestForeignModulesColumn_EmptySetIsTheEmptyString(t *testing.T) {
	t.Parallel()

	if got := domain.ForeignModulesColumn(nil); got != "" {
		t.Errorf("ForeignModulesColumn(nil) = %q, want the empty string", got)
	}
	if got := domain.ForeignModulesColumn([]domain.ForeignModule{}); got != "" {
		t.Errorf("ForeignModulesColumn(empty) = %q, want the empty string", got)
	}
	// A zero-valued entry names no module, so it renders nothing rather than an
	// entry a reader would parse back as a module called "".
	if got := domain.ForeignModulesColumn([]domain.ForeignModule{{}}); got != "" {
		t.Errorf("ForeignModulesColumn(zero entry) = %q, want the empty string", got)
	}
	back, err := domain.ParseForeignModulesColumn("")
	if err != nil {
		t.Fatalf("ParseForeignModulesColumn(\"\"): %v", err)
	}
	if back != nil {
		t.Errorf("the empty column parsed to %+v, want nil", back)
	}
}

// TestParseForeignModulesColumn_RefusesWhatItCannotRead: only the write leg and
// the back-fill write this column, and both write one shape. Anything else is a
// hand-edited row, and reading one as "no foreign modules" would drop a
// qualification the store is carrying — silently, which is the failure the axis
// exists to remove.
func TestParseForeignModulesColumn_RefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{
		"example.com/nested",          // no "@" at all
		"@v1.0.0",                     // no path
		"example.com/a@v1 not-a-pair", // one good entry, one not
	} {
		if _, err := domain.ParseForeignModulesColumn(bad); err == nil {
			t.Errorf("ParseForeignModulesColumn(%q) returned no error", bad)
		} else if !errors.Is(err, domain.ErrMalformedForeignModulesColumn) {
			t.Errorf("ParseForeignModulesColumn(%q) = %v, want ErrMalformedForeignModulesColumn", bad, err)
		}
	}
}
