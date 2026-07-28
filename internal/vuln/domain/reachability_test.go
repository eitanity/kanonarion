package domain_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// A route is normalised to entry point first, whichever analyser produced it.
// govulncheck reports the reverse — vulnerable symbol first — so a stored route
// that could be in either order is one no consumer can render without guessing
// which instrument wrote it.
func TestReachabilityRoute_Reverse(t *testing.T) {
	t.Parallel()
	asReported := domain.ReachabilityRoute{
		{ModulePath: "golang.org/x/text", ModuleVersion: "v0.3.0", Symbol: "Parse"},
		{ModulePath: "google.golang.org/grpc", ModuleVersion: "v1.82.0", Symbol: "Dial"},
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", Symbol: "main"},
	}
	got := asReported.Reverse()
	if got[0].Symbol != "main" || got[len(got)-1].Symbol != "Parse" {
		t.Fatalf("reversed route is not entry-point-first: %v", got)
	}
	// The original is untouched: the analyser may still need it in its own order.
	if asReported[0].Symbol != "Parse" {
		t.Fatal("Reverse mutated its receiver")
	}
}

// A partially versioned route reports itself as unversioned. The version exists
// so a reader can check the route against their own build, and a route that
// answers that for some hops and not others cannot be checked at all.
func TestReachabilityRoute_IsVersioned(t *testing.T) {
	t.Parallel()
	versioned := domain.ReachabilityRoute{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", Symbol: "main"},
		{ModulePath: "golang.org/x/text", ModuleVersion: "v0.3.0", Symbol: "Parse"},
	}
	if !versioned.IsVersioned() {
		t.Fatal("a fully versioned route reported itself as unversioned")
	}

	// A dependency hop with no version makes the route uncheckable.
	partial := domain.ReachabilityRoute{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", Symbol: "main"},
		{ModulePath: "golang.org/x/text", Symbol: "Parse"},
	}
	if partial.IsVersioned() {
		t.Fatal("a route with an unversioned dependency hop claimed to be checkable")
	}

	// The ENTRY POINT is exempt, and this is the shape of almost every real
	// govulncheck route: a main module has no version in a Go build, so its frame
	// arrives without one. Requiring a version there would report every route
	// from a project scan as uncheckable.
	rootUnversioned := domain.ReachabilityRoute{
		{ModulePath: "example.com/proj", Package: "example.com/proj", Symbol: "main"},
		{ModulePath: "golang.org/x/text", ModuleVersion: "v0.37.0", Symbol: "Append"},
	}
	if !rootUnversioned.IsVersioned() {
		t.Fatal("a route whose only unversioned hop is the entry point was reported uncheckable")
	}

	// The shape of a real project route, measured on a working store: several
	// hops inside the project's own module before it reaches a dependency. Those
	// hops carry no version because a main module has none, and the route is
	// still checkable — the dependency part is the only part a reader compares.
	throughRoot := domain.ReachabilityRoute{
		{ModulePath: "github.com/org/app", Package: "github.com/org/app/internal/a", Symbol: "Handler"},
		{ModulePath: "github.com/org/app", Package: "github.com/org/app/internal/b", Symbol: "recv"},
		{ModulePath: "google.golang.org/grpc", ModuleVersion: "v1.82.0", Symbol: "recvMsg"},
	}
	if !throughRoot.IsVersioned() {
		t.Fatal("a route through several root-module hops was reported uncheckable")
	}

	// A route that never leaves the root has no dependency to compare.
	rootOnlyDeep := domain.ReachabilityRoute{
		{ModulePath: "github.com/org/app", Symbol: "main"},
		{ModulePath: "github.com/org/app", Symbol: "run"},
	}
	if rootOnlyDeep.IsVersioned() {
		t.Fatal("a route that never leaves the root module claimed to be checkable")
	}

	// A call-graph route names no versions at all, so its dependency hops fail.
	unversioned := domain.ReachabilityRoute{
		{ModulePath: "example.com/proj", Symbol: "main"},
		{ModulePath: "golang.org/x/text", Symbol: "Append"},
	}
	if unversioned.IsVersioned() {
		t.Fatal("a route with no versions claimed to be checkable")
	}

	if (domain.ReachabilityRoute{}).IsVersioned() {
		t.Fatal("an empty route claimed to be versioned")
	}

	// A route of one hop is the root alone: there is no dependency in it to
	// check against another build, so it is not checkable however well the one
	// hop is identified.
	rootOnly := domain.ReachabilityRoute{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", Symbol: "main"},
	}
	if rootOnly.IsVersioned() {
		t.Fatal("a single-hop route claimed to be checkable")
	}

	// A hop naming neither module nor version is unidentifiable, not satisfied.
	unidentified := domain.ReachabilityRoute{
		{ModulePath: "example.com/app", Symbol: "main"},
		{Symbol: "someSymbol"},
	}
	if unidentified.IsVersioned() {
		t.Fatal("a route with an unidentifiable hop claimed to be checkable")
	}
}

// A hop renders the parts the analyser supplied and no empty delimiters for the
// parts it could not.
func TestReachabilityFrame_String(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		frame domain.ReachabilityFrame
		want  string
	}{
		{"fully specified",
			domain.ReachabilityFrame{ModulePath: "golang.org/x/text", ModuleVersion: "v0.3.0", Package: "golang.org/x/text/language", Receiver: "Tag", Symbol: "Parse"},
			"golang.org/x/text@v0.3.0 golang.org/x/text/language.(Tag).Parse"},
		{"no version, as a call-graph route has",
			domain.ReachabilityFrame{ModulePath: "example.com/app", Package: "example.com/app", Symbol: "main"},
			"example.com/app main"},
		{"symbol alone",
			domain.ReachabilityFrame{Symbol: "main"},
			"main"},
	} {
		if got := tc.frame.String(); got != tc.want {
			t.Errorf("%s: String() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The derivation reports the unrecorded case as a statement rather than as a
// blank, on the same terms as every other "not recorded" in this domain.
func TestReachabilityDerivation_String(t *testing.T) {
	t.Parallel()
	if got := (domain.ReachabilityDerivation{}).String(); got != "derivation not recorded" {
		t.Fatalf("zero derivation renders as %q", got)
	}
	if (domain.ReachabilityDerivation{}).IsRecorded() {
		t.Fatal("the zero derivation reports itself as recorded")
	}
	full := domain.ReachabilityDerivation{
		Analyser: domain.AnalyserGovulncheck,
		Fidelity: string(domain.ScanModeSource),
		Rooting:  domain.TargetRootedAt(coordinatetest.MustNew("github.com/org/app", "local")),
	}
	got := full.String()
	for _, want := range []string{"govulncheck", "source", "github.com/org/app@local"} {
		if !strings.Contains(got, want) {
			t.Errorf("derivation %q does not state %q", got, want)
		}
	}
}

// StampReachabilityRooting is the one place the frame — decided by the use case
// that writes the record — meets the answers produced by analysers below it.
func TestStampReachabilityRooting(t *testing.T) {
	t.Parallel()
	stated := domain.TargetRootedAt(coordinatetest.MustNew("example.com/other", "local"))
	rec := domain.VulnerabilityRecord{
		Rooting: domain.RootingIsolated,
		Findings: []domain.VulnerabilityFinding{
			{ID: "GO-1", Reachable: &domain.ReachabilityResult{IsReachable: true}},
			{ID: "GO-2", Reachable: nil},
			{ID: "GO-3", Reachable: &domain.ReachabilityResult{
				IsReachable: false,
				DerivedBy:   domain.ReachabilityDerivation{Rooting: stated},
			}},
		},
	}
	domain.StampReachabilityRooting(&rec)

	if got := rec.Findings[0].Reachable.DerivedBy.Rooting; got != domain.RootingIsolated {
		t.Errorf("unstamped answer got frame %q, want the record's", got)
	}
	if rec.Findings[1].Reachable != nil {
		t.Error("a finding with no reachability answer gained one")
	}
	// An analyser that stated its own frame keeps it, on the same terms as the
	// record seal's axis handling.
	if got := rec.Findings[2].Reachable.DerivedBy.Rooting; got != stated {
		t.Errorf("a stated frame was overwritten: got %q, want %q", got, stated)
	}
}

// The new fields are absent from the canonical form when unset, which is what
// makes the change hash-transparent for every record already stored: none of
// them carries a route or a derivation.
func TestReachability_NewFieldsAreAbsentWhenUnset(t *testing.T) {
	t.Parallel()
	rec := domain.VulnerabilityRecord{
		Ecosystem:  fetchdomain.EcosystemGo,
		Coordinate: coordinatetest.MustNew("github.com/foo/bar", "v1.0.0"),
		Findings: []domain.VulnerabilityFinding{{
			ID:        "GO-2026-0001",
			Reachable: &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh},
		}},
		OverallStatus:   domain.StatusAffected,
		PipelineVersion: "v16",
	}
	sealed, err := domain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	blob, err := domain.VulnerabilityRecordHasher{}.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, key := range []string{"routes", "derived_by"} {
		if strings.Contains(string(blob), key) {
			t.Errorf("an unset %q was emitted into the canonical form: %s", key, blob)
		}
	}

	// And a stated derivation IS covered by the seal, so the claim about how an
	// answer was reached is as tamper-evident as the answer.
	withDerivation := rec
	withDerivation.Findings = []domain.VulnerabilityFinding{{
		ID: "GO-2026-0001",
		Reachable: &domain.ReachabilityResult{
			IsReachable: true, Confidence: domain.ConfidenceHigh,
			DerivedBy: domain.ReachabilityDerivation{Analyser: domain.AnalyserGovulncheck},
		},
	}}
	sealedWith, err := domain.VulnerabilityRecordHasher{}.SetContentHash(withDerivation)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if sealedWith.ContentHash == sealed.ContentHash {
		t.Fatal("the derivation is outside the content hash — the claim is not covered by the seal")
	}

	blobWith, err := domain.VulnerabilityRecordHasher{}.Marshal(sealedWith)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var round map[string]json.RawMessage
	if uerr := json.Unmarshal(blobWith, &round); uerr != nil {
		t.Fatalf("unmarshalling sealed record: %v", uerr)
	}
	back, err := domain.VulnerabilityRecordHasher{}.Unmarshal(blobWith)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Findings[0].Reachable.DerivedBy.Analyser != domain.AnalyserGovulncheck {
		t.Fatal("the round trip lost the analyser")
	}
}
