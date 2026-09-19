package cmd_test

import (
	"go/types"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	capdomain "github.com/eitanity/kanonarion/internal/capability/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// A rule over an enum written as "!= the good value" type-checks, reads well,
// and misclassifies every member that is neither the good one nor a failure.
// Three shipped rules had that shape: a walk counted a require redirected to a
// local path as a failed fetch, its store counted the same node the same way
// independently, and a capability report told an operator the call graph would
// not resolve for a module they had themselves excluded from analysis.
//
// Correcting the members that exist today does not close that. What closes it is
// requiring a decision per member: each table below is checked against the
// constants the type actually declares, read out of the source, so a member
// added without a line here fails the build rather than inheriting whichever
// side of the predicate it happens to land on.
//
// Being correct today is not the criterion for being in this file; being able to
// grow is. Four of the predicates covered here were already right — switches
// with documented defaults — and every one of them would have absorbed a new
// member silently. The default that reads best in isolation is the one that
// hurts: a resolution source this build does not recognise is assumed to owe a
// fetched artefact, which is the safe answer for a typo and the wrong answer for
// the next source to be added, whose whole meaning is that nothing was fetched
// and nothing should have been.

// TestNodeStatusFailureClassification fixes which node outcomes the walk counts
// as failures.
func TestNodeStatusFailureClassification(t *testing.T) {
	cases := []struct {
		name      string
		value     walkdomain.NodeStatus
		isFailure bool
	}{
		{"NodeSucceeded", walkdomain.NodeSucceeded, false},
		{"NodeFetchFailed", walkdomain.NodeFetchFailed, true},
		{"NodeInternalPanic", walkdomain.NodeInternalPanic, true},
		// The require was redirected to a local filesystem path, so there is no
		// remote artefact to fetch. The domain says the walk is not partial because
		// of these nodes; counting one told the operator that a subpackage of their
		// own project had failed to fetch.
		{"NodeLocalReplace", walkdomain.NodeLocalReplace, false},
	}
	named := make([]string, 0, len(cases))
	for _, tc := range cases {
		named = append(named, tc.name)
		if got := tc.value.IsFailure(); got != tc.isFailure {
			t.Errorf("%s.IsFailure() = %v, want %v", tc.name, got, tc.isFailure)
		}
	}
	requireEveryMemberClassified(t, "internal/walk/domain", "NodeStatus", named)
}

// TestCallGraphStatusCapabilityClassification fixes what a capability report
// says about each extraction outcome. Three answers, not two: a complete graph,
// a graph the analysis could not finish, and a module the operator chose not to
// analyse at all.
func TestCallGraphStatusCapabilityClassification(t *testing.T) {
	const (
		complete   = "complete"
		unresolved = "did not fully resolve"
		excluded   = "excluded by configuration"
	)
	cases := []struct {
		name  string
		value cgdomain.CallGraphStatus
		want  string
	}{
		{"CallGraphStatusUnknown", cgdomain.CallGraphStatusUnknown, unresolved},
		{"CallGraphStatusExtracted", cgdomain.CallGraphStatusExtracted, complete},
		{"CallGraphStatusPartial", cgdomain.CallGraphStatusPartial, unresolved},
		{"CallGraphStatusLoadFailed", cgdomain.CallGraphStatusLoadFailed, unresolved},
		{"CallGraphStatusOutOfMemory", cgdomain.CallGraphStatusOutOfMemory, unresolved},
		{"CallGraphStatusCancelled", cgdomain.CallGraphStatusCancelled, unresolved},
		{"CallGraphStatusExtractionFailed", cgdomain.CallGraphStatusExtractionFailed, unresolved},
		// A configuration decision, not an analysis outcome. The report still says
		// the set is not a measurement, and says why in the operator's own terms.
		{"CallGraphStatusExcludedByConfig", cgdomain.CallGraphStatusExcludedByConfig, excluded},
	}
	named := make([]string, 0, len(cases))
	for _, tc := range cases {
		named = append(named, tc.name)
		report := capdomain.Analyse(cgdomain.CallGraphRecord{OverallStatus: tc.value}, nil)
		got := complete
		switch {
		case !report.Partial:
		case strings.Contains(report.Caveat, "excluded from call-graph analysis by configuration"):
			got = excluded
		case strings.Contains(report.Caveat, "did not fully resolve"):
			got = unresolved
		default:
			got = "unclassified: " + report.Caveat
		}
		if got != tc.want {
			t.Errorf("Analyse(%s): reads as %q, want %q (caveat %q)", tc.name, got, tc.want, report.Caveat)
		}
		if report.Partial == (report.Caveat == "") {
			t.Errorf("Analyse(%s): Partial=%v with caveat %q; a caveat is owed exactly when the set is not the whole answer",
				tc.name, report.Partial, report.Caveat)
		}
	}
	requireEveryMemberClassified(t, "internal/callgraph/domain", "CallGraphStatus", named)
}

// TestFetchVerificationStatusClassification fixes both rules the fetch stage's
// verification outcome decides: whether the bytes are anchored to trust at all,
// and whether an SBOM may assert where they came from.
//
// The two live in one table because they read one enum, so a member added to it
// has to be decided for both. They are not the same question. IsVerified is the
// read/serve gate. ConfirmsVCSOrigin is true for Verified alone, and that is a
// decision rather than an oversight: every other status leaves the git leg
// unmeasured while the record may still carry a URL inferred from the module
// path, and emitting it would put a guess into a shipped document wearing the
// appearance of a measurement.
func TestFetchVerificationStatusClassification(t *testing.T) {
	cases := []struct {
		name           string
		value          fetchdomain.VerificationStatus
		isVerified     bool
		confirmsOrigin bool
	}{
		{"Verified", fetchdomain.Verified, true, true},
		// Authentic against the transparency log, and no evidence whatsoever
		// about the repository.
		{"VerifiedBySumDBOnly", fetchdomain.VerifiedBySumDBOnly, true, false},
		{"VerifiedByGoSum", fetchdomain.VerifiedByGoSum, true, false},
		{"UnverifiedNoSumDB", fetchdomain.UnverifiedNoSumDB, false, false},
		{"UnverifiedMissingOrigin", fetchdomain.UnverifiedMissingOrigin, false, false},
		{"UnverifiedHashMismatch", fetchdomain.UnverifiedHashMismatch, false, false},
		{"UnverifiedGoModInconsistent", fetchdomain.UnverifiedGoModInconsistent, false, false},
		{"UnverifiedNoVCS", fetchdomain.UnverifiedNoVCS, false, false},
		{"UnverifiedVCSToolMissing", fetchdomain.UnverifiedVCSToolMissing, false, false},
		// Created from a local path: cross-verification does not apply, and there
		// is no upstream repository to name.
		{"LocalSource", fetchdomain.LocalSource, true, false},
	}
	named := make([]string, 0, len(cases))
	for _, tc := range cases {
		named = append(named, tc.name)
		if got := tc.value.IsVerified(); got != tc.isVerified {
			t.Errorf("%s.IsVerified() = %v, want %v", tc.name, got, tc.isVerified)
		}
		if got := tc.value.ConfirmsVCSOrigin(); got != tc.confirmsOrigin {
			t.Errorf("%s.ConfirmsVCSOrigin() = %v, want %v", tc.name, got, tc.confirmsOrigin)
		}
	}
	requireEveryMemberClassified(t, "internal/fetch/domain", "VerificationStatus", named)
}

// TestStdlibVerificationStatusClassification fixes what each standard-library
// custody outcome says about the published-checksum anchor.
//
// This is a DIFFERENT type in a different package from the fetch stage's
// VerificationStatus, and the two are deliberately not interchangeable: the
// stdlib anchor is go.dev/dl's published checksum plus a googlesource
// tag/commit, never a signed transparency-log entry. They are classified
// separately for that reason.
func TestStdlibVerificationStatusClassification(t *testing.T) {
	cases := []struct {
		name  string
		value stdlibdomain.VerificationStatus
		want  bool
	}{
		{"VerifiedGoDevChecksum", stdlibdomain.VerifiedGoDevChecksum, true},
		{"GoDevChecksumMismatch", stdlibdomain.GoDevChecksumMismatch, false},
		{"UnverifiedGoDevUnavailable", stdlibdomain.UnverifiedGoDevUnavailable, false},
		{"UnverifiedGoDevNotPublished", stdlibdomain.UnverifiedGoDevNotPublished, false},
		// Deliberately false. The offline anchor establishes custody from the
		// toolchain on this machine WITHOUT consulting the published checksum, so
		// reading it as a go.dev/dl checksum match would be the stronger claim.
		{"VerifiedLocalToolchain", stdlibdomain.VerifiedLocalToolchain, false},
	}
	named := make([]string, 0, len(cases))
	for _, tc := range cases {
		named = append(named, tc.name)
		if got := tc.value.Verified(); got != tc.want {
			t.Errorf("%s.Verified() = %v, want %v", tc.name, got, tc.want)
		}
	}
	requireEveryMemberClassified(t, "internal/stdlib/domain", "VerificationStatus", named)
}

// TestResolutionSourceArtefactClassification fixes, per resolution source,
// whether a node resolved that way owes the blob store a module zip and — when
// it does not — what kind of thing it is instead.
//
// The noun is asserted for every member, the empty string included. Empty is a
// classification in its own right, meaning "this source owns an artefact", and
// inferring it from a missing table row would be the same silence this file
// exists to break.
//
// Both rules read one enum, so a member joins both tables or neither. That is
// not hypothetical: the source for a node the depth bound left untraversed was
// added after this file, and under the documented default of HasFetchedArtefact
// it would have arrived owing an artefact — which is the answer that had the
// walk reporting a policy decision as a failed fetch in the first place.
func TestResolutionSourceArtefactClassification(t *testing.T) {
	cases := []struct {
		name        string
		value       walkdomain.ResolutionSource
		hasArtefact bool
		absenceNoun string
	}{
		{"ResolutionTarget", walkdomain.ResolutionTarget, true, ""},
		{"ResolutionLocalMainModule", walkdomain.ResolutionLocalMainModule, false, "local main module"},
		{"ResolutionMVS", walkdomain.ResolutionMVS, true, ""},
		{"ResolutionReplace", walkdomain.ResolutionReplace, true, ""},
		{"ResolutionLocalReplace", walkdomain.ResolutionLocalReplace, false, "local replace"},
		// A fetch that failed still named bytes that should be in the store, which
		// is what distinguishes it from a node that never owed any.
		{"ResolutionFetchFailed", walkdomain.ResolutionFetchFailed, true, ""},
		{"ResolutionParseFailed", walkdomain.ResolutionParseFailed, true, ""},
		// Ingested from disk into the blob store, so it does have a zip.
		{"ResolutionLocalAnalysed", walkdomain.ResolutionLocalAnalysed, true, ""},
		{"ResolutionStdlib", walkdomain.ResolutionStdlib, false, "Go standard library"},
		// The depth policy stopped the walk before this requirement. Its bytes are
		// published and another walk may hold them, so the classification is not
		// "no artefact exists" but "this walk was told not to acquire one": the
		// missing fetch record is an absence the run created on purpose, and the
		// predicate exists to separate exactly that from bytes that are owed and
		// missing.
		{"ResolutionDepthBounded", walkdomain.ResolutionDepthBounded, false, "requirement beyond the depth bound"},
	}
	named := make([]string, 0, len(cases))
	for _, tc := range cases {
		named = append(named, tc.name)
		if got := tc.value.HasFetchedArtefact(); got != tc.hasArtefact {
			t.Errorf("%s.HasFetchedArtefact() = %v, want %v", tc.name, got, tc.hasArtefact)
		}
		if got := tc.value.ArtefactAbsenceNoun(); got != tc.absenceNoun {
			t.Errorf("%s.ArtefactAbsenceNoun() = %q, want %q", tc.name, got, tc.absenceNoun)
		}
		// The two are documented as one statement: the noun is what a source with
		// no artefact IS, and "" is what a source that owns one gets. A member
		// added to one switch and not the other lands here.
		if tc.hasArtefact != (tc.absenceNoun == "") {
			t.Errorf("%s is classified as hasArtefact=%v with noun %q; a source owes a noun exactly when it owes no artefact",
				tc.name, tc.hasArtefact, tc.absenceNoun)
		}
	}
	requireEveryMemberClassified(t, "internal/walk/domain", "ResolutionSource", named)
}

// requireEveryMemberClassified compares the names a classification table covers
// with the constants the type declares, read out of the source rather than
// listed a second time by hand. A member added to the enum and not to the table
// fails here; a member removed or renamed fails here too, rather than leaving a
// line that asserts nothing.
func requireEveryMemberClassified(t *testing.T, pkgDir, typeName string, classified []string) {
	t.Helper()
	declared := enumMembers(t, pkgDir, typeName)
	missing := difference(declared, classified)
	stale := difference(classified, declared)
	for _, name := range missing {
		t.Errorf("%s.%s has no classification: the enum grew and the rule over it did not.\n"+
			"Decide which side it is on and add it to the table — a member nobody classified inherits "+
			"whichever side the predicate happens to put it, which is the defect this test exists for.",
			typeName, name)
	}
	for _, name := range stale {
		t.Errorf("%s.%s is classified here but is no longer declared: the table is asserting about a constant "+
			"that does not exist", typeName, name)
	}
}

// enumMembers returns the names of every constant of typeName declared in the
// package rooted at pkgDir, relative to the repository.
func enumMembers(t *testing.T, pkgDir, typeName string) []string {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedDeps | packages.NeedImports,
		Dir:  "..",
	}
	pkgs, err := packages.Load(cfg, "./"+pkgDir)
	if err != nil {
		t.Fatalf("loading %s: %v", pkgDir, err)
	}
	want := modulePath + "/" + pkgDir
	for _, p := range pkgs {
		if p.PkgPath != want || p.Types == nil {
			continue
		}
		var out []string
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			konst, ok := scope.Lookup(name).(*types.Const)
			if !ok {
				continue
			}
			named, ok := konst.Type().(*types.Named)
			if !ok || named.Obj() == nil || named.Obj().Name() != typeName {
				continue
			}
			out = append(out, name)
		}
		if len(out) == 0 {
			t.Fatalf("%s declares no constants of type %s; the guard is reading the wrong type", pkgDir, typeName)
		}
		sort.Strings(out)
		return out
	}
	t.Fatalf("package %s was not loaded", want)
	return nil
}

func difference(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, s := range b {
		in[s] = true
	}
	var out []string
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
