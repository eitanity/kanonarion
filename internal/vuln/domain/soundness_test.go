package domain_test

import (
	"encoding/json"
	"testing"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// negative builds a not-reachable finding derived by the named analyser at the
// named fidelity. It is the shape every stored negative has: no route, and a
// derivation that says who looked and how well they could see.
func negative(analyser domain.ReachabilityAnalyser, fidelity string) domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{
		ID:              "GO-0000-0000",
		AffectedSymbols: []string{"pkg.Vulnerable"},
		Reachable: &domain.ReachabilityResult{
			IsReachable: false,
			Confidence:  domain.ConfidenceHigh,
			DerivedBy: domain.ReachabilityDerivation{
				Analyser: analyser,
				Fidelity: fidelity,
			},
		},
	}
}

// TestNegativeSoundness_TheThreeModesAreDistinguishable is the ticket's central
// observable: a govulncheck source-mode negative, a govulncheck binary-mode
// negative and a built-graph search all report IsReachable false at
// ConfidenceHigh, and until now nothing separated them.
func TestNegativeSoundness_TheThreeModesAreDistinguishable(t *testing.T) {
	source := negative(domain.AnalyserGovulncheck, string(domain.ScanModeSource))
	binary := negative(domain.AnalyserGovulncheck, string(domain.ScanModeBinary))
	searched := negative(domain.AnalyserCallGraphBFS, string(callgraphdomain.CompletenessBuiltWithBodies))

	for _, f := range []domain.VulnerabilityFinding{source, binary, searched} {
		if f.Reachable.IsReachable || f.Reachable.Confidence != domain.ConfidenceHigh {
			t.Fatalf("fixture is not the shape under test: %+v", f.Reachable)
		}
	}

	got := map[string]domain.ReachabilitySoundness{}
	for name, f := range map[string]domain.VulnerabilityFinding{
		"source": source, "binary": binary, "searched": searched,
	} {
		s, reason := domain.NegativeSoundness(f)
		if reason == "" {
			t.Errorf("%s: soundness %s carries no reason; a bare rung is a label", name, s)
		}
		got[name] = s
	}

	if got["searched"] != domain.SoundnessConfirmed {
		t.Errorf("a search over a graph built with bodies = %s, want %s", got["searched"], domain.SoundnessConfirmed)
	}
	if got["source"] != domain.SoundnessInferred {
		t.Errorf("govulncheck source-mode negative = %s, want %s", got["source"], domain.SoundnessInferred)
	}
	if got["binary"] != domain.SoundnessUnconfirmed {
		t.Errorf("govulncheck binary-mode negative = %s, want %s", got["binary"], domain.SoundnessUnconfirmed)
	}
	if got["source"] == got["binary"] || got["source"] == got["searched"] || got["binary"] == got["searched"] {
		t.Errorf("the three modes are not distinguishable: %+v", got)
	}
	if !got["searched"].IsConfirmed() {
		t.Error("the only rung a confident negative may rest on does not report itself confirmed")
	}
	if got["source"].IsConfirmed() || got["binary"].IsConfirmed() {
		t.Error("a govulncheck negative reports itself confirmed; govulncheck never runs a search that could confirm one")
	}
	if got["source"].Rank() <= got["binary"].Rank() {
		t.Errorf("a source-mode silence (%d) does not outrank a symbol table (%d)", got["source"].Rank(), got["binary"].Rank())
	}
}

// TestNegativeSoundness_CoversEveryCallGraphLevel pins this mapping to the
// call-graph domain's published ladder. A level added there must be classified
// here deliberately rather than falling through to a default, and only
// BUILT_WITH_BODIES may confirm a negative — the rule completeness.go already
// states and nothing applied.
func TestNegativeSoundness_CoversEveryCallGraphLevel(t *testing.T) {
	for _, level := range callgraphdomain.CompletenessLevels() {
		s, reason := domain.NegativeSoundness(negative(domain.AnalyserCallGraphBFS, string(level)))
		if reason == "" {
			t.Errorf("%s: no reason given", level)
		}
		want := domain.SoundnessUnconfirmed
		if level == callgraphdomain.CompletenessBuiltWithBodies {
			want = domain.SoundnessConfirmed
		}
		if s != want {
			t.Errorf("call graph %s -> %s, want %s", level, s, want)
		}
	}
}

// TestNegativeSoundness_UnsearchableOutranksEveryOtherCause asserts the
// precedence: an advisory that names no symbols has no searchable target, and
// that is true whatever the analyser did. The read side already orders it first
// for the same reason.
func TestNegativeSoundness_UnsearchableOutranksEveryOtherCause(t *testing.T) {
	for _, analyser := range []domain.ReachabilityAnalyser{
		domain.AnalyserGovulncheck, domain.AnalyserCallGraphBFS, domain.AnalyserUnrecorded,
	} {
		f := negative(analyser, string(callgraphdomain.CompletenessBuiltWithBodies))
		f.AffectedSymbols = nil
		f.AdvisoryNamesNoSymbols = true
		if s, _ := domain.NegativeSoundness(f); s != domain.SoundnessUnsearchable {
			t.Errorf("analyser %s with no named symbols -> %s, want %s", analyser, s, domain.SoundnessUnsearchable)
		}
	}
}

// TestNegativeSoundness_StatesNothingForAPositive keeps positives untouched. A
// route is its own evidence, and stamping a soundness rung on it would invite
// the reading that a route needs one.
func TestNegativeSoundness_StatesNothingForAPositive(t *testing.T) {
	f := negative(domain.AnalyserGovulncheck, string(domain.ScanModeSource))
	f.Reachable.IsReachable = true
	f.Reachable.Routes = []domain.ReachabilityRoute{{{ModulePath: "example.com/app"}, {ModulePath: "example.com/dep", ModuleVersion: "v1.0.0"}}}
	if s, reason := domain.NegativeSoundness(f); s != domain.SoundnessNotStated || reason != "" {
		t.Errorf("positive -> (%s, %q), want the zero rung and no reason", s, reason)
	}

	var noAnswer domain.VulnerabilityFinding
	if s, _ := domain.NegativeSoundness(noAnswer); s != domain.SoundnessNotStated {
		t.Errorf("finding with no reachability answer -> %s, want %s", s, domain.SoundnessNotStated)
	}
}

// TestNegativeSoundness_AnUnnamedAnalyserIsNeverConfirmed covers the records
// written before the derivation was recorded at all. They ladder onto a stated
// rung rather than a bucket of their own, and it is not the confirmed one.
func TestNegativeSoundness_AnUnnamedAnalyserIsNeverConfirmed(t *testing.T) {
	for _, fidelity := range []string{"", "source", string(callgraphdomain.CompletenessBuiltWithBodies)} {
		s, reason := domain.NegativeSoundness(negative(domain.AnalyserUnrecorded, fidelity))
		if s != domain.SoundnessUnconfirmed {
			t.Errorf("unrecorded analyser at fidelity %q -> %s, want %s", fidelity, s, domain.SoundnessUnconfirmed)
		}
		if reason == "" {
			t.Errorf("unrecorded analyser at fidelity %q: no reason given", fidelity)
		}
	}
	// A govulncheck answer that does not say which mode it ran in cannot be told
	// from a binary-mode one, so it is not credited as if it were source mode.
	if s, _ := domain.NegativeSoundness(negative(domain.AnalyserGovulncheck, "")); s != domain.SoundnessUnconfirmed {
		t.Errorf("govulncheck with no stated mode -> %s, want %s", s, domain.SoundnessUnconfirmed)
	}
}

// TestReachabilitySoundnessLevels_IsExhaustiveAndOrdered pins the published
// ladder against Rank, so a rung added to one and not the other is caught.
func TestReachabilitySoundnessLevels_IsExhaustiveAndOrdered(t *testing.T) {
	levels := domain.ReachabilitySoundnessLevels()
	seen := map[domain.ReachabilitySoundness]bool{}
	for i, l := range levels {
		if seen[l] {
			t.Errorf("%s listed twice", l)
		}
		seen[l] = true
		if i > 0 && levels[i-1].Rank() <= l.Rank() {
			t.Errorf("ladder is not strictly descending at %s (%d) after %s (%d)",
				l, l.Rank(), levels[i-1], levels[i-1].Rank())
		}
	}
	for _, want := range []domain.ReachabilitySoundness{
		domain.SoundnessConfirmed, domain.SoundnessInferred,
		domain.SoundnessUnconfirmed, domain.SoundnessUnsearchable,
		domain.SoundnessDisputed, domain.SoundnessNotStated,
	} {
		if !seen[want] {
			t.Errorf("%s is missing from ReachabilitySoundnessLevels", want)
		}
	}
	if domain.SoundnessNotStated.String() != "not stated" {
		t.Errorf("zero value renders as %q", domain.SoundnessNotStated.String())
	}
	for _, l := range levels {
		if l == domain.SoundnessNotStated {
			continue
		}
		if l.String() != string(l) {
			t.Errorf("%s renders as %q", string(l), l.String())
		}
	}
	// A rung this build does not know — a record written by a later generation,
	// read by this one — ranks below every stated one rather than above them. A
	// default that returned the top rung would let an unrecognised word read as a
	// confirmed negative.
	future := domain.ReachabilitySoundness("a-rung-from-a-later-generation")
	if future.Rank() != domain.SoundnessNotStated.Rank() {
		t.Errorf("unknown rung ranks %d, want the floor %d", future.Rank(), domain.SoundnessNotStated.Rank())
	}
	if future.IsConfirmed() {
		t.Error("an unrecognised rung reports itself confirmed")
	}
}

// TestSoundnessMarshalsTheNamedZero pins the wire form of the zero rung.
//
// SoundnessNotStated is the empty string, so a surface emitting the raw value
// left a positive verdict — which HAS no rung, and says so — serialising
// identically to a reply that never derived one. Naming the zero value on the
// wire is what separates "there is no absence here to qualify" from "this
// producer does not state a rung at all", which is the whole distinction the
// ladder exists to make visible.
func TestSoundnessMarshalsTheNamedZero(t *testing.T) {
	for _, tc := range []struct {
		rung domain.ReachabilitySoundness
		want string
	}{
		{domain.SoundnessNotStated, `"not stated"`},
		{domain.SoundnessConfirmed, `"confirmed"`},
		{domain.SoundnessInferred, `"inferred"`},
		{domain.SoundnessUnconfirmed, `"unconfirmed"`},
		{domain.SoundnessUnsearchable, `"unsearchable"`},
		{domain.SoundnessDisputed, `"disputed"`},
	} {
		raw, err := json.Marshal(tc.rung)
		if err != nil {
			t.Fatalf("marshalling %q: %v", tc.rung, err)
		}
		if string(raw) != tc.want {
			t.Errorf("marshalling %q gave %s, want %s", tc.rung, raw, tc.want)
		}
	}
}

// TestEveryLadderRungMarshals guards the pin above against the ladder growing a
// rung nothing renders. The levels list is the one place the ladder is stated;
// a rung added there must marshal as the word it is named by, not as an empty
// field a consumer reads as "no rung".
func TestEveryLadderRungMarshals(t *testing.T) {
	for _, rung := range domain.ReachabilitySoundnessLevels() {
		raw, err := json.Marshal(rung)
		if err != nil {
			t.Fatalf("marshalling %q: %v", rung, err)
		}
		if string(raw) == `""` {
			t.Errorf("rung %q marshals to an empty string", rung)
		}
	}
}

// TestReachabilitySoundnessStatement_EveryRungArrivesWithItsOwnWords is the
// guard that keeps a tallying surface derived.
//
// A renderer walks ReachabilitySoundnessLevels and prints each rung with its own
// statement, so a rung added to the ladder appears in that rendering with no
// edit to the renderer. What it cannot do is invent words: a rung added here and
// left out of Statement would be rendered under a bare name, which is a tally
// with nothing behind it, and a rung that borrowed a neighbour's sentence would
// be worse. This fails on both.
func TestReachabilitySoundnessStatement_EveryRungArrivesWithItsOwnWords(t *testing.T) {
	seen := map[string]domain.ReachabilitySoundness{}
	for _, rung := range domain.ReachabilitySoundnessLevels() {
		statement := rung.Statement()
		if statement == "" {
			t.Errorf("rung %q states nothing: a surface tallying it would print a name with no meaning behind it", rung.String())
			continue
		}
		if other, dup := seen[statement]; dup {
			t.Errorf("rungs %q and %q share a statement, so a reader cannot tell the two tallies apart",
				other.String(), rung.String())
		}
		seen[statement] = rung
	}

	// A value this type does not define states nothing rather than borrowing the
	// nearest rung's words.
	if got := domain.ReachabilitySoundness("invented").Statement(); got != "" {
		t.Errorf("an undefined rung stated %q, want \"\"", got)
	}
}
