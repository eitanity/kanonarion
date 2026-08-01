package cli

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// parseInvocation pushes one printed command line through the CLI's own
// argument parser: subcommand resolution, flag parsing, positional-arity
// validation, and the kind of positional each command declares. It executes
// nothing, so no store is opened.
//
// The last check is the one that matters here, and arity alone would have
// missed the defect entirely: "kanonarion vuln-scan <module>@<version>
// --reachability" parses, because vuln-scan accepts one positional. What it
// does NOT accept is a coordinate there — the positional is a walk id, as its
// own Use line says — so the invocation failed at run time with "walk record not
// found". A remedy is wrong the moment the command cannot do what the remedy
// asked, whether the parser or the use case is what says so.
func parseInvocation(t *testing.T, line string) error {
	t.Helper()
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != "kanonarion" {
		t.Fatalf("remedy line %q does not start with the binary name", line)
	}
	root := newRootCmd(io.Discard, io.Discard)
	cmd, rest, err := root.Find(fields[1:])
	if err != nil {
		return fmt.Errorf("resolving subcommand for %q: %w", line, err)
	}
	if cmd == root {
		t.Fatalf("remedy line %q names no subcommand", line)
	}
	if err := cmd.ParseFlags(rest); err != nil {
		return fmt.Errorf("parsing flags of %q: %w", line, err)
	}
	positionals := cmd.Flags().Args()
	if err := cmd.ValidateArgs(positionals); err != nil {
		return fmt.Errorf("validating positionals of %q: %w", line, err)
	}
	for _, arg := range positionals {
		if !strings.Contains(arg, "@") {
			continue
		}
		if !declaresModulePositional(cmd.Use) {
			return &remedyGrammarError{use: cmd.Use, arg: arg}
		}
	}
	return nil
}

// declaresModulePositional reports whether a command's Use line declares a
// module coordinate as a positional argument.
func declaresModulePositional(use string) bool {
	return strings.Contains(use, "<module") || strings.Contains(use, "@<version>")
}

// remedyGrammarError names a coordinate passed where the command declares
// something else.
type remedyGrammarError struct{ use, arg string }

func (e *remedyGrammarError) Error() string {
	return "coordinate " + e.arg + " passed positionally to a command whose positional is not a module: " + e.use
}

// A remedy the tool then rejects costs the caller exactly the round trip the
// remedy existed to save. Every line every reachability remedy can print is
// parsed here, so a refusal cannot ship advice the CLI refuses — which is what
// "kanonarion vuln-scan <module>@<version> --reachability" was: vuln-scan takes
// a walk id positionally, so following it failed with "walk record not found".
func TestReachabilityRemedies_EveryLineIsAcceptedByTheParser(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("github.com/golang-jwt/jwt/v4", "v4.5.1")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	remedies := reachabilityRemedies(coord)
	if len(remedies) == 0 {
		t.Fatal("no remedies enumerated")
	}
	for _, r := range remedies {
		if len(r.lines) == 0 {
			t.Errorf("remedy %q prints no invocation", r.lead)
		}
		for _, line := range r.lines {
			if err := parseInvocation(t, line); err != nil {
				t.Errorf("remedy line %q is rejected by the CLI's own parser: %v", line, err)
			}
		}
	}
}

// The rendered form must keep the invocations on their own lines: a caller
// copies a line, and prose sharing the line would be copied with it.
func TestReachabilityRemedy_RendersOneInvocationPerLine(t *testing.T) {
	got := remedyProjectRooted().String()
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Fatalf("remedy rendered as one line: %q", got)
	}
	for _, l := range lines[1:] {
		trimmed := strings.TrimSpace(l)
		if !strings.HasPrefix(trimmed, "kanonarion ") {
			t.Errorf("line %q is not a bare invocation", l)
		}
		if err := parseInvocation(t, trimmed); err != nil {
			t.Errorf("rendered line %q is rejected by the parser: %v", trimmed, err)
		}
	}
}

// -- the cause of a nil reachability answer ---------------------------------

func nilReachabilityRecord(t *testing.T, coord coordinate.ModuleCoordinate, rooting vuldomain.Rooting) vuldomain.VulnerabilityRecord {
	t.Helper()
	return vuldomain.VulnerabilityRecord{
		Coordinate:    coord,
		OverallStatus: vuldomain.StatusAffected,
		Rooting:       rooting,
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:              "GO-2025-3553",
			Summary:         "an advisory",
			AffectedSymbols: []string{"Parser.ParseUnverified"},
		}},
	}
}

// A scan rooted at the module itself DID run with reachability; it produced no
// route because a module that is its own root has no consumer entry point. The
// refusal must say that, not accuse the operator of omitting the flag they
// passed — the message that survived being followed and repeated itself with a
// cause the record it was printed from contradicts.
func TestVulnReachability_SelfRootedScan_NamesTheRootingNotTheFlag(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("github.com/golang-jwt/jwt/v4", "v4.5.1")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	rec := nilReachabilityRecord(t, coord, vuldomain.TargetRootedAt(coord))

	_, verr := vulnReachabilityVerdict(coord, rec, true, "GO-2025-3553", nil, nil)
	if verr == nil {
		t.Fatal("want a refusal, got none")
	}
	msg := verr.Error()
	if strings.Contains(msg, "scanned without --reachability") {
		t.Errorf("refusal asserts a cause the record contradicts:\n%s", msg)
	}
	for _, want := range []string{
		"rooted at github.com/golang-jwt/jwt/v4@v4.5.1",
		"its own root",
		"kanonarion vuln-scan --gomod ./go.mod --reachability",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
}

// The other cause keeps its message: a scan rooted elsewhere that recorded no
// answer and no note was not asked for one.
func TestVulnReachability_ForeignRootedScan_KeepsTheMissingFlagCause(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("github.com/golang-jwt/jwt/v4", "v4.5.1")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	consumer, err := coordinate.NewModuleCoordinate("example.com/app", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	rec := nilReachabilityRecord(t, coord, vuldomain.TargetRootedAt(consumer))

	_, verr := vulnReachabilityVerdict(coord, rec, true, "GO-2025-3553", nil, nil)
	if verr == nil {
		t.Fatal("want a refusal, got none")
	}
	if !strings.Contains(verr.Error(), "scanned without --reachability") {
		t.Errorf("refusal lost the missing-flag cause:\n%s", verr.Error())
	}
}

// An isolated scan names no root at all, so it cannot be read as self-rooted.
func TestVulnReachability_IsolatedScan_KeepsTheMissingFlagCause(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("github.com/golang-jwt/jwt/v4", "v4.5.1")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	rec := nilReachabilityRecord(t, coord, vuldomain.RootingIsolated)

	_, verr := vulnReachabilityVerdict(coord, rec, true, "GO-2025-3553", nil, nil)
	if verr == nil {
		t.Fatal("want a refusal, got none")
	}
	if !strings.Contains(verr.Error(), "scanned without --reachability") {
		t.Errorf("refusal lost the missing-flag cause:\n%s", verr.Error())
	}
}

// A third cause of the same absence, and the one no flag and no rooting can
// change: the advisory names no symbol for this module path, so the reachability
// leg had nothing to search for and skipped the finding. That leaves the same
// nil answer and the same empty note as an unrequested analysis, and it was
// reported as one — sending an operator to re-run a scan for a question that has
// no target.
func TestVulnReachability_AdvisoryNamesNoSymbols_NamesTheAbsentTarget(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("github.com/golang-jwt/jwt", "v3.2.2+incompatible")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	rec := vuldomain.VulnerabilityRecord{
		Coordinate:    coord,
		OverallStatus: vuldomain.StatusAffected,
		Rooting:       vuldomain.RootingIsolated,
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:                     "GO-2025-3553",
			Summary:                "an advisory",
			AdvisoryNamesNoSymbols: true,
		}},
	}

	_, verr := vulnReachabilityVerdict(coord, rec, true, "GO-2025-3553", nil, nil)
	if verr == nil {
		t.Fatal("want a refusal, got none")
	}
	msg := verr.Error()
	if strings.Contains(msg, "scanned without --reachability") {
		t.Errorf("refusal blames a flag for an absent search target:\n%s", msg)
	}
	for _, want := range []string{"names no symbols for this module path", "package level", "kanonarion vuln-show"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
}

// The SBOM does not state whether an advisory is reachable; it names the query
// that does. That command line leaves this codebase inside a published document,
// where a reader who follows it verbatim has no way to ask what went wrong — so
// it is held to the same contract as every remedy line the CLI prints, and
// parsed here by the CLI's own argument parser.
func TestSBOMScopeStatement_NamesACommandTheParserAccepts(t *testing.T) {
	if err := parseInvocation(t, cyclonedx.ReachabilityQueryInvocation); err != nil {
		t.Errorf("the SBOM's reachability query %q is rejected by the CLI's own parser: %v",
			cyclonedx.ReachabilityQueryInvocation, err)
	}
}
