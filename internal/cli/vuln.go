package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/spf13/cobra"
)

// advisoryCountLine renders how many advisories a verdict was measured against.
//
// It is the line that makes a clean verdict readable: govulncheck reports "No
// vulnerabilities found." against a database holding six thousand advisories and
// against one holding none, so the count is what tells the two apart after the
// fact. A scan against an empty database is refused outright, so no record can
// carry a measured zero.
//
// A zero is therefore reported as unrecorded rather than as a count. It means
// the record predates the measurement, which is unproven — not a state that
// ranks beside a measured one, and never a claim that nothing was consulted.
func advisoryCountLine(snapshot vuldomain.DatabaseSnapshot) string {
	if n := snapshot.AdvisoryCount(); n > 0 {
		return fmt.Sprintf("%d in the snapshot scanned against", n)
	}
	return "not recorded (this record predates the advisory count)"
}

func newVulnCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use: "vuln <module>@<version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Show the vulnerability record for a module",
		Example: `  kanonarion vuln github.com/gin-gonic/gin@v1.6.2
  kanonarion vuln github.com/gin-gonic/gin@v1.6.2 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runVuln(cmd.Context(), args[0], jsonOut, ctr.QueryVuln, ctr.QueryScanRuns, ctr.QueryWalks, ctr.QueryCallGraph, stdout)
		},
	}

	return cmd
}

func runVuln(ctx context.Context, arg string, jsonOut bool, uc QueryVulnUseCase, runs QueryScanRunsUseCase, walks QueryWalksUseCase, graphs QueryCallGraphUseCase, stdout io.Writer) error {
	// runs is unused on this path — it only explains a walk-scoped miss, and
	// this command names no walk — but it is threaded rather than nil so the
	// two entry points cannot drift into different behaviour. walks is used:
	// the no-record refusal names a succeeded walk if one exists.
	return runVulnShow(ctx, arg, "", "", false, jsonOut, false, uc, runs, walks, graphs, stdout)
}

// printVulnRecord renders a single VulnerabilityRecord in human-readable form;
// shared between `vuln`, `vuln-show`, and any future text presenter.
func printVulnRecord(stdout io.Writer, rec vuldomain.VulnerabilityRecord, classify routeRootFunc) {
	if classify == nil {
		classify = unclassifiedRoutes
	}
	coverage, _ := vuldomain.RecordAxes(rec)
	label := string(rec.OverallStatus)
	// Whether the summary word needs a coverage caveat beside it is a coverage
	// question. Gating on the word instead left the cause off exactly the records
	// that most need it: a metadata-only record that matched an advisory reads
	// Affected, so its "version-not-in-toolchain" went unprinted.
	if coverage == vuldomain.CoverageUnscannable && rec.UnscanReason != "" {
		label = fmt.Sprintf("%s (%s)", rec.OverallStatus, rec.UnscanReason)
	}
	_, _ = fmt.Fprintf(stdout, "%s@%s — %s\n", rec.Coordinate.Path(), rec.Coordinate.Version(), label)
	// Reachability under a pre-modules coordinate is measured over a call graph
	// built from a module whose own requirements the toolchain never resolved, so
	// a not-reached verdict here is bounded by more than the graph's own
	// completeness axis says.
	if line := preModulesCaveat(rec.Coordinate); line != "" {
		_, _ = fmt.Fprintf(stdout, "  %s\n", line)
	}
	_, _ = fmt.Fprintf(stdout, "  Walk:            %s\n", rec.WalkID)
	// The analysis frame is printed on every record, including "not recorded".
	// A reachability finding means something different in each: isolated answers
	// "is this advisory reachable in the module examined alone", target-rooted
	// answers "is it reachable in the build we ship". Leaving it off would let a
	// reader take one for the other, which is exactly what happened while the two
	// shared a row.
	_, _ = fmt.Fprintf(stdout, "  Analysis frame:  %s\n", vuldomain.RecordRooting(rec))
	// The toolchain is printed on every record, "not recorded" included. Which
	// files build constraints selected and which symbols the analysis could reach
	// are the toolchain's, so a verdict read without it is a verdict about a build
	// the reader cannot identify.
	_, _ = fmt.Fprintf(stdout, "  Toolchain:       %s\n", rec.Toolchain.String())
	// First and last validated are stated as distinct facts: when the verdict was
	// first established versus the run that last re-confirmed it. The reader, not
	// kanonarion, judges whether that is acceptably fresh.
	if !rec.FirstScannedAt.IsZero() {
		_, _ = fmt.Fprintf(stdout, "  First validated: %s\n", rec.FirstScannedAt.UTC().Format(time.RFC3339))
	}
	_, _ = fmt.Fprintf(stdout, "  Last validated:  %s\n", rec.ScannedAt.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(stdout, "  Snapshot:        %s@%s\n", rec.DatabaseSnapshot.Source(), rec.DatabaseSnapshot.Version())
	_, _ = fmt.Fprintf(stdout, "  Advisories:      %s\n", advisoryCountLine(rec.DatabaseSnapshot))
	if !rec.DatabaseSnapshot.RetrievedAt().IsZero() {
		_, _ = fmt.Fprintf(stdout, "  Snapshot age:    retrieved %s (%d day(s) old at validation)\n",
			rec.DatabaseSnapshot.RetrievedAt().UTC().Format(time.RFC3339),
			vuldomain.SnapshotAgeDays(rec.ScannedAt, rec.DatabaseSnapshot.RetrievedAt()))
	}
	// The coverage caveat is printed from the coverage axis, and printing it does
	// not end the record: a coverage gap and an advisory match are independent
	// facts, and a record carrying both owes both lines. Returning after the reason
	// — which routing on the collapsed word did — would have dropped the findings
	// of every metadata-only record the moment this switch started catching them.
	switch coverage {
	case vuldomain.CoverageFailedScan:
		reason := rec.ErrorDetail
		if reason == "" {
			reason = "unknown reason"
		}
		_, _ = fmt.Fprintf(stdout, "  Reason:   %s\n", reason)
	case vuldomain.CoverageUnscannable:
		reason := rec.UnscannableReason
		if reason == "" {
			reason = "unknown reason"
		}
		_, _ = fmt.Fprintf(stdout, "  Reason:   %s\n", reason)
	case vuldomain.CoverageAnalysed:
		// Analysed: no caveat owed, the findings below are the whole answer.
	}
	if len(rec.Findings) == 0 {
		// "No findings" is a claim only an analysed module can make. On a coverage
		// gap the reason line above is the answer, and printing "No findings" beside
		// it would read as an all-clear for a module nothing was ever looked at in.
		if coverage == vuldomain.CoverageAnalysed {
			_, _ = fmt.Fprintln(stdout, "  No findings.")
		}
		return
	}
	printFindingLines(stdout, rec, classify)
}

// reachabilityLabel renders the reachability tag beside a finding, from the one
// shared reading every surface uses.
//
// It has more outcomes than two, and the branch that matters is the one it used
// to reach last. A finding whose answer was never determined at symbol level —
// because the advisory names no symbol for this module path — is not a negative
// and not a positive: labelling it "not reachable" reports a search that was
// never run, and labelling it "[reachable]" reports code as running that nothing
// showed running. This function tested the stored bit BEFORE the advisory, so a
// finding carrying both read "[reachable]" here while the reachability command,
// over the same record, reported it at package level. The state settles the
// order once, for every surface.
//
// notReachable lets each caller keep its own wording for the genuine negative,
// which differs in how much of the instrument it names.
func reachabilityLabel(f vuldomain.VulnerabilityFinding, notReachable string) string {
	switch state := vuldomain.FindingReachabilityState(f); state {
	case vuldomain.StateNotAnalysed:
		// Nobody asked. No tag: there is no answer here to qualify, and the state
		// line under the finding says so in full.
		return ""
	case vuldomain.StateNotComputed:
		// A reachability question that was asked and could not be answered is not
		// the same as one nobody asked, and the blank label rendered them alike. The
		// note printed under the finding carries the reason; this is what stops the
		// entry reading as a finding reachability was simply not run for.
		return " [reachability requested but not computed]"
	case vuldomain.StateReachable:
		return " [reachable]"
	case vuldomain.StatePackageLevelOnly:
		return " [affected at package level; symbol-level reachability not determined]"
	case vuldomain.StateNotDetermined:
		return " [reachability not determined]"
	case vuldomain.StateWithdrawn:
		// The retraction has its own line under the finding and it is the whole
		// answer; a reachability tag beside it would offer reachability as the
		// mitigation for an advisory that no longer stands.
		return ""
	default:
		// The genuine negative: the entry an operator acts on by NOT upgrading, so
		// the label says how thorough the search behind it was. A bare "[not
		// reachable]" reads the same whether a call graph was searched or an
		// analyser simply never mentioned the module, and on a working store every
		// one of them was the second.
		if soundness, _ := vuldomain.NegativeSoundness(f); soundness != vuldomain.SoundnessNotStated {
			return strings.TrimSuffix(notReachable, "]") + " — " + soundness.String() + "]"
		}
		return notReachable
	}
}

// fixReferenceURLs returns the URLs of a finding's FIX references, in the
// record's own canonical order.
//
// The type comparison is case-insensitive because the type is upstream's string
// and a record states it as it was published rather than normalising it.
func fixReferenceURLs(f vuldomain.VulnerabilityFinding) []string {
	var out []string
	for _, ref := range f.References {
		if strings.EqualFold(ref.Type, "FIX") {
			out = append(out, ref.URL)
		}
	}
	return out
}

func printFindingLines(stdout io.Writer, rec vuldomain.VulnerabilityRecord, classify routeRootFunc) {
	if classify == nil {
		classify = unclassifiedRoutes
	}
	for _, f := range rec.Findings {
		aliases := ""
		if len(f.Aliases) > 0 {
			aliases = " (" + strings.Join(f.Aliases, ", ") + ")"
		}
		// The first route's root is classified before the heading is printed,
		// because its kind belongs on the same line as the reachability tag: a
		// test-scope root beside "[reachable]" is the one pairing that changes what
		// the whole entry means, and a line further down is a line that is skipped.
		root := firstRouteRootOf(f, classify)
		_, _ = fmt.Fprintf(stdout, "  %s%s%s%s: %s\n",
			f.ID, aliases, reachabilityLabel(f, " [not reachable]"), routeRootTag(root), f.Summary)
		// The retraction is printed as its own line, ahead of the range and the fix,
		// because it changes what the rest of the entry means: an affected range and
		// a fixed version for a retracted advisory describe a report that was
		// withdrawn, and acting on the fix line would be acting on nothing. Upstream
		// signals this only by prefixing the summary with "WITHDRAWN: ", which is
		// prose a reader may or may not notice and no consumer could route on.
		if f.IsWithdrawn() {
			_, _ = fmt.Fprintf(stdout, "      WITHDRAWN: advisory retracted upstream %s — not a finding against this module\n",
				f.WithdrawnAt.UTC().Format(time.RFC3339))
		}
		if f.AffectedRange != "" {
			_, _ = fmt.Fprintf(stdout, "      affected: %s\n", f.AffectedRange)
		}
		// FixDisplay renders "no fix available" explicitly rather than leaving the
		// remediation question blank — a finding exists to answer "will a bump fix
		// it?", and absence of a fix is an answer, not missing data.
		_, _ = fmt.Fprintf(stdout, "      fix:      %s\n", f.FixDisplay())
		if len(f.AffectedSymbols) > 0 {
			_, _ = fmt.Fprintf(stdout, "      symbols:  %s\n", strings.Join(f.AffectedSymbols, ", "))
		}
		// Only the FIX references are printed, and they are printed under the fix
		// line they belong to. An advisory publishes up to a dozen links and most
		// of them are places the vulnerability is discussed; the FIX ones are the
		// commit or CL that remediates it, which is the only kind a reader acts on
		// here. The record carries every reference with its type, and --json emits
		// them all, so nothing is lost by the text view choosing.
		if fixes := fixReferenceURLs(f); len(fixes) > 0 {
			_, _ = fmt.Fprintf(stdout, "      fix refs: %s\n", strings.Join(fixes, ", "))
		}
		// Printed where the symbols would have been, because the empty symbol list
		// is the thing being explained: a reader must not take it for a symbol list
		// that failed to load, nor read the absent route as "nothing calls it".
		if f.AdvisoryNamesNoSymbols {
			_, _ = fmt.Fprintln(stdout, "      symbols:  none named by the advisory for this module path — affected at package level, symbol-level reachability not determinable")
		}
		// The state is printed on every finding and never omitted at a "normal"
		// value, in the same word the JSON surfaces publish. A reader must be able
		// to tell not_reachable from package_level_only from a build that does not
		// derive the state at all, and only a line that is always present carries
		// the third distinction. The tag on the heading above is prose for a
		// person; this is the word every surface agrees on.
		state := vuldomain.FindingReachabilityState(f)
		_, _ = fmt.Fprintf(stdout, "      reachability: %s — %s\n", state, state.Statement())
		// A reachability answer never prints without saying what produced it. The
		// same advisory in the same module is reachable in one build and not in
		// the next, so an unlabelled answer reads as a property of the module and
		// is a property of one analysis of one build.
		if f.Reachable != nil {
			_, _ = fmt.Fprintf(stdout, "      derived:  %s\n", f.Reachable.DerivedBy)
		}
		// The route is what answers "which of my dependencies reaches this". It is
		// printed entry point first, and says so when its hops carry no versions,
		// because an unversioned route cannot be checked against another build.
		if f.Reachable != nil && len(f.Reachable.Routes) > 0 {
			route := f.Reachable.Routes[0]
			caveat := ""
			if !route.IsVersioned() {
				caveat = " (hops carry no module version)"
			}
			_, _ = fmt.Fprintf(stdout, "      route:    entry point first%s\n", caveat)
			for _, hop := range route {
				_, _ = fmt.Fprintf(stdout, "        %s\n", hop)
			}
			// The evidence behind the tag on the heading, printed where the route it
			// describes is. Naming the root kind is a fact about what starts the
			// route; it is not a claim that anything is exploitable, and the reason
			// is what keeps the reader on the first reading.
			if root.IsRecorded() {
				_, _ = fmt.Fprintf(stdout, "      root:     %s\n", root)
				if root.NodeID != "" {
					_, _ = fmt.Fprintf(stdout, "        node:   %s\n", root.NodeID)
				}
				if root.Remedy != "" {
					_, _ = fmt.Fprintf(stdout, "        next:   %s\n", root.Remedy)
				}
			}
			if extra := len(f.Reachable.Routes) - 1; extra > 0 {
				_, _ = fmt.Fprintf(stdout, "        (%d further route(s) recorded)\n", extra)
			}
		}
		if f.ReachabilityNote != "" {
			_, _ = fmt.Fprintf(stdout, "      reachability: %s\n", f.ReachabilityNote)
		}
	}
}
