package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
)

type latestFlags struct {
	gomodPath string
	goproxy   string
	tool      bool
	project   bool
	fresh     bool
}

func newLatestCmd(stdout, stderr io.Writer) *cobra.Command {
	var f latestFlags

	cmd := &cobra.Command{
		Use:   "latest [<module>...]",
		Short: "Resolve the latest published version of one or more modules",
		Long: `latest queries the Go module proxy for the latest published version of one or
more modules.

With --gomod, it reports the pinned version from go.mod against the latest
available for every direct dependency, letting you see staleness at a glance.

Two separate facts are reported for each module. The latest version at the
module path itself, and — because a Go module's next MAJOR version lives at a
different path — the newest major path above the pinned one that resolves. A
module pinned several majors behind is current at its own path and still behind;
both are stated, never merged.

Successful lookups are recorded in the store and served back while they are
younger than staleness.ttl (default 1h). Every answer states the lookup time it
used; pass --fresh to bypass the ledger and re-query the proxy.

Without --gomod, one or more module paths may be passed as positional
arguments; with multiple modules, --json emits an array.`,
		Example: `  kanonarion latest github.com/spf13/cobra
  kanonarion latest github.com/spf13/cobra github.com/stretchr/testify
  kanonarion latest github.com/spf13/cobra --json
  kanonarion latest --gomod ./go.mod
  kanonarion latest --gomod ./go.mod --json
  kanonarion latest --gomod ./go.mod --tool
  kanonarion latest --gomod ./go.mod --fresh`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.gomodPath != "" && len(args) > 0 {
				return fmt.Errorf("cannot specify both a module path and --gomod")
			}
			if (f.tool || f.project) && len(args) > 0 {
				return fmt.Errorf("--tool and --project apply to a go.mod scan, not a positional module path")
			}
			return runLatest(cmd.Context(), args, f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.gomodPath, "gomod", "", "path to go.mod; report latest vs pinned for the project's code dependencies (default: ./go.mod)")
	cmd.Flags().StringVar(&f.goproxy, "goproxy", "", "override GOPROXY (default: $GOPROXY or proxy.golang.org)")
	cmd.Flags().BoolVar(&f.tool, "tool", false, "scope to the tooling supply chain (the go.mod tool directives' closure)")
	cmd.Flags().BoolVar(&f.project, "project", false, "scope to the complete set: the project's code AND tooling")
	cmd.Flags().BoolVar(&f.fresh, "fresh", false, "re-query the proxy instead of serving recorded lookups from the store")

	return cmd
}

// latestResult is the per-module output record.
type latestResult struct {
	Module string `json:"module"`
	Pinned string `json:"pinned,omitempty"`
	Latest string `json:"latest"`
	// omitzero, not omitempty: omitempty has no effect on a struct, so a module
	// whose publication date the proxy did not supply emitted
	// "0001-01-01T00:00:00Z" — a fabricated date offered where the honest answer is
	// no date at all. omitzero is the form that actually omits it (and is the form
	// WalkSummary.CompletedAt already uses for the same reason).
	LatestDate time.Time `json:"latest_date,omitzero"`
	// LatestReleaseAgeDays is how long ago the LATEST release shipped — the age
	// of Latest, measured from LatestDate to now. It is not how far behind the
	// pin is, and it was emitted as `days_behind` until that name was corrected:
	// under the old key a project pinned eighteen months back on an actively
	// released module read as "2", while a current pin on a quiet module read as
	// "1272", inverting the order a reader sorting by it expects.
	//
	// How far behind the pin actually is would need the PINNED version's
	// publication date. Nothing kanonarion records carries it: the staleness
	// ledger holds one row per module path with the LATEST version's publication
	// time, and the fetch ledger holds when kanonarion fetched an artefact, which
	// is a fact about this machine and not about the release. Obtaining it would
	// mean one extra proxy request per module — a second network sweep, on the
	// command whose sweep cost the ledger exists to remove — and would still be
	// unavailable to an offline run. So the field is not emitted at all rather
	// than approximated under a name that promises precision.
	//
	// Absent (omitempty) when the proxy supplied no publication date for the
	// latest version, which is the same condition that leaves LatestDate absent.
	// It is populated whether or not the pin is current: the age of a release is
	// a fact about the release, and suppressing it for an up-to-date pin would
	// make the field mean something different on different rows.
	LatestReleaseAgeDays int `json:"latest_release_age_days,omitempty"`
	// IsLatest answers "is the pin the newest version of this module path".
	//
	// It is a POINTER because the question is not always answered. A lookup that
	// failed measured nothing, and a module named with no pin was never asked the
	// question at all; both used to emit a bool, and the zero value of a bool on
	// a failed lookup is the claim "your pin is behind" about a row nothing was
	// established for. Unanswered is null, with StalenessUnmeasured naming why.
	IsLatest *bool `json:"is_latest"`
	// StalenessUnmeasured is the machine-readable reason IsLatest is null, from
	// the vocabulary shared with `audit` and `fetch` (see staleness.go). Absent on
	// a measured row.
	StalenessUnmeasured string `json:"staleness_unmeasured,omitempty"`

	// NewerMajor is the newest major-suffixed path above the pinned major, when
	// one resolves. It is a SEPARATE field from Latest and is never folded into
	// IsLatest: a module can be at the latest version of its own path and still
	// be a whole major line behind, and reporting only the first is the failure
	// this field exists to correct. Absent when nothing newer was found — or, if
	// MajorProbed is false, when nothing was asked.
	NewerMajorModule string    `json:"newer_major_module,omitempty"`
	NewerMajorLatest string    `json:"newer_major_latest,omitempty"`
	NewerMajorDate   time.Time `json:"newer_major_date,omitzero"`
	// MajorProbed distinguishes "probed, no newer major" from "not probed".
	MajorProbed bool `json:"major_probed"`

	// LookedUpAt is when the proxy was asked for this answer. A served answer
	// carries the original lookup time, not the time of this run.
	LookedUpAt time.Time `json:"looked_up_at,omitzero"`
	// Served is true when the answer came from the store rather than the proxy.
	Served bool `json:"served_from_store"`
}

// applyStaleness copies a resolved staleness record onto an output row.
func (r *latestResult) applyStaleness(ans staleapp.Answer) {
	r.Latest = ans.LatestVersion
	r.LatestDate = ans.LatestPublishedAt
	r.LatestReleaseAgeDays = latestReleaseAgeDays(ans.LatestPublishedAt)
	r.NewerMajorModule = ans.NewerMajor.Path
	r.NewerMajorLatest = ans.NewerMajor.Version
	r.NewerMajorDate = ans.NewerMajor.PublishedAt
	r.MajorProbed = ans.NewerMajor.Probed
	r.LookedUpAt = ans.LookedUpAt
	r.Served = ans.Served
}

// newerMajor rebuilds the domain fact from an output row, so the renderers
// share one definition of what "has a newer major" means.
func (r latestResult) newerMajor() staledomain.NewerMajor {
	return staledomain.NewerMajor{
		Probed:      r.MajorProbed,
		Path:        r.NewerMajorModule,
		Version:     r.NewerMajorLatest,
		PublishedAt: r.NewerMajorDate,
	}
}

func runLatest(ctx context.Context, args []string, f latestFlags, stdout, stderr io.Writer) error {
	proxy, err := proxyadapter.New(f.goproxy, false)
	if err != nil {
		return proxyAdapterError(err)
	}

	// The ledger is the only reason this command opens the store. A store that
	// cannot be opened is reported and the run continues live rather than
	// failing: the answer is still obtainable, it is just paid for again.
	ledger, closeLedger, lerr := openStalenessLedger(storeRoot)
	if lerr != nil {
		_, _ = fmt.Fprintf(stderr, "staleness ledger unavailable, resolving live: %v\n", lerr)
	} else {
		defer func() { _ = closeLedger() }()
	}
	// --fresh belongs here: the subject of this command IS the latest answer, so
	// asking for a fresh one is asking for the ledger to be bypassed.
	resolver := newStalenessResolver(newProxyLatestResolver(proxy), ledger, activeConfig.Staleness.TTL, f.fresh)

	if len(args) == 0 {
		gomodPath, err := resolveGoModPath(f.gomodPath)
		if err != nil {
			return err
		}
		scope, serr := scopeFromFlags(f.tool, f.project)
		if serr != nil {
			return serr
		}
		return runLatestGomod(ctx, gomodPath, scope, resolver, stdout, stderr)
	}

	return runLatestModules(ctx, args, resolver, stdout)
}

// runLatestModules resolves one or more module coordinates from positional
// args. Extra positional arguments used to be silently dropped; now
// every module is queried and the output mode is determined by jsonOut and
// arity: a single module renders as a one-line text string or a JSON object,
// multiple modules render as one text line each or a JSON array.
func runLatestModules(ctx context.Context, modules []string, resolver *staleapp.Resolver, stdout io.Writer) error {
	results := make([]latestResult, 0, len(modules))
	for _, modulePath := range modules {
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("context cancelled: %w", cerr)
		}
		// No pin is passed: with nothing named on the command line the resolved
		// latest places the probe's starting major, so a bare path whose newest
		// release is a +incompatible v2 still probes from /v3.
		ans, err := resolver.Resolve(ctx, modulePath, "")
		if err != nil {
			return fmt.Errorf("querying latest for %s: %w", modulePath, err)
		}
		// No pin was named, so there is no comparison to report: is_latest is null
		// with the reason "not asked", never true. `latest <module>` answers "what
		// is the newest version", and answering the unasked staleness question in
		// the affirmative beside it is how a caller ends up reading a bare path
		// lookup as a clean bill of health for a version it never mentioned.
		res := latestResult{
			Module:              modulePath,
			StalenessUnmeasured: stalenessNotAsked,
		}
		res.applyStaleness(ans)
		results = append(results, res)
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		// Preserve the single-module object shape for backward compatibility;
		// >1 module emits an array (matching the --gomod output shape).
		if len(results) == 1 {
			if err := enc.Encode(results[0]); err != nil {
				return fmt.Errorf("encoding JSON: %w", err)
			}
			return nil
		}
		if err := enc.Encode(results); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	for _, r := range results {
		if err := writeLatestSingleLine(stdout, r); err != nil {
			return err
		}
	}
	return nil
}

// writeLatestSingleLine prints one human-readable line for a resolved module.
func writeLatestSingleLine(stdout io.Writer, r latestResult) error {
	days := 0
	if !r.LatestDate.IsZero() {
		days = int(time.Since(r.LatestDate).Hours() / 24)
	}
	var line string
	switch {
	case r.LatestDate.IsZero():
		line = fmt.Sprintf("%s@%s", r.Module, r.Latest)
	case days == 0:
		line = fmt.Sprintf("%s@%s (released today)", r.Module, r.Latest)
	default:
		line = fmt.Sprintf("%s@%s (released %d days ago, %s)",
			r.Module, r.Latest, days, r.LatestDate.UTC().Format("2006-01-02"))
	}
	if note := newerMajorNote(r.newerMajor()); note != "" {
		line += "; " + note
	}
	if asOf := stalenessAsOf(r.LookedUpAt); asOf != "" {
		line += "  [as of " + asOf + "]"
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// latestReleaseAgeDays is how many whole days ago publishedAt was. A zero
// publication time yields zero: the proxy supplied no date, so there is no age
// to report and the field is omitted rather than filled with one.
func latestReleaseAgeDays(publishedAt time.Time) int {
	if publishedAt.IsZero() {
		return 0
	}
	return int(time.Since(publishedAt).Hours() / 24)
}

// latestRowFor resolves one pinned dependency into an output row.
//
// The failed lookup is the row this function exists to get right: nothing was
// measured, so is_latest is null with the reason, and the table keeps the error
// line it already printed. The row used to carry a bare zero-value IsLatest,
// which --json emitted as `"is_latest": false` — the claim "your pin is behind"
// contradicting the very text line beside it that said the lookup errored.
func latestRowFor(ctx context.Context, lookup stalenessLookup, path, pinned string, stderr io.Writer) latestResult {
	ans, lerr := lookup.Resolve(ctx, path, pinned)
	if ans.LatestVersion == "" {
		if lerr != nil {
			_, _ = fmt.Fprintf(stderr, "latest %s: %v\n", path, lerr)
		}
		return latestResult{
			Module: path,
			Pinned: pinned,
			// The sentinel the table has always keyed its error cell on stays,
			// so the text output is unchanged; what changes is that the JSON now
			// says the column is unmeasured instead of answering it.
			Latest:              "(error)",
			StalenessUnmeasured: stalenessLookupFailed,
		}
	}
	if lerr != nil {
		// The same-major answer resolved and the major probe did not. The module
		// is reported with what was measured and MajorProbed false, so "no newer
		// major" is never printed for a question that failed.
		_, _ = fmt.Fprintf(stderr, "latest %s: %v\n", path, lerr)
	}

	isLatest := ans.LatestVersion == pinned
	res := latestResult{
		Module:   path,
		Pinned:   pinned,
		IsLatest: &isLatest,
	}
	res.applyStaleness(ans)
	return res
}

// runLatestGomod takes the lookup as an interface, not the concrete resolver, so
// the row above can be exercised against a lookup that fails — the leg no live
// proxy can be asked to produce on demand.
func runLatestGomod(ctx context.Context, gomodPath string, scope depScope, lookup stalenessLookup, stdout, stderr io.Writer) error {
	type pinnedDep struct {
		path    string
		version string
	}
	var deps []pinnedDep

	coords, err := resolveScopeModules(gomodPath, scope)
	if err != nil {
		return fmt.Errorf("resolving %s scope: %w", scope, err)
	}
	if len(coords) == 0 {
		// JSON array output: the empty answer is [], keeping the empty and
		// populated results the same type. Prose stays on the text path only.
		if jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode([]latestResult{}); err != nil {
				return fmt.Errorf("encoding JSON: %w", err)
			}
			return nil
		}
		_, _ = fmt.Fprintf(stdout, "no %s dependencies found in %s\n", scope, gomodPath)
		return nil
	}
	for _, coord := range coords {
		at := strings.LastIndex(coord, "@")
		deps = append(deps, pinnedDep{path: coord[:at], version: coord[at+1:]})
	}

	results := make([]latestResult, 0, len(deps))
	for _, dep := range deps {
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("context cancelled: %w", cerr)
		}
		results = append(results, latestRowFor(ctx, lookup, dep.path, dep.version, stderr))
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	return printLatestTable(stdout, results)
}

func printLatestTable(stdout io.Writer, results []latestResult) error {
	const colWidth = 55
	oldest := oldestLookup(results)
	for _, r := range results {
		coord := r.Module + "@" + r.Pinned
		if len(coord) < colWidth {
			coord = fmt.Sprintf("%-*s", colWidth, coord)
		}
		var status string
		switch {
		case r.Latest == "(error)":
			status = "(error resolving latest)"
		case r.IsLatest == nil:
			// Any other unmeasured row states the absence in the cell rather than
			// falling through to one of the answers below.
			status = stalenessUnmeasuredLabel(r.StalenessUnmeasured)
		case *r.IsLatest:
			status = "current"
		case r.LatestReleaseAgeDays == 0:
			status = fmt.Sprintf("latest: %s (released today)", r.Latest)
		default:
			status = fmt.Sprintf("latest: %s (%d days ago)", r.Latest, r.LatestReleaseAgeDays)
		}
		// The newer-major clause is appended, never substituted: "current" stays
		// true of the module's own path and the major line is stated beside it.
		if note := newerMajorNote(r.newerMajor()); note != "" {
			status += "; " + note
		}
		if _, err := fmt.Fprintf(stdout, "%s  %s\n", coord, status); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if asOf := stalenessAsOf(oldest); asOf != "" {
		if _, err := fmt.Fprintf(stdout, "\nlatest as of %s (staleness.ttl %s; --fresh to re-query)\n",
			asOf, activeConfig.Staleness.TTL); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}

// oldestLookup returns the earliest lookup time across the table.
//
// The table is dated by its OLDEST row, not its newest: a mixed run where most
// rows were served and a few re-queried is only as current as the row that was
// asked about longest ago, and dating it by the freshest would overstate the
// whole table.
func oldestLookup(results []latestResult) time.Time {
	var oldest time.Time
	for _, r := range results {
		if r.LookedUpAt.IsZero() {
			continue
		}
		if oldest.IsZero() || r.LookedUpAt.Before(oldest) {
			oldest = r.LookedUpAt
		}
	}
	return oldest
}
