package cli

import (
	"context"
	"encoding/json"
	"errors"
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
	gomodPath    string
	goproxy      string
	tool         bool
	project      bool
	fresh        bool
	excludeTests bool
}

func newLatestCmd(stdout, stderr io.Writer) *cobra.Command {
	var f latestFlags

	cmd := &cobra.Command{
		Use:         "latest [<module>...]",
		Annotations: map[string]string{annotationStoreIntent: StoreIntentCreate},
		Short:       "Resolve the latest published version of one or more modules",
		Long: `latest queries the Go module proxy for the latest published version of one or
more modules.

With --gomod, it reports the pinned version from go.mod against the latest
available for every direct dependency, letting you see staleness at a glance.

Separate facts are reported for each module, never merged. The latest version at
the module path itself, and — because a Go module's next MAJOR version lives at
a different path — the newest major path above the pinned major that resolves. A
module pinned several majors behind is current at its own path and still behind.

A +incompatible pin gets a third: its OWN major republished at /vN. The major
number is unchanged there and only the path moved, so it reads as "same major
republished" rather than "newer major" — usually the cheaper move, and invisible
to the first fact. Where a pin has both, both are reported, that one first.

Successful lookups are recorded in the store and served back while they are
younger than staleness.ttl (default 1h) — including under GOPROXY=off, where a
module with no such lookup is refused rather than answered. Every answer states
the lookup time it used; pass --fresh to bypass the ledger and re-query.

Without --gomod, one or more module paths may be passed as positional
arguments; with multiple modules, --json emits an array.`,
		Example: `  kanonarion latest github.com/spf13/cobra
  kanonarion latest github.com/spf13/cobra github.com/stretchr/testify
  kanonarion latest github.com/spf13/cobra --json
  kanonarion latest --gomod ./go.mod
  kanonarion latest --gomod ./go.mod --json
  kanonarion latest --gomod ./go.mod --tool
  kanonarion latest --gomod ./go.mod --exclude-tests
  kanonarion latest --gomod ./go.mod --fresh`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.gomodPath != "" && len(args) > 0 {
				return fmt.Errorf("cannot specify both a module path and --gomod")
			}
			if (f.tool || f.project) && len(args) > 0 {
				return fmt.Errorf("--tool and --project apply to a go.mod scan, not a positional module path")
			}
			// A positional module names itself; there is no scope to resolve and so
			// no test axis to narrow. Refused by name rather than parsed and
			// dropped, which would leave the output byte-identical.
			if f.excludeTests && len(args) > 0 {
				return refuseInapplicableFlags("latest <module>...",
					[]inapplicableFlag{{flag: "--" + testScopeFlagName, where: "latest --gomod"}})
			}
			return runLatest(cmd.Context(), args, f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.gomodPath, "gomod", "", "path to go.mod; report latest vs pinned for the project's code dependencies (default: ./go.mod)")
	cmd.Flags().StringVar(&f.goproxy, "goproxy", "", "override GOPROXY (default: $GOPROXY or proxy.golang.org)")
	cmd.Flags().BoolVar(&f.tool, "tool", false, "scope to the tooling supply chain (the go.mod tool directives' closure)")
	cmd.Flags().BoolVar(&f.project, "project", false, "scope to the complete set: the project's code AND tooling")
	cmd.Flags().BoolVar(&f.fresh, "fresh", false, "re-query the proxy instead of serving recorded lookups from the store")
	cmd.Flags().BoolVar(&f.excludeTests, testScopeFlagName, false, "with --gomod: resolve the dependency scope without test imports")

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
	// It is a POINTER, and always emitted, because ZERO IS A REAL ANSWER: a
	// release that shipped today is nought days old. As a bare int under
	// `omitempty` that row was erased, so "the fix landed today" and "we do not
	// know when it was published" were the same absence — on a row that is
	// behind and offering a target, which is where the figure carries its
	// meaning. Null now means only one thing, and it is never a fabricated age.
	//
	// Null in exactly two cases, told apart by PinAheadOfLatest:
	//   - the proxy supplied no publication date (PinAheadOfLatest false), the
	//     same condition that leaves LatestDate absent;
	//   - the pin is AHEAD (PinAheadOfLatest true), where no distance is
	//     reported at all. There the age would travel beside `is_latest: false`
	//     and read as "you are this far behind" — the wrong answer that state
	//     exists to withhold. On a current row it travels beside
	//     `is_latest: true`, which no consumer reads that way, and it is kept:
	//     the age of a release is a fact about the release.
	// LatestDate is unaffected either way — a publication date is a fact about a
	// named release, while this figure is a distance, and only the distance is
	// meaningless when nothing is being offered.
	LatestReleaseAgeDays *int `json:"latest_release_age_days"`
	// IsLatest answers "is the pin the newest version of this module path".
	//
	// It is a POINTER because the question is not always answered. A lookup that
	// failed measured nothing, and a module named with no pin was never asked the
	// question at all; both used to emit a bool, and the zero value of a bool on
	// a failed lookup is the claim "your pin is behind" about a row nothing was
	// established for. Unanswered is null, with StalenessUnmeasured naming why.
	IsLatest *bool `json:"is_latest"`
	// PinAheadOfLatest is true when the pin sorts ABOVE the newest version
	// published at this path. Latest still names what the proxy answered — it
	// is a fact about the path — but it is not an upgrade target, and no age is
	// emitted beside it.
	//
	// Emitted on every row, false included, so "measured, and not in that state"
	// is distinguishable from "this build does not derive the field". A POINTER
	// for the same reason IsLatest is: on an unmeasured row, and on a bare
	// module path with no pin to compare, no comparison was made, and a bare
	// false there answers a question nobody put.
	PinAheadOfLatest *bool `json:"pin_ahead_of_latest"`
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

	// Republished* is the module's OWN major published at its /vN path, which is
	// a SIBLING fact to NewerMajor and not a variant of it. A +incompatible pin
	// carries its major in the version while living at the unsuffixed path, so
	// /vN is the same major number at the path the toolchain expects for it — a
	// path migration, not a major upgrade. It reached these keys as
	// newer_major_module until the two were separated, which told a consumer to
	// budget a breaking change for what can be a patch-level move.
	//
	// Both sets are populated when both hold, and neither is derived from the
	// other: a consumer wanting the cheap move reads these keys, one wanting the
	// next major line reads newer_major_*, and neither has to parse a major
	// number out of a path to tell which it has.
	RepublishedModule string    `json:"republished_module,omitempty"`
	RepublishedLatest string    `json:"republished_latest,omitempty"`
	RepublishedDate   time.Time `json:"republished_date,omitzero"`
	// RepublishedProbed distinguishes "asked, this major is not republished" from
	// "not asked" — the question is only put for a +incompatible pin on a bare
	// path. Emitted always, false included: false is an answer here, and erasing
	// it would make a module that was asked indistinguishable from a build that
	// does not derive the field at all.
	RepublishedProbed bool `json:"republished_probed"`

	// Deprecated is the module author's OWN deprecation notice, reproduced
	// verbatim from the `// Deprecated:` comment on their go.mod module
	// directive. It is a fourth fact beside the three above and is never merged
	// into them: a deprecated module frequently has no newer major at all, and
	// the successor a notice names is often at a path the /vN probe structurally
	// cannot reach — google.golang.org/protobuf succeeds github.com/golang/protobuf
	// on a different host entirely.
	//
	// It is a POINTER and is ALWAYS emitted, because there are three states and
	// only two of them are answers:
	//   - null: not established. The answer came from a source that cannot see
	//     the notice (a per-path @latest lookup) or from a ledger row recorded
	//     before the question was asked. It is NOT "not deprecated".
	//   - "": established, and the module declares no deprecation.
	//   - text: the notice, as published.
	// A bare string could not tell the first two apart, and collapsing them
	// would report every unasked module as actively fine.
	//
	// kanonarion never INFERS a successor. If a module is superseded and says so
	// nowhere machine-readable, this is empty and nothing is reported.
	Deprecated *string `json:"deprecated"`

	// DependencyScope names the go.mod dependency scope this row was selected by
	// and the test axis that scope applied.
	//
	// On the row rather than on an envelope because there is none: --json emits a
	// bare array, and a row copied out of it otherwise carries no record of which
	// set it belonged to — 20 rows with test imports and 18 without decode
	// identically. Absent on the positional path, where the caller named the
	// modules and no scope was projected.
	DependencyScope *scopeJSON `json:"dependency_scope,omitempty"`

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
	r.RepublishedModule = ans.Republication.Path
	r.RepublishedLatest = ans.Republication.Version
	r.RepublishedDate = ans.Republication.PublishedAt
	r.RepublishedProbed = ans.Republication.Asked
	r.Deprecated = deprecationField(ans.Deprecation)
	r.LookedUpAt = ans.LookedUpAt
	r.Served = ans.Served
}

// latestErrorSentinel is what the `latest` column holds for a row whose lookup
// failed. It is a value in the version field rather than a state of its own for
// historical reasons; the JSON says the same thing properly through
// staleness_unmeasured.
const latestErrorSentinel = "(error)"

// sameMajorAnswered reports whether this row got a same-major answer at all.
//
// It is the gate on stating an unanswered major probe: a probe is planned for
// every module whose latest resolves, so on a row with an answer an unprobed
// major line is a lost answer, while on a row with none — an offline row, or the
// error sentinel — nothing was asked and the row's own cell already says so.
func (r latestResult) sameMajorAnswered() bool {
	return r.Latest != "" && r.Latest != latestErrorSentinel
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

// republication rebuilds the sibling fact from an output row, for the same
// reason: the text line and the JSON must not disagree about which of the two
// facts a row holds.
func (r latestResult) republication() staledomain.Republication {
	return staledomain.Republication{
		Asked:       r.RepublishedProbed,
		Path:        r.RepublishedModule,
		Version:     r.RepublishedLatest,
		PublishedAt: r.RepublishedDate,
	}
}

// deprecationField renders the domain fact as the JSON three-state: nil when the
// question was not answered, a pointer to the notice (empty for a recorded
// negative) when it was.
func deprecationField(dep staledomain.Deprecation) *string {
	if !dep.Checked {
		return nil
	}
	notice := dep.Notice
	return &notice
}

// deprecation rebuilds the domain fact from an output row, so the text renderers
// and the JSON cannot disagree about which state a row is in.
func (r latestResult) deprecation() staledomain.Deprecation {
	if r.Deprecated == nil {
		return staledomain.Deprecation{}
	}
	return staledomain.Deprecation{Checked: true, Notice: *r.Deprecated}
}

func runLatest(ctx context.Context, args []string, f latestFlags, stdout, stderr io.Writer) error {
	// An environment that declares no module fetching is no longer refused at
	// adapter construction. GOPROXY=off says the network may not be asked; it
	// does not say the answer is unknown, and the staleness ledger exists
	// precisely so a recorded lookup can be served without going out. The
	// refusal that used to fire here also offered --from-modcache and
	// `use --recursive`, which are about module BYTES — neither can produce an
	// @latest version, so it named remedies this command has no use for.
	//
	// --fresh is the exception and is deliberately untouched: it means "bypass
	// the ledger and re-query the proxy", which an environment that forbids
	// fetching cannot do, so it keeps the refusal it has today.
	//
	// The gate is ErrProxyOff specifically, NOT every construction refusal.
	// GOPROXY=direct is a different statement: the operator asked for VCS-origin
	// fetching, a route this adapter has not got, and serving a recorded answer
	// there would answer a request that was never refused on network grounds. It
	// keeps refusing, with the message that names the mode.
	proxy, perr := proxyadapter.New(f.goproxy, false)
	offline := perr != nil && errors.Is(perr, proxyadapter.ErrProxyOff) && !f.fresh
	if perr != nil && !offline {
		return proxyAdapterError(perr)
	}

	// The ledger is the only reason this command opens the store. A store that
	// cannot be opened is reported and the run continues live rather than
	// failing: the answer is still obtainable, it is just paid for again. When
	// the network is forbidden there is nothing to fall back to, and the
	// per-module refusal below states that rather than a live retry that will
	// not happen.
	ledger, closeLedger, lerr := openStalenessLedger(storeRoot)
	if lerr != nil {
		if offline {
			_, _ = fmt.Fprintf(stderr, "staleness ledger unavailable and the environment forbids fetching: %v\n", lerr)
		} else {
			_, _ = fmt.Fprintf(stderr, "staleness ledger unavailable, resolving live: %v\n", lerr)
		}
	} else {
		defer func() { _ = closeLedger() }()
	}
	// --fresh belongs here: the subject of this command IS the latest answer, so
	// asking for a fresh one is asking for the ledger to be bypassed.
	//
	// Offline the lookup is the ledger alone — the same one `audit` uses under
	// --from-modcache, with the same rule: a row inside the TTL is a
	// measurement and is served, anything else refuses. Serving a stale row
	// because the network is unavailable would present an old answer as
	// current, which is worse than refusing, and it never writes, because an
	// offline run learns no new upstream fact.
	var lookup stalenessLookup
	if offline {
		// proxy is nil here — construction refused — so the live resolver is not
		// built at all rather than being built around an adapter that cannot be
		// asked.
		lookup = newOfflineStalenessLookup(ledger, activeConfig.Staleness.TTL)
	} else {
		lookup = newStalenessResolver(newProxyLatestResolver(proxy, buildLogger(logLevel, stderr), nil),
			ledger, activeConfig.Staleness.TTL, f.fresh)
	}

	if len(args) == 0 {
		gomodPath, err := resolveGoModPath(f.gomodPath)
		if err != nil {
			return err
		}
		scope, serr := scopeFromFlags(f.tool, f.project)
		if serr != nil {
			return serr
		}
		if f.excludeTests && scope == scopeComplete {
			return refuseTestScopeOnCompleteScope("latest --gomod")
		}
		// The go.mod path is the one place the latest question is asked about a
		// SET, and the go command answers a set in one call. The offline lookup
		// keeps the ledger it already had: `go list -m -u` under a declared air
		// gap reports every module as having no update, which is not an answer,
		// so the batch refuses there rather than manufacturing one.
		return runLatestGomod(ctx, gomodPath, scope, f.excludeTests, func(coords []string) stalenessLookup {
			if offline {
				return lookup
			}
			return newGomodStalenessResolver(newProxyLatestResolver(proxy, buildLogger(logLevel, stderr), nil),
				ledger, activeConfig.Staleness.TTL, f.fresh, gomodPath, f.goproxy, pinnedModulesOf(coords))
		}, stdout, stderr)
	}

	return runLatestModules(ctx, args, lookup, stdout, stderr)
}

// runLatestModules resolves one or more module coordinates from positional
// args. Extra positional arguments used to be silently dropped; now
// every module is queried and the output mode is determined by jsonOut and
// arity: a single module renders as a one-line text string or a JSON object,
// multiple modules render as one text line each or a JSON array.
func runLatestModules(ctx context.Context, modules []string, lookup stalenessLookup, stdout, stderr io.Writer) error {
	results := make([]latestResult, 0, len(modules))
	for _, modulePath := range modules {
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("context cancelled: %w", cerr)
		}
		// No pin is passed: with nothing named on the command line the resolved
		// latest places the probe's starting major, so a bare path whose newest
		// release is a +incompatible v2 still probes from /v3.
		ans, err := lookup.Resolve(ctx, modulePath, "")
		if err != nil && ans.LatestVersion == "" {
			if errors.Is(err, errStalenessOffline) {
				return latestOfflineRefusal(modulePath)
			}
			// Nothing resolved at all: there is no answer to print.
			return fmt.Errorf("querying latest for %s: %w", modulePath, err)
		}
		if err != nil {
			// The same-major answer resolved and only the newer-major probe
			// failed. That half is reported with MajorProbed false, exactly as
			// the --gomod rows do it; failing the command here would discard a
			// measurement that succeeded — and, with several modules named,
			// every module after this one — because a second question about a
			// different path could not be put.
			_, _ = fmt.Fprintf(stderr, "latest %s: %v\n", modulePath, err)
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

// latestOfflineRefusal is what a named module gets when the environment forbids
// fetching and the ledger cannot answer for it.
//
// It names the actual obstacle — no recorded lookup inside the staleness TTL —
// rather than the module-bytes remedies the proxy adapter's own refusal carries.
// `--from-modcache` reads bytes already downloaded and `use --recursive`
// reconstitutes a module from the store; neither yields an @latest version, so
// offering them here sent the reader after two things that cannot work.
//
// It carries ExitConfig because the run was stopped by a precondition, which is
// the code the adapter refusal it replaces already used.
func latestOfflineRefusal(modulePath string) error {
	return &exitError{
		code: ExitConfig,
		msg: fmt.Sprintf(
			"cannot resolve latest for %s: this environment does no proxy fetching, and the store holds no lookup "+
				"for it inside staleness.ttl (%s); offline, latest serves only a lookup recorded earlier",
			modulePath, activeConfig.Staleness.TTL),
	}
}

// writeLatestSingleLine prints one human-readable line for a resolved module.
func writeLatestSingleLine(stdout io.Writer, r latestResult) error {
	days := 0
	if !r.LatestDate.IsZero() {
		days = int(cliSince(r.LatestDate).Hours() / 24)
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
	if note := majorNotes(r.republication(), r.newerMajor(), r.sameMajorAnswered()); note != "" {
		line += "; " + note
	}
	// Appended as its own clause, never substituted for one of the others: a
	// module can be deprecated AND have a newer major, and they are different
	// claims.
	if note := deprecationNote(r.deprecation()); note != "" {
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

// latestReleaseAgeDays is how many whole days ago publishedAt was, or nil when
// the proxy supplied no publication date.
//
// It returns a POINTER because zero is a real answer here — a release that
// shipped today is nought days old — and it used to be indistinguishable from
// "no date was supplied": both produced 0, and an `omitempty` tag then erased
// both from the JSON. On a row that is behind and IS offering a target, that
// is the field's most meaningful value going missing precisely where it means
// most. A fabricated age is not the alternative: an absent date yields nil,
// which every renderer states as no age rather than as "today".
func latestReleaseAgeDays(publishedAt time.Time) *int {
	if publishedAt.IsZero() {
		return nil
	}
	days := int(cliSince(publishedAt).Hours() / 24)
	return &days
}

// latestRowFor resolves one pinned dependency into an output row.
//
// The failed lookup is the row this function exists to get right: nothing was
// measured, so is_latest is null with the reason, and the table keeps the error
// line it already printed. The row used to carry a bare zero-value IsLatest,
// which --json emitted as `"is_latest": false` — the claim "your pin is behind"
// contradicting the very text line beside it that said the lookup errored.
// The error is returned as well as rendered because ONE class of failure is not
// this row's: a batched resolution answers for the whole set in one call, so its
// failure is the same failure for every module and the caller stops the run on
// it rather than printing it once per dependency. Every other error stays a
// per-row condition and is rendered as one, exactly as before.
func latestRowFor(ctx context.Context, lookup stalenessLookup, path, pinned string, stderr io.Writer) (latestResult, error) {
	ans, lerr := lookup.Resolve(ctx, path, pinned)
	if ans.LatestVersion == "" {
		if errors.Is(lerr, errStalenessOffline) {
			// Not a failure: the environment forbids asking and nothing recorded
			// was inside the TTL. It gets the offline reason and no error line,
			// exactly as the audit column does, so the table says "unmeasured
			// (offline)" instead of "(error resolving latest)" — which would
			// report a working mode as a fault.
			return latestResult{
				Module:              path,
				Pinned:              pinned,
				StalenessUnmeasured: stalenessOfflineNoEntry,
			}, nil
		}
		if lerr != nil {
			_, _ = fmt.Fprintf(stderr, "latest %s: %v\n", path, lerr)
		}
		return latestResult{
			Module: path,
			Pinned: pinned,
			// The sentinel the table has always keyed its error cell on stays,
			// so the text output is unchanged; what changes is that the JSON now
			// says the column is unmeasured instead of answering it.
			Latest:              latestErrorSentinel,
			StalenessUnmeasured: stalenessLookupFailed,
		}, fmt.Errorf("resolving latest for %s: %w", path, lerr)
	}
	if lerr != nil {
		// The same-major answer resolved and the major probe did not. The module
		// is reported with what was measured and MajorProbed false, so "no newer
		// major" is never printed for a question that failed.
		_, _ = fmt.Fprintf(stderr, "latest %s: %v\n", path, lerr)
	}

	// Placed with semver, not string equality: string equality has only two
	// outcomes, so a pin that sorts ABOVE @latest landed in "behind" and the
	// row named a downgrade as its upgrade target.
	pos := staledomain.ComparePin(pinned, ans.LatestVersion)
	isLatest := pos == staledomain.PinLevel
	ahead := pos == staledomain.PinAhead
	res := latestResult{
		Module:           path,
		Pinned:           pinned,
		IsLatest:         &isLatest,
		PinAheadOfLatest: &ahead,
	}
	res.applyStaleness(ans)
	if ahead {
		// See LatestReleaseAgeDays: a distance is not reported where nothing is
		// being offered to close it. applyStaleness sets it unconditionally
		// because it also serves the unpinned row, which has no position at all.
		res.LatestReleaseAgeDays = nil
	}
	if lerr != nil {
		return res, fmt.Errorf("resolving latest for %s: %w", path, lerr)
	}
	return res, nil
}

// runLatestGomod takes the lookup as an interface, not the concrete resolver, so
// the row above can be exercised against a lookup that fails — the leg no live
// proxy can be asked to produce on demand.
// newLookup is a FACTORY rather than a built lookup because the batched latest
// source has to be told which modules it is answering for, and that set is this
// function's own result. Building the lookup before the scope is resolved would
// have meant either a batch over the wrong set or a second scope resolution.
func runLatestGomod(ctx context.Context, gomodPath string, scope depScope, excludeTests bool,
	newLookup func(coords []string) stalenessLookup, stdout, stderr io.Writer) error {
	type pinnedDep struct {
		path    string
		version string
	}
	var deps []pinnedDep

	coords, res, err := resolveScopeModules(gomodPath, scope, excludeTests)
	if err != nil {
		return fmt.Errorf("resolving %s scope: %w", scope, err)
	}
	// Which set these rows are the whole of, stated before them and on the same
	// channel as every other statement about the run. The empty case states it
	// too: a table with no rows is answered by naming the set that was empty.
	if nerr := writeDepScopeNotice(stderr, res, len(coords), true); nerr != nil {
		return nerr
	}
	scopeField := newScopeJSON(res)
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
	lookup := newLookup(coords)

	results := make([]latestResult, 0, len(deps))
	for _, dep := range deps {
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("context cancelled: %w", cerr)
		}
		row, rerr := latestRowFor(ctx, lookup, dep.path, dep.version, stderr)
		row.DependencyScope = scopeField
		if errors.Is(rerr, staleapp.ErrBatchUnavailable) {
			// The batched call answers for every module at once, so this is not
			// one dependency's failure and must not be rendered as one: printing
			// it per row would repeat the identical message once per dependency
			// while the table filled with unmeasured cells. The run stops with
			// the reason, in the go command's own words.
			return fmt.Errorf("resolving the latest version of the %s dependency set: %w", scope, rerr)
		}
		results = append(results, row)
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
		case r.Latest == latestErrorSentinel:
			status = "(error resolving latest)"
		case r.IsLatest == nil:
			// Any other unmeasured row states the absence in the cell rather than
			// falling through to one of the answers below.
			status = stalenessUnmeasuredLabel(r.StalenessUnmeasured)
		case *r.IsLatest:
			status = "current"
		case r.PinAheadOfLatest != nil && *r.PinAheadOfLatest:
			// No target and no age: there is nothing at this path to move to,
			// and the age of a release the pin is already past is not a
			// distance behind.
			status = fmt.Sprintf("ahead of latest tag: %s", r.Latest)
		case r.LatestReleaseAgeDays == nil:
			// The proxy named a newer version and no date for it. The target is
			// still worth stating; an age is not invented for it, and it used to
			// be — a missing date reached this line as 0 and printed
			// "released today" about a release nothing is known about.
			status = fmt.Sprintf("latest: %s", r.Latest)
		case *r.LatestReleaseAgeDays == 0:
			status = fmt.Sprintf("latest: %s (released today)", r.Latest)
		default:
			status = fmt.Sprintf("latest: %s (%d days ago)", r.Latest, *r.LatestReleaseAgeDays)
		}
		// The major-line clauses are appended, never substituted: "current" stays
		// true of the module's own path and the other paths are stated beside it.
		if note := majorNotes(r.republication(), r.newerMajor(), r.sameMajorAnswered()); note != "" {
			status += "; " + note
		}
		if note := deprecationNote(r.deprecation()); note != "" {
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
