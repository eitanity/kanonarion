package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
)

func newWalkListCmd(stdout, stderr io.Writer) *cobra.Command {
	var module string
	var platform buildTargetFlags
	var since string
	var statusStr string
	var scopeStr string
	var tool bool
	var limit, offset int
	var walkID string
	var latest bool
	var latestSuccess bool
	var moduleAlias *deprecatedAlias

	cmd := &cobra.Command{
		Use: "walk-list",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "List stored walk records",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := refuseWalkIDRowFilters(cmd); err != nil {
				return err
			}
			if tool && scopeStr != "" {
				return fmt.Errorf("cannot combine --tool and --scope")
			}
			if tool {
				scopeStr = "tool"
			}
			moduleArg, err := moduleAlias.resolve(cmd, module, stderr)
			if err != nil {
				return err
			}
			if latestSuccess {
				if statusStr != "" && statusStr != "succeeded" {
					return fmt.Errorf("--latest-success implies --status succeeded; cannot combine with --status %s", statusStr)
				}
				statusStr = "succeeded"
				limit = 1
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer releaseStore(cleanup)
			lerr := runWalkList(cmd.Context(), moduleArg, since, statusStr, scopeStr, platform, walkID, limit, offset, latest, latestSuccess, ctr.QueryWalks, stdout, stderr)
			if me, ok := errors.AsType[*moduleFilterError](lerr); ok && cmd.Flags().Changed("target") {
				me.flag = "target"
			}
			return lerr
		},
	}
	cmd.Flags().StringVar(&module, "module", "", "filter by the module@version the walk is rooted at")
	cmd.Flags().StringVar(&platform.goos, "goos", "", "filter by the recorded target operating system; pass with --goarch")
	cmd.Flags().StringVar(&platform.goarch, "goarch", "", "filter by the recorded target architecture; pass with --goos")
	cmd.Flags().StringVar(&platform.tinygo, "tinygo", "", "filter by the recorded TinyGo target, e.g. pico (needs the tinygo command on PATH)")
	cmd.Flags().StringVar(&since, "since", "", "filter by start time (RFC3339)")
	cmd.Flags().StringVar(&statusStr, "status", "", "filter by overall status (succeeded|partial|failed|cancelled)")
	cmd.Flags().StringVar(&scopeStr, "scope", "", "filter by walk scope (code|tool|complete)")
	cmd.Flags().BoolVar(&tool, "tool", false, "shorthand for --scope tool")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of results to return (0 = unlimited)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many results")
	cmd.Flags().StringVar(&walkID, "walk-id", "", "fetch a single walk summary by ID")
	cmd.Flags().BoolVar(&latest, "latest", false, "return only the latest unique (target, scope, platform, toolchain) combination")
	cmd.Flags().BoolVar(&latestSuccess, "latest-success", false, "return only the single most recent succeeded walk (as a JSON object, not an array)")
	// --target is the old spelling of --module. Every other command reads it as
	// GOOS/GOARCH, so it is kept only as a warning alias, not as a platform filter.
	moduleAlias = registerDeprecatedAlias(cmd, "target", "module")
	return cmd
}

// walkListRowFilters are the walk-list flags that narrow or select rows. Paging
// and output flags are not here: they still apply to one named walk.
var walkListRowFilters = []string{"module", "target", "goos", "goarch", "tinygo", "since", "status", "scope", "tool", "latest", "latest-success"}

// refuseWalkIDRowFilters refuses a row filter beside --walk-id. The walk is
// already named, so a filter would be ignored and the walk returned even when it
// does not match — a wrong answer, not an unfiltered one.
func refuseWalkIDRowFilters(cmd *cobra.Command) error {
	if !cmd.Flags().Changed("walk-id") {
		return nil
	}
	var given []string
	for _, name := range walkListRowFilters {
		if cmd.Flags().Changed(name) {
			given = append(given, "--"+name)
		}
	}
	if len(given) == 0 {
		return nil
	}
	return &exitError{code: ExitConfig, msg: fmt.Sprintf("--walk-id names one walk; it cannot be combined with %s", strings.Join(given, ", "))}
}

// walkListPlatform is the recorded-platform row filter --goos/--goarch or
// --tinygo ask for, nil when none was given. The pair is validated as every
// resolving command validates it, so a mistyped half is refused by name. A
// TinyGo target is matched on its recorded name alone: a listing reads the
// store, and the tinygo command need not be on this host to read it.
func walkListPlatform(ctx context.Context, f buildTargetFlags) (*walkports.BuildEnvFilter, error) {
	if f.tinygo != "" {
		declare(goenv.Target{}, goenv.TinyGo{})
		if _, err := (buildTargetFlags{goos: f.goos, goarch: f.goarch, tinygo: f.tinygo}).parse(); err != nil {
			return nil, err
		}
		return &walkports.BuildEnvFilter{TinyGoTarget: f.tinygo}, nil
	}
	if err := resolveBuildTarget(ctx, buildTargetFlags{goos: f.goos, goarch: f.goarch}, "", ""); err != nil {
		return nil, err
	}
	if !declaredTarget.Declared() {
		return nil, nil
	}
	return &walkports.BuildEnvFilter{GOOS: declaredTarget.GOOS(), GOARCH: declaredTarget.GOARCH()}, nil
}

// moduleFilterError is a module filter that is not a coordinate. It names the
// flag the caller typed; RunE sets flag to "target" when the alias was used.
type moduleFilterError struct {
	flag  string
	value string
	err   error
}

func (e *moduleFilterError) Error() string {
	return fmt.Sprintf("--%s: invalid module coordinate %q: %v", e.flag, e.value, e.err)
}

func (e *moduleFilterError) Unwrap() error { return e.err }

// platformNotModule refuses a module filter that is a GOOS/GOARCH pair, naming
// --goos/--goarch: --target means a platform on every other command, so this is
// the mistake the old spelling invites. Asked only after the value failed to
// parse as a coordinate; the toolchain decides what is a pair.
func platformNotModule(ctx context.Context, arg string) error {
	t, err := goenv.ParseTarget(arg)
	if err != nil || strings.Contains(arg, "@") {
		return nil //nolint:nilerr // not a pair: the coordinate refusal stands
	}
	if ok, _, serr := gotoolchain.New("", nil).Supports(ctx, t); serr != nil || !ok {
		return nil //nolint:nilerr // an unconfirmed pair: the coordinate refusal stands
	}
	return &exitError{code: ExitConfig, msg: fmt.Sprintf(
		"%q is a build platform, not a module coordinate: on walk-list, --module (and its deprecated spelling --target) names the module@version a walk is rooted at; filter by the recorded platform with --goos %s --goarch %s",
		arg, t.GOOS(), t.GOARCH())}
}

func runWalkList(ctx context.Context, targetArg, sinceArg, statusArg, scopeArg string, platform buildTargetFlags, walkID string, limit, offset int, latest, latestSuccess bool, uc QueryWalksUseCase, stdout, stderr io.Writer) error {
	env, perr := walkListPlatform(ctx, platform)
	if perr != nil {
		return perr
	}
	if walkID != "" {
		return showOneWalk(ctx, walkID, uc, stdout, stderr)
	}
	// One row more than will be printed, so the extra row's presence answers
	// whether the limit bit. --latest-success is not a listing — it selects a
	// single record by definition — so it keeps its own limit and states nothing.
	fetchLimit := truncationFetchLimit(limit)
	if latestSuccess {
		fetchLimit = limit
	}
	filter, ferr := buildWalkFilter(targetArg, sinceArg, statusArg, scopeArg, fetchLimit, offset, latest)
	if ferr != nil {
		if perr := platformNotModule(ctx, targetArg); perr != nil {
			return perr
		}
		return ferr
	}
	filter.BuildEnv = env

	summaries, err := uc.ListWalks(ctx, filter)
	if err != nil {
		return fmt.Errorf("listing walks: %w", err)
	}

	if latestSuccess {
		return showLatestSuccess(ctx, summaries, uc, stdout, stderr)
	}

	summaries, truncated := truncateList(summaries, limit)
	trunc := listTruncation{limit: limit, subject: "walk records", truncated: truncated, offset: offset}

	if jsonOut {
		var zero *listZeroScope
		if len(summaries) == 0 {
			scope, serr := walkListZeroScope(ctx, filter, offset, uc)
			if serr != nil {
				return serr
			}
			zero = &scope
		}
		return writeListDocument(stdout, summaries, trunc, zero)
	}

	if len(summaries) == 0 {
		scope, serr := walkListZeroScope(ctx, filter, offset, uc)
		if serr != nil {
			return serr
		}
		return writeListZeroNotice(stdout, scope)
	}
	for _, s := range summaries {
		if pErr := writeWalkRow(stdout, s); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
	}
	return writeListTruncationNotice(stdout, trunc)
}

// showOneWalk prints the summary of the walk --walk-id names.
func showOneWalk(ctx context.Context, walkID string, uc QueryWalksUseCase, stdout, stderr io.Writer) error {
	rec, rerr := uc.GetWalk(ctx, walkID)
	if rerr != nil {
		if isWalkNotFound(rerr) {
			scope, serr := walkIDZeroScope(ctx, walkID, uc)
			return walkSelectorMiss(scope, serr, stderr)
		}
		return fmt.Errorf("loading walk %s: %w", walkID, rerr)
	}
	summary := walkports.WalkSummary{
		ID:            rec.ID,
		Target:        rec.Target,
		Scope:         rec.Scope,
		Depth:         rec.Depth,
		StartedAt:     rec.StartedAt,
		CompletedAt:   rec.CompletedAt,
		OverallStatus: rec.OverallStatus,
		NodeCount:     len(rec.Graph.Nodes),
		FailureCount:  domain.CountNodeFailures(rec),
		GOOS:          rec.Graph.BuildEnv.GOOS,
		GOARCH:        rec.Graph.BuildEnv.GOARCH,
		TinyGoTarget:  rec.Graph.BuildEnv.TinyGoTarget,
		TinyGoVersion: rec.Graph.BuildEnv.TinyGoVersion,
	}
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(summary); encErr != nil {
			return fmt.Errorf("encoding JSON: %w", encErr)
		}
		return nil
	}
	if pErr := writeWalkRow(stdout, summary); pErr != nil {
		return fmt.Errorf("writing output: %w", pErr)
	}
	return nil
}

// showLatestSuccess prints the newest succeeded walk, refusing when there is
// none.
func showLatestSuccess(ctx context.Context, summaries []walkports.WalkSummary, uc QueryWalksUseCase, stdout, stderr io.Writer) error {
	if len(summaries) == 0 {
		scope, serr := latestSuccessZeroScope(ctx, uc)
		return walkSelectorMiss(scope, serr, stderr)
	}
	s := summaries[0]
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(s); encErr != nil {
			return fmt.Errorf("encoding JSON: %w", encErr)
		}
		return nil
	}
	if pErr := writeWalkRow(stdout, s); pErr != nil {
		return fmt.Errorf("writing output: %w", pErr)
	}
	return nil
}

// writeWalkRow prints one walk-list text row. The platform is printed, in the
// frame wording every read uses, so rows can be narrowed with --goos/--goarch: a
// module-rooted walk is not-platform-scoped, a project walk without one unrecorded.
func writeWalkRow(w io.Writer, s walkports.WalkSummary) error {
	_, err := fmt.Fprintf(w, "%s  %s  %s  %s  scope=%s  platform=%s  depth=%s  nodes=%d failures=%d\n",
		s.ID, s.Target.String(), ledgerStamp(s.StartedAt),
		s.OverallStatus.String(), string(s.Scope), s.BuildFrame(), string(s.Depth), s.NodeCount, s.FailureCount)
	return err //nolint:wrapcheck // every caller wraps it as an output write
}

// walkSelectorMiss answers a single-record selector that matched nothing.
//
// It is a not-found, not an empty listing: the caller named one record and it is
// not there, so the process exits 4 and the answer travels on the error rather
// than on stdout — stdout stays the data channel, and a --walk-id that missed
// must not put a sentence where a JSON object was expected. Under --json the
// structured statement still goes to stderr, because a machine caller reading
// the exit code needs the same counts a human gets from the message.
//
// Both selectors answer identically because both are the same question: the
// store was searched, this is how much of it there was, and this is what would
// list it. A flat "not found" reads as "this store has never seen one" whether
// the store holds nothing or holds a thousand — the same defect the walk
// containment search was fixed for.
func walkSelectorMiss(scope listZeroScope, scopeErr error, stderr io.Writer) error {
	if scopeErr != nil {
		return scopeErr
	}
	if jsonOut {
		if err := writeListZeroNoticeJSON(stderr, scope); err != nil {
			return err
		}
	}
	return &exitError{code: ExitNotFound, msg: listZeroLine(scope)}
}

// walkSelectorZeroScope sizes the store a single-record selector searched.
//
// The survey read is paid only on the miss, exactly as the listings pay theirs:
// a selector that found its record never reaches here. A failed survey is
// returned rather than absorbed — every sentence the notice can render carries a
// count, so a scope that could not be sized has nothing honest to say, and a
// zero substituted for a failed count would assert the one reading that is
// certainly wrong.
func walkSelectorZeroScope(ctx context.Context, uc QueryWalksUseCase, filterName, filterValue, field string,
	example func(walkports.WalkSummary) string,
) (listZeroScope, error) {
	all, err := uc.ListWalks(ctx, walkports.WalkFilter{})
	if err != nil {
		return listZeroScope{}, fmt.Errorf("counting walk records for the zero-result notice: %w", err)
	}
	scope := listZeroScope{
		subject:     "walk record",
		filterName:  filterName,
		filterValue: filterValue,
		field:       field,
		matchKind:   matchExact,
		considered:  len(all),
		produce:     "kanonarion walk <module>@<version>",
		listAll:     "kanonarion walk-list --limit 0",
	}
	if len(all) > 0 {
		scope.example = example(all[0])
	}
	return scope, nil
}

// walkIDZeroScope sizes the store a --walk-id was looked for in.
func walkIDZeroScope(ctx context.Context, walkID string, uc QueryWalksUseCase) (listZeroScope, error) {
	return walkSelectorZeroScope(ctx, uc, "walk id", walkID, "walk id",
		func(s walkports.WalkSummary) string { return s.ID })
}

// walkIDMiss answers every command that reads a walk by ID and did not find it.
//
// It is one function rather than one message per command because the answer is
// not about the command: `walk-show`, `verification-coverage`, `dependents
// --walk-id`, `context --walk-id` and `walk-diff` were all asked the same
// question, all searched the same corpus, and three of them spelled the miss
// differently — `walk record "X" not found`, `walk X not found`, and `one or
// both walk IDs not found`. A caller who learned to read one of those learned
// nothing about the next.
//
// The survey read it pays is on the miss branch only: a walk that was found
// never reaches here, which is what keeps the statement off the path these
// commands take almost every time they run.
func walkIDMiss(ctx context.Context, uc QueryWalksUseCase, walkID string, stderr io.Writer) error {
	scope, serr := walkIDZeroScope(ctx, walkID, uc)
	return walkSelectorMiss(scope, serr, stderr)
}

// walkTargetMiss answers the commands that select a walk by the module it was
// rooted at rather than by ID — `use`, `license --recursive`, `license-compat`.
//
// Their flat negative already carried the remedy (`run 'kanonarion walk' first`)
// and it is kept: keepProduce puts it beside the corpus statement rather than
// having one displace the other. What it could not say is how many walks the
// target was compared against, which is the difference between a store that has
// never been walked and one holding fifty walks of other modules.
func walkTargetMiss(ctx context.Context, uc QueryWalksUseCase, target coordinate.ModuleCoordinate,
	stderr io.Writer,
) error {
	scope, serr := walkSelectorZeroScope(ctx, uc, "target module", target.String(), "target coordinate",
		func(s walkports.WalkSummary) string { return s.Target.String() })
	if serr == nil {
		scope.produce = walkInvocation(target)
		scope.keepProduce = true
	}
	return walkSelectorMiss(scope, serr, stderr)
}

// latestSuccessZeroScope sizes the store a --latest-success found no succeeded
// walk in. The selector is --status succeeded with a limit of one, so that is
// what the statement names: a caller whose walks all failed is looking at the
// status, not at a missing record.
func latestSuccessZeroScope(ctx context.Context, uc QueryWalksUseCase) (listZeroScope, error) {
	return walkSelectorZeroScope(ctx, uc, "overall status", domain.WalkSucceeded.String(), "overall status",
		func(s walkports.WalkSummary) string { return s.OverallStatus.String() })
}

// buildWalkFilter parses walk-list's four filter flags into the store filter.
// Each is reported by the flag the caller typed, so a rejected value names the
// flag they have to correct rather than the field it parses into.
func buildWalkFilter(targetArg, sinceArg, statusArg, scopeArg string, limit, offset int, latest bool) (walkports.WalkFilter, error) {
	filter := walkports.WalkFilter{Limit: limit, Offset: offset, LatestOnly: latest}
	if targetArg != "" {
		coord, cerr := parseCoordinate(targetArg)
		if cerr != nil {
			return walkports.WalkFilter{}, &moduleFilterError{flag: "module", value: targetArg, err: cerr}
		}
		filter.Target = &coord
	}
	if sinceArg != "" {
		t, perr := time.Parse(time.RFC3339, sinceArg)
		if perr != nil {
			return walkports.WalkFilter{}, fmt.Errorf("parsing --since %q: %w", sinceArg, perr)
		}
		filter.Since = &t
	}
	if statusArg != "" {
		st, perr := parseWalkStatus(statusArg)
		if perr != nil {
			return walkports.WalkFilter{}, fmt.Errorf("parsing --status %q: %w", statusArg, perr)
		}
		filter.OverallStatus = &st
	}
	if scopeArg != "" {
		sc, perr := parseWalkScope(scopeArg)
		if perr != nil {
			return walkports.WalkFilter{}, fmt.Errorf("parsing --scope %q: %w", scopeArg, perr)
		}
		filter.Scope = &sc
	}
	return filter, nil
}

// walkListZeroScope lifts every filter and the paging and re-asks the store, so
// a zero distinguishes a store with no walk records from filters that excluded
// all of them, and either from a page that starts past the last record. Reached
// only when the listing came back empty.
//
// Every filter that was set is named together, as license-list names its two:
// dropping one would send the reader to check a value that was not the one that
// excluded their walk.
func walkListZeroScope(ctx context.Context, applied walkports.WalkFilter, offset int, uc QueryWalksUseCase) (listZeroScope, error) {
	all, err := uc.ListWalks(ctx, walkports.WalkFilter{})
	if err != nil {
		return listZeroScope{}, fmt.Errorf("counting walk records for the zero-result notice: %w", err)
	}
	scope := listZeroScope{
		subject:    "walk record",
		considered: len(all),
		produce:    "kanonarion walk <module>@<version>",
		listAll:    "kanonarion walk-list",
	}
	names, values, fields, kinds := describeWalkFilter(applied)
	if len(names) > 0 {
		scope.filterName = strings.Join(names, " and ")
		scope.filterValue = strings.Join(values, " / ")
		scope.field = strings.Join(fields, ", then the ")
		// Identical match kinds are stated once: "compared for exact equality
		// then for exact equality" reads as two different comparisons.
		scope.matchKind = kinds[0]
		for _, k := range kinds[1:] {
			if k != kinds[0] {
				scope.matchKind = strings.Join(kinds, " then ")
				break
			}
		}
	}
	// The illustration has to be in the shape the filter compares against, so it
	// is offered only for a lone target filter; a status or an instant is not a
	// spelling the reader can have got wrong.
	if len(names) == 1 && applied.Target != nil && len(all) > 0 {
		scope.example = all[0].Target.String()
	}
	// An offset past the end empties the page without any filter having anything
	// to do with it, and the two look identical from the rows alone.
	// An empty corpus is not something a page can start past, so a zero over it
	// keeps the store-empty statement and its produce-a-record remedy.
	if scope.filterValue == "" && len(all) > 0 && offset > 0 && offset >= len(all) {
		scope.pagedPast = fmt.Sprintf("--offset %d starts past the last one", offset)
	}
	return scope, nil
}

// describeWalkFilter names each condition the filter applied, its value, the
// field it compares and how.
func describeWalkFilter(applied walkports.WalkFilter) (names, values, fields, kinds []string) {
	if applied.Target != nil {
		names = append(names, "target")
		values = append(values, applied.Target.String())
		fields = append(fields, "target coordinate")
		kinds = append(kinds, matchExact)
	}
	if applied.BuildEnv != nil {
		names = append(names, "platform")
		values = append(values, applied.BuildEnv.String())
		fields = append(fields, "recorded platform")
		kinds = append(kinds, matchExact)
	}
	if applied.Since != nil {
		names = append(names, "start time")
		values = append(values, applied.Since.UTC().Format(time.RFC3339))
		fields = append(fields, "start time")
		kinds = append(kinds, matchLowerBound)
	}
	if applied.OverallStatus != nil {
		names = append(names, "overall status")
		values = append(values, applied.OverallStatus.String())
		fields = append(fields, "overall status")
		kinds = append(kinds, matchExact)
	}
	if applied.Scope != nil {
		names = append(names, "walk scope")
		values = append(values, string(*applied.Scope))
		fields = append(fields, "walk scope")
		kinds = append(kinds, matchExact)
	}
	return names, values, fields, kinds
}

func parseWalkStatus(s string) (domain.WalkStatus, error) {
	switch strings.ToLower(s) {
	case "succeeded":
		return domain.WalkSucceeded, nil
	case "partial":
		return domain.WalkPartial, nil
	case "failed":
		return domain.WalkFailed, nil
	case "cancelled":
		return domain.WalkCancelled, nil
	default:
		return 0, fmt.Errorf("unknown status %q; want succeeded|partial|failed|cancelled", s)
	}
}
func parseWalkScope(s string) (domain.WalkScope, error) {
	switch strings.ToLower(s) {
	case "code":
		return domain.WalkScopeCode, nil
	case "tool":
		return domain.WalkScopeTool, nil
	case "complete":
		return domain.WalkScopeComplete, nil
	default:
		return "", fmt.Errorf("unknown scope %q; want code|tool|complete", s)
	}
}
