package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	"github.com/eitanity/kanonarion/internal/adapters/clock"
	sqlite2 "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	noopsigner "github.com/eitanity/kanonarion/internal/adapters/signer/noop"
	"github.com/eitanity/kanonarion/internal/adapters/sumdb/gosum"
	sumdbretry "github.com/eitanity/kanonarion/internal/adapters/sumdb/retrying"
	"github.com/eitanity/kanonarion/internal/adapters/vcs/gitexec"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	"github.com/spf13/cobra"
)

type fetchFlags struct {
	force         bool
	strict        bool
	insecure      bool
	skipVCSVerify bool
	goproxy       string
	listVersions  bool
	tool          bool
	project       bool
	gomod         string
	policyPath    string
	// vcsHosts is the effective VCS forge allowlist, resolved once from the
	// depth policy before any fetch runs. The zero value enforces the built-in
	// default set.
	vcsHosts domain.VCSHostAllowlist
}

func newFetchCmd(stdout, stderr io.Writer) *cobra.Command {
	var f fetchFlags

	cmd := &cobra.Command{
		Use:   "fetch <module>[@<version>]",
		Short: "Fetch, verify, and persist a Go module fact record",
		Example: `  kanonarion fetch github.com/spf13/cobra@v1.8.1
  kanonarion fetch github.com/spf13/cobra@latest
  kanonarion fetch github.com/spf13/cobra --list-versions
  kanonarion fetch github.com/spf13/cobra@v1.8.1 --json
  kanonarion fetch github.com/spf13/cobra@v1.8.1 --force --strict --store-root /var/mirror
  kanonarion fetch --gomod ./go.mod
  kanonarion fetch --gomod ./go.mod --tool`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// The fetch stage's allowed_vcs_hosts governs which forges this
			// command may cross-verify against, so resolve the policy once here
			// rather than per module in the scope loop.
			hosts, herr := resolveFetchVCSHosts(cmd.Context(), f.policyPath, stderr)
			if herr != nil {
				return herr
			}
			f.vcsHosts = hosts

			goModScope := f.gomod != "" || f.tool || f.project
			if goModScope {
				if len(args) > 0 {
					return fmt.Errorf("cannot combine a go.mod scope fetch (--gomod/--tool/--project) with a positional argument")
				}
				if f.listVersions {
					return fmt.Errorf("cannot combine --list-versions with a go.mod scope fetch")
				}
				scope, serr := scopeFromFlags(f.tool, f.project)
				if serr != nil {
					return serr
				}
				gomodPath, err := resolveGoModPath(f.gomod)
				if err != nil {
					return err
				}
				return runFetchScope(cmd.Context(), gomodPath, scope, f, stdout, stderr)
			}
			if len(args) == 0 {
				return usageErr(cmd)
			}
			if len(args) > 1 {
				return fmt.Errorf("accepts 1 arg, received %d", len(args))
			}
			return runFetch(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&f.force, "force", false, "re-fetch even if cached")
	registerAllowVerificationDowngradeFlag(cmd)
	cmd.Flags().BoolVar(&f.strict, "strict", false, "exit non-zero on verification failure")
	cmd.Flags().BoolVar(&f.insecure, "insecure", false, "allow plain HTTP proxy URLs (forces unverified status)")
	cmd.Flags().BoolVar(&f.skipVCSVerify, "skip-vcs-verify", false, "skip git cross-verification; sumdb verification still runs")
	cmd.Flags().StringVar(&f.goproxy, "goproxy", "", "override GOPROXY (default: $GOPROXY or proxy.golang.org)")
	cmd.Flags().BoolVar(&f.listVersions, "list-versions", false, "list available versions from the proxy and exit without fetching")
	cmd.Flags().BoolVar(&f.tool, "tool", false, "fetch the tooling supply chain (the go.mod tool directives' closure) instead of a positional module@version")
	cmd.Flags().BoolVar(&f.project, "project", false, "fetch the complete set: the project's code AND tooling")
	cmd.Flags().StringVar(&f.gomod, "gomod", "", "path to a go.mod file to fetch a dependency scope from (default: search upward from cwd)")
	cmd.Flags().StringVar(&f.policyPath, "policy", "", "path to depth policy YAML (default: search for .kanonarion/policy.yaml)")

	return cmd
}

// resolveFetchVCSHosts resolves the effective VCS forge allowlist for a fetch
// from the depth policy's fetch stage. An absent policy, or a policy without
// allowed_vcs_hosts, yields the built-in default set; a malformed list is an
// error rather than a silent fall-back to the default, which would verify
// against forges the operator did not authorise.
func resolveFetchVCSHosts(ctx context.Context, policyPath string, stderr io.Writer) (domain.VCSHostAllowlist, error) {
	logger := buildLogger(logLevel, stderr)
	policy, _, err := loadPolicy(ctx, policyPath, logger)
	if err != nil {
		return domain.VCSHostAllowlist{}, fmt.Errorf("loading policy: %w", err)
	}
	hosts, err := policy.FetchStage().VCSHostAllowlist()
	if err != nil {
		return domain.VCSHostAllowlist{}, fmt.Errorf("resolving fetch-stage VCS host allowlist: %w", err)
	}
	return hosts, nil
}

// runFetchScope fetches every module in a go.mod's dependency scope (default
// code, or --tool / --project), continuing on per-module errors.
func runFetchScope(ctx context.Context, gomodPath string, scope depScope, f fetchFlags, stdout, stderr io.Writer) error {
	coords, err := resolveScopeModules(gomodPath, scope)
	if err != nil {
		return fmt.Errorf("resolving %s scope: %w", scope, err)
	}
	if len(coords) == 0 {
		// Diagnostic, not data: keep stdout clean so a --json caller reading
		// the per-module object stream is not handed prose on an empty scope.
		_, _ = fmt.Fprintf(stderr, "no %s dependencies found in %s\n", scope, gomodPath)
		return nil
	}
	_, _ = fmt.Fprintf(stderr, "fetching %d %s modules from %s\n", len(coords), scope, gomodPath)
	var errs []error
	for _, coord := range coords {
		if ferr := fetchOne(ctx, coord, f, stdout, stderr); ferr != nil {
			_, _ = fmt.Fprintf(stderr, "fetch %s: %v\n", coord, ferr)
			errs = append(errs, fmt.Errorf("%s: %w", coord, ferr))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d fetches failed", len(errs), len(coords))
	}
	return nil
}

// runFetch fetches the single module named positionally. The go.mod scope
// flags select the other path entirely, so a positional fetch refuses them by
// name rather than parsing and dropping them; the scope loop calls fetchOne
// directly, where they have already been acted on.
func runFetch(ctx context.Context, arg string, f fetchFlags, stdout, stderr io.Writer) error {
	if err := refuseInapplicableFlags("fetch <module>[@<version>]", fetchGoModOnlyFlags(f)); err != nil {
		return err
	}
	return fetchOne(ctx, arg, f, stdout, stderr)
}

func fetchOne(ctx context.Context, arg string, f fetchFlags, stdout, stderr io.Writer) (err error) {
	logger := buildLogger(logLevel, stderr)

	path, version, err := parseModuleArg(arg)
	if err != nil {
		return fmt.Errorf("invalid argument %q: %w", arg, err)
	}

	proxyAdapter, err := proxyadapter.New(f.goproxy, f.insecure)
	if err != nil {
		return proxyAdapterError(err)
	}

	if f.listVersions {
		return runListVersions(ctx, path, jsonOut, proxyAdapter, stdout)
	}

	if version == "" {
		return fmt.Errorf("version required: use %s@<version> or %s@latest", path, path)
	}

	var coord coordinate.ModuleCoordinate
	if version == "latest" {
		coord, err = resolveLatest(ctx, path, proxyAdapter, stderr)
		if err != nil {
			return err
		}
	} else {
		coord, err = coordinate.NewModuleCoordinate(path, version)
		if err != nil {
			return fmt.Errorf("invalid coordinate %q: %w", arg, err)
		}
	}

	vcsClient := gitexec.New()
	blobStore := localfs.New(storeRoot)

	dbPath := storeRoot + "/mirror.db"
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		return fmt.Errorf("creating store root: %w", err)
	}
	rawStore, err := sqlite2.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening fact store: %w", err)
	}
	factStore, err := sqlite2.NewAuditingStore(rawStore, storeRoot+"/audit.jsonl")
	if err != nil {
		return fmt.Errorf("creating auditing store: %w", err)
	}
	defer func() {
		if cerr := factStore.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing fact store: %w", cerr)
		}
	}()

	// Retry transient checksum-database failures before they can downgrade the
	// module's verification status, matching the walk path's wiring.
	sumdbClient := sumdbretry.New(gosum.New(storeRoot+"/sumdb"), logger)
	clk := clock.System{}

	uc := application.NewFetchModuleUseCase(
		proxyAdapter, vcsClient, blobStore, factStore,
		sumdbClient, clk, clock.Monotonic{}, "", logger,
	).WithSigner(noopsigner.New(), factStore).
		WithAudit(factStore).
		WithAllowVerificationDowngrade(allowVerificationDowngrade)

	result, err := uc.Execute(ctx, application.FetchRequest{
		Coordinate:    coord,
		Force:         f.force,
		SkipVCSVerify: f.skipVCSVerify,
		VCSHosts:      f.vcsHosts,
	})
	if err != nil {
		return fmt.Errorf("fetching module: %w", err)
	}

	// Check staleness for pinned versions. The proxy call is fast relative to
	// the fetch itself and the result is informative for both humans and agents.
	stale := fetchStalenessFor(ctx, proxyAdapter, coord, version, stderr)

	if jsonOut {
		type fetchOutput struct {
			Record    any           `json:"record"`
			Staleness stalenessInfo `json:"staleness"`
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(fetchOutput{Record: result.Record, Staleness: stale}); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
	} else {
		status := result.Record.VerificationStatus
		cached := ""
		if result.FromCache {
			cached = " (cached)"
		}
		retracted := ""
		if result.Record.Retracted {
			retracted = " [RETRACTED]"
		}
		resolved := ""
		if version == "latest" {
			resolved = " (resolved from @latest)"
		}
		stalenessNote := fetchStalenessNote(stale)
		if _, err := fmt.Fprintf(stdout, "%s: %s%s%s%s%s\n", coord.String(), status, retracted, resolved, cached, stalenessNote); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		if result.Record.VerificationDetail != "" {
			if _, err := fmt.Fprintf(stdout, "  detail: %s\n", result.Record.VerificationDetail); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
		}
	}

	if f.strict && result.Record.VerificationStatus != string(domain.Verified) {
		return fmt.Errorf("verification failed: %s", result.Record.VerificationStatus)
	}
	return nil
}

// stalenessInfo is the `staleness` block of `fetch --json`, and the note beside
// the text line. It is OUTPUT ONLY: nothing here is persisted or hashed — the
// fetch record the run seals is result.Record, which this type never touches —
// so stating an unmeasured column costs no migration and no pipeline version.
type stalenessInfo struct {
	// IsLatest is null when the comparison was not made: a lookup that failed, or
	// an @latest fetch, which resolves the newest version and therefore has no pin
	// to be behind. It used to default to true through both, so a failed lookup
	// and an unasked question both reported the module as current.
	IsLatest *bool `json:"is_latest"`
	// PinAheadOfLatest is true when the requested version sorts ABOVE the
	// newest version published at this path, which is not an upgrade to offer
	// and carries no DaysSince.
	//
	// Emitted on every block, false included, so "measured, and not in that
	// state" is distinguishable from "this build does not derive the field"; a
	// POINTER, and null wherever IsLatest is null, because an unmeasured block
	// made no comparison and a bare false there would be an answer to a
	// question nobody put.
	PinAheadOfLatest *bool `json:"pin_ahead_of_latest"`
	// Unmeasured names why IsLatest is null, from the vocabulary shared with
	// `audit` and `latest` (see staleness.go). Absent on a measured row, which
	// keeps a measured block byte-identical to what it has always emitted.
	Unmeasured    string `json:"staleness_unmeasured,omitempty"`
	LatestVersion string `json:"latest_version,omitempty"`
	// DaysSince is the age of LatestVersion, and shares LatestReleaseAgeDays'
	// shape for the same reason: zero is a real answer — a release that shipped
	// today — and under `omitempty` it was erased, so "released today" and "no
	// publication date" were the same absence. It is emitted on every block,
	// 0 included.
	//
	// Null means there is no age here, which on this surface has three causes,
	// each of them read off the two fields above rather than off this one: the
	// pin is current (IsLatest true, and `fetch` has never reported an age for a
	// coordinate that is not behind), the pin is ahead (PinAheadOfLatest true,
	// no distance to offer), or the proxy supplied no publication date (both
	// false). Null is never a fabricated "released today".
	DaysSince *int `json:"days_since_latest"`
}

// latestInfoLookup asks the proxy for a module path's newest version. The proxy
// adapter satisfies it; narrowing the dependency here is what lets the failed
// lookup — the case whose rendering this exists to fix — be exercised.
type latestInfoLookup interface {
	LatestInfo(ctx context.Context, path string) (proxyadapter.LatestVersionInfo, error)
}

// fetchStalenessFor answers "is the fetched coordinate the newest version", or
// states that it did not.
//
// requestedVersion is what the user wrote, not what was resolved: "@latest" is
// the never-asked case even though the coordinate it produced is pinned.
func fetchStalenessFor(ctx context.Context, proxy latestInfoLookup, coord coordinate.ModuleCoordinate, requestedVersion string, stderr io.Writer) stalenessInfo {
	if requestedVersion == "latest" {
		return stalenessInfo{Unmeasured: stalenessNotAsked}
	}
	info, lerr := proxy.LatestInfo(ctx, coord.Path())
	if lerr != nil || info.Version == "" {
		// An empty version with no error is the same absence as an error: there
		// is no version to compare the pin against, so there is no comparison.
		if lerr != nil {
			_, _ = fmt.Fprintf(stderr, "staleness %s: %v\n", coord.Path(), lerr)
		}
		return stalenessInfo{Unmeasured: stalenessLookupFailed}
	}
	// Placed with semver, not string equality, for the same reason the audit and
	// latest rows are: a pin can sort ABOVE @latest, and string equality has no
	// third outcome to put that in.
	pos := staledomain.ComparePin(coord.Version(), info.Version)
	isLatest := pos == staledomain.PinLevel
	ahead := pos == staledomain.PinAhead
	out := stalenessInfo{IsLatest: &isLatest, PinAheadOfLatest: &ahead}
	if !isLatest {
		out.LatestVersion = info.Version
		// The age is only recorded where it means "how long you have been
		// behind"; a pin ahead of the latest tag is behind nothing.
		if pos == staledomain.PinBehind {
			out.DaysSince = latestReleaseAgeDays(info.Time)
		}
	}
	return out
}

// fetchStalenessNote renders the clause the text line carries after the
// verification status. A current pin adds nothing — silence there means
// "measured, and current", which the unmeasured cases must therefore not
// borrow: they say so in words.
func fetchStalenessNote(stale stalenessInfo) string {
	if stale.IsLatest == nil {
		return " [staleness " + stalenessUnmeasuredLabel(stale.Unmeasured) + "]"
	}
	if *stale.IsLatest {
		return ""
	}
	if stale.PinAheadOfLatest != nil && *stale.PinAheadOfLatest {
		return fmt.Sprintf(" [ahead of latest tag: %s]", stale.LatestVersion)
	}
	if stale.DaysSince == nil {
		// A newer version with no publication date: named without an invented
		// age, where it used to read "released today".
		return fmt.Sprintf(" [latest: %s]", stale.LatestVersion)
	}
	if *stale.DaysSince == 0 {
		return fmt.Sprintf(" [latest: %s, released today]", stale.LatestVersion)
	}
	return fmt.Sprintf(" [latest: %s, %d days ago]", stale.LatestVersion, *stale.DaysSince)
}

// latestResolver resolves a module path's @latest to a pinned coordinate. The
// concrete proxy adapter satisfies it; narrowing the dependency here lets the
// resolution logic be tested without a live proxy.
type latestResolver interface {
	Latest(ctx context.Context, path string) (coordinate.ModuleCoordinate, error)
}

// versionLister lists a module path's published versions. The concrete proxy
// adapter satisfies it; see latestResolver for the rationale.
type versionLister interface {
	ListVersions(ctx context.Context, path string) ([]string, error)
}

// resolveLatest calls the proxy to resolve @latest to a pinned coordinate,
// prints the resolution to stderr, and returns the pinned coordinate.
// It is called by both fetch and walk before any store operations.
func resolveLatest(ctx context.Context, path string, proxy latestResolver, stderr io.Writer) (coordinate.ModuleCoordinate, error) {
	coord, err := proxy.Latest(ctx, path)
	if err != nil {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("resolving %s@latest: %w", path, err)
	}
	if _, wErr := fmt.Fprintf(stderr, "resolved %s@latest → %s\n", path, coord.Version()); wErr != nil {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("writing output: %w", wErr)
	}
	return coord, nil
}

// runListVersions queries the proxy for all known versions of path and prints
// them newest-first. With jsonOut the result is a JSON array.
func runListVersions(ctx context.Context, path string, jsonOut bool, proxy versionLister, stdout io.Writer) error {
	versions, err := proxy.ListVersions(ctx, path)
	if err != nil {
		return fmt.Errorf("listing versions for %s: %w", path, err)
	}
	// The empty case is answered on the caller's own channel: under --json an
	// empty array, never a human sentence that fails to parse. Only the text
	// path gets the prose.
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if versions == nil {
			versions = []string{}
		}
		if encErr := enc.Encode(versions); encErr != nil {
			return fmt.Errorf("encoding JSON: %w", encErr)
		}
		return nil
	}
	if len(versions) == 0 {
		if _, wErr := fmt.Fprintf(stdout, "no versions found for %s\n", path); wErr != nil {
			return fmt.Errorf("writing output: %w", wErr)
		}
		return nil
	}
	for _, v := range versions {
		if _, wErr := fmt.Fprintln(stdout, v); wErr != nil {
			return fmt.Errorf("writing output: %w", wErr)
		}
	}
	return nil
}
