package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	"github.com/eitanity/kanonarion/internal/adapters/clock"
	sqlite2 "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	noopsigner "github.com/eitanity/kanonarion/internal/adapters/signer/noop"
	"github.com/eitanity/kanonarion/internal/adapters/sumdb/gosum"
	"github.com/eitanity/kanonarion/internal/adapters/vcs/gitexec"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
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
	cmd.Flags().BoolVar(&f.strict, "strict", false, "exit non-zero on verification failure")
	cmd.Flags().BoolVar(&f.insecure, "insecure", false, "allow plain HTTP proxy URLs (forces unverified status)")
	cmd.Flags().BoolVar(&f.skipVCSVerify, "skip-vcs-verify", false, "skip git cross-verification; sumdb verification still runs")
	cmd.Flags().StringVar(&f.goproxy, "goproxy", "", "override GOPROXY (default: $GOPROXY or proxy.golang.org)")
	cmd.Flags().BoolVar(&f.listVersions, "list-versions", false, "list available versions from the proxy and exit without fetching")
	cmd.Flags().BoolVar(&f.tool, "tool", false, "fetch the tooling supply chain (the go.mod tool directives' closure) instead of a positional module@version")
	cmd.Flags().BoolVar(&f.project, "project", false, "fetch the complete set: the project's code AND tooling")
	cmd.Flags().StringVar(&f.gomod, "gomod", "", "path to a go.mod file to fetch a dependency scope from (default: search upward from cwd)")

	return cmd
}

// runFetchScope fetches every module in a go.mod's dependency scope (default
// code, or --tool / --project), continuing on per-module errors.
func runFetchScope(ctx context.Context, gomodPath string, scope depScope, f fetchFlags, stdout, stderr io.Writer) error {
	coords, err := resolveScopeModules(gomodPath, scope)
	if err != nil {
		return fmt.Errorf("resolving %s scope: %w", scope, err)
	}
	if len(coords) == 0 {
		_, _ = fmt.Fprintf(stdout, "no %s dependencies found in %s\n", scope, gomodPath)
		return nil
	}
	_, _ = fmt.Fprintf(stderr, "fetching %d %s modules from %s\n", len(coords), scope, gomodPath)
	var errs []error
	for _, coord := range coords {
		if ferr := runFetch(ctx, coord, f, stdout, stderr); ferr != nil {
			_, _ = fmt.Fprintf(stderr, "fetch %s: %v\n", coord, ferr)
			errs = append(errs, fmt.Errorf("%s: %w", coord, ferr))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d fetches failed", len(errs), len(coords))
	}
	return nil
}

func runFetch(ctx context.Context, arg string, f fetchFlags, stdout, stderr io.Writer) (err error) {
	logger := buildLogger(logLevel, stderr)

	path, version, err := parseModuleArg(arg)
	if err != nil {
		return fmt.Errorf("invalid argument %q: %w", arg, err)
	}

	proxyAdapter, err := proxyadapter.New(f.goproxy, f.insecure)
	if err != nil {
		return fmt.Errorf("creating proxy adapter: %w", err)
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

	sumdbClient := gosum.New(storeRoot + "/sumdb")
	clk := clock.System{}

	uc := application.NewFetchModuleUseCase(
		proxyAdapter, vcsClient, blobStore, factStore,
		sumdbClient, clk, clock.Monotonic{}, "", logger,
	).WithSigner(noopsigner.New(), factStore)

	result, err := uc.Execute(ctx, application.FetchRequest{
		Coordinate:    coord,
		Force:         f.force,
		SkipVCSVerify: f.skipVCSVerify,
	})
	if err != nil {
		return fmt.Errorf("fetching module: %w", err)
	}

	// Check staleness for pinned versions. The proxy call is fast relative to
	// the fetch itself and the result is informative for both humans and agents.
	type stalenessInfo struct {
		IsLatest      bool   `json:"is_latest"`
		LatestVersion string `json:"latest_version,omitempty"`
		DaysSince     int    `json:"days_since_latest,omitempty"`
	}
	stale := stalenessInfo{IsLatest: true}
	if version != "latest" {
		if info, lerr := proxyAdapter.LatestInfo(ctx, coord.Path); lerr == nil && info.Version != coord.Version {
			stale.IsLatest = false
			stale.LatestVersion = info.Version
			if !info.Time.IsZero() {
				stale.DaysSince = int(time.Since(info.Time).Hours() / 24)
			}
		}
	}

	if jsonOut {
		type fetchOutput struct {
			Record    interface{}   `json:"record"`
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
		stalenessNote := ""
		if !stale.IsLatest {
			if stale.DaysSince == 0 {
				stalenessNote = fmt.Sprintf(" [latest: %s, released today]", stale.LatestVersion)
			} else {
				stalenessNote = fmt.Sprintf(" [latest: %s, %d days ago]", stale.LatestVersion, stale.DaysSince)
			}
		}
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
	if _, wErr := fmt.Fprintf(stderr, "resolved %s@latest → %s\n", path, coord.Version); wErr != nil {
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
