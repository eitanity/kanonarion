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
)

type latestFlags struct {
	gomodPath string
	goproxy   string
	tool      bool
	project   bool
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

Without --gomod, one or more module paths may be passed as positional
arguments; with multiple modules, --json emits an array.`,
		Example: `  kanonarion latest github.com/spf13/cobra
  kanonarion latest github.com/spf13/cobra github.com/stretchr/testify
  kanonarion latest github.com/spf13/cobra --json
  kanonarion latest --gomod
  kanonarion latest --gomod ./go.mod
  kanonarion latest --gomod ./go.mod --json
  kanonarion latest --gomod ./go.mod --tool`,
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

	return cmd
}

// latestResult is the per-module output record.
type latestResult struct {
	Module     string    `json:"module"`
	Pinned     string    `json:"pinned,omitempty"`
	Latest     string    `json:"latest"`
	LatestDate time.Time `json:"latest_date,omitempty"`
	DaysBehind int       `json:"days_behind"`
	IsLatest   bool      `json:"is_latest"`
}

func runLatest(ctx context.Context, args []string, f latestFlags, stdout, stderr io.Writer) error {
	proxy, err := proxyadapter.New(f.goproxy, false)
	if err != nil {
		return fmt.Errorf("creating proxy adapter: %w", err)
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
		return runLatestGomod(ctx, gomodPath, scope, proxy, stdout, stderr)
	}

	return runLatestModules(ctx, args, proxy, stdout)
}

// runLatestModules resolves one or more module coordinates from positional
// args. Extra positional arguments used to be silently dropped; now
// every module is queried and the output mode is determined by jsonOut and
// arity: a single module renders as a one-line text string or a JSON object,
// multiple modules render as one text line each or a JSON array.
func runLatestModules(ctx context.Context, modules []string, proxy *proxyadapter.Proxy, stdout io.Writer) error {
	results := make([]latestResult, 0, len(modules))
	for _, modulePath := range modules {
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("context cancelled: %w", cerr)
		}
		info, err := proxy.LatestInfo(ctx, modulePath)
		if err != nil {
			return fmt.Errorf("querying latest for %s: %w", modulePath, err)
		}
		results = append(results, latestResult{
			Module:     modulePath,
			Latest:     info.Version,
			LatestDate: info.Time,
			DaysBehind: 0,
			IsLatest:   true,
		})
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
	var writeErr error
	switch {
	case r.LatestDate.IsZero():
		_, writeErr = fmt.Fprintf(stdout, "%s@%s\n", r.Module, r.Latest)
	case days == 0:
		_, writeErr = fmt.Fprintf(stdout, "%s@%s (released today)\n", r.Module, r.Latest)
	default:
		_, writeErr = fmt.Fprintf(stdout, "%s@%s (released %d days ago, %s)\n",
			r.Module, r.Latest, days, r.LatestDate.UTC().Format("2006-01-02"))
	}
	if writeErr != nil {
		return fmt.Errorf("writing output: %w", writeErr)
	}
	return nil
}

func runLatestGomod(ctx context.Context, gomodPath string, scope depScope, proxy *proxyadapter.Proxy, stdout, stderr io.Writer) error {
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
		info, lerr := proxy.LatestInfo(ctx, dep.path)
		if lerr != nil {
			_, _ = fmt.Fprintf(stderr, "latest %s: %v\n", dep.path, lerr)
			results = append(results, latestResult{
				Module: dep.path,
				Pinned: dep.version,
				Latest: "(error)",
			})
			continue
		}

		days := 0
		if !info.Time.IsZero() {
			days = int(time.Since(info.Time).Hours() / 24)
		}
		res := latestResult{
			Module:     dep.path,
			Pinned:     dep.version,
			Latest:     info.Version,
			LatestDate: info.Time,
			IsLatest:   info.Version == dep.version,
		}
		if !res.IsLatest {
			res.DaysBehind = days
		}
		results = append(results, res)
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
	for _, r := range results {
		coord := r.Module + "@" + r.Pinned
		if len(coord) < colWidth {
			coord = fmt.Sprintf("%-*s", colWidth, coord)
		}
		var status string
		switch {
		case r.Latest == "(error)":
			status = "(error resolving latest)"
		case r.IsLatest:
			status = "current"
		case r.DaysBehind == 0:
			status = fmt.Sprintf("latest: %s (released today)", r.Latest)
		default:
			status = fmt.Sprintf("latest: %s (%d days ago)", r.Latest, r.DaysBehind)
		}
		if _, err := fmt.Fprintf(stdout, "%s  %s\n", coord, status); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}
