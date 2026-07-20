package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/adapters/snippetscan"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// newNoticeCmd returns the 'notice' command that generates a deterministic
// THIRD-PARTY-LICENSES attribution document from stored license records.
func newNoticeCmd(stdout, stderr io.Writer) *cobra.Command {
	var walkID string
	var gomodPath string
	var packagePattern string

	cmd := &cobra.Command{
		Use:   "notice",
		Short: "Generate a THIRD-PARTY-LICENSES attribution document",
		Long: `Generate a deterministic THIRD-PARTY-LICENSES file from stored license records.

The document includes per-module: module coordinate, SPDX identifier, verbatim
license text, and verbatim copyright notices.

Third-party code copied into first-party source is covered too. Such code has
no go.mod entry, so it is invisible to module license extraction; notice scans
first-party Go source for SPDX snippet tags (SPDX-SnippetBegin..SnippetEnd) and
renders each block as a first-class attribution entry.

Modules with Ambiguous or Multiple license status, or a missing copyright
notice, are reported on stderr and cause a non-zero exit — they require human
review before the document can be published. A malformed SPDX snippet block, or
one citing an SPDX identifier with no embedded license text, is the same gate.

Use --package to scope the document to the modules actually linked into a
specific binary. This excludes dev tools, linters, and test-only dependencies
that appear in go.mod but are never distributed.`,
		Example: `  kanonarion notice --package ./cmd/kanonarion
  kanonarion notice --walk-id <id>
  kanonarion notice --gomod ./go.mod`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			flags := 0
			if walkID != "" {
				flags++
			}
			if gomodPath != "" {
				flags++
			}
			if packagePattern != "" {
				flags++
			}
			if flags > 1 {
				return fmt.Errorf("--walk-id, --gomod, and --package are mutually exclusive")
			}
			if flags == 0 {
				var rerr error
				gomodPath, rerr = resolveGoModPath("")
				if rerr != nil {
					return rerr
				}
			}
			return runNotice(cmd.Context(), walkID, gomodPath, packagePattern, snippetRoot(gomodPath), stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&walkID, "walk-id", "", "walk to generate notice for")
	cmd.Flags().StringVar(&gomodPath, "gomod", "", "path to go.mod — the project's code dependencies; prefer --package to scope to a distributed binary")
	cmd.Flags().StringVar(&packagePattern, "package", "", "Go package pattern (e.g. ./cmd/kanonarion); scopes notice to modules linked into that binary")
	return cmd
}

// snippetRoot returns the first-party module directory to scan for SPDX
// snippet blocks. It is the directory holding the resolved go.mod. When no
// go.mod can be resolved — a --walk-id run outside a project checkout — it
// returns "", and the scan is skipped: there is no first-party tree to read.
func snippetRoot(gomodPath string) string {
	resolved, err := resolveGoModPath(gomodPath)
	if err != nil {
		return ""
	}
	dir := filepath.Dir(resolved)
	if abs, aerr := filepath.Abs(dir); aerr == nil {
		return abs
	}
	return dir
}

func runNotice(ctx context.Context, walkID, gomodPath, packagePattern, snippetDir string, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	dbPath := filepath.Join(storeRoot, "mirror.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("store not found at %s: run a kanonarion command to initialise it", dbPath)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return noticeWith(ctx, ctr, walkID, gomodPath, packagePattern, snippetDir, stdout, stderr)
}

// noticeWith holds the notice logic over an injected Container: it resolves the
// module set, refuses to emit the document when any module requires human
// review (failing loudly to stderr with a non-nil error rather than publishing
// an incomplete NOTICE), and otherwise writes the attribution document. Split
// from runNotice so the review-gate contract is testable without a live store.
func noticeWith(ctx context.Context, ctr *Container, walkID, gomodPath, packagePattern, snippetDir string, stdout, stderr io.Writer) error {
	coords, err := resolveNoticeCoords(ctx, walkID, gomodPath, packagePattern, ctr)
	if err != nil {
		return err
	}

	// Third-party code copied into first-party source carries its licence in
	// SPDX snippet tags, not in go.mod. Scan for it before the module-count
	// short-circuit below: a project with no dependencies can still redistribute
	// copied source, and omitting it is exactly the gap this closes.
	snippetEntries, err := collectSnippetEntries(snippetDir)
	if err != nil {
		return err
	}

	if len(coords) == 0 && len(snippetEntries) == 0 {
		if _, werr := fmt.Fprintln(stderr, "no modules found"); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		return nil
	}

	result, err := ctr.GenerateNotice.Generate(ctx, licapp.NoticeRequest{Coordinates: coords})
	if err != nil {
		return fmt.Errorf("generating notice: %w", err)
	}

	// Fail loudly if any modules require review.
	if len(result.ReviewItems) > 0 {
		if _, werr := fmt.Fprintf(stderr, "notice: %d module(s) require human review before publishing:\n\n", len(result.ReviewItems)); werr != nil {
			return fmt.Errorf("writing review header: %w", werr)
		}
		for _, item := range result.ReviewItems {
			if _, werr := fmt.Fprintf(stderr, "  %s: %s\n", item.Coordinate, item.Reason); werr != nil {
				return fmt.Errorf("writing review item: %w", werr)
			}
		}
		return fmt.Errorf("%d module(s) require review", len(result.ReviewItems))
	}

	entries := append(result.Entries, snippetEntries...)
	licensedomain.SortNoticeEntries(entries)
	return writeNoticeDocument(entries, stdout)
}

// collectSnippetEntries scans the first-party tree for SPDX snippet blocks and
// converts them to notice entries. A malformed block or an SPDX identifier with
// no embedded licence text is fatal — the same gate a module with a missing
// copyright notice hits.
func collectSnippetEntries(snippetDir string) ([]licensedomain.NoticeEntry, error) {
	if snippetDir == "" {
		return nil, nil
	}
	atts, err := snippetscan.New(snippetDir).Scan()
	if err != nil {
		return nil, fmt.Errorf("scanning first-party source for SPDX snippets: %w", err)
	}
	if len(atts) == 0 {
		return nil, nil
	}
	entries, err := licensedomain.NoticeEntriesFromSnippets(atts)
	if err != nil {
		return nil, fmt.Errorf("building copied-source attribution: %w", err)
	}
	return entries, nil
}

func resolveNoticeCoords(
	ctx context.Context,
	walkID, gomodPath, packagePattern string,
	ctr *Container,
) ([]fetchdomain.ModuleCoordinate, error) {
	if walkID != "" {
		rec, err := ctr.QueryWalks.GetWalk(ctx, walkID)
		if err != nil {
			return nil, fmt.Errorf("loading walk %s: %w", walkID, err)
		}
		coords := make([]fetchdomain.ModuleCoordinate, 0, len(rec.Graph.Nodes))
		for _, n := range rec.Graph.Nodes {
			coords = append(coords, n.Coordinate)
		}
		return coords, nil
	}

	var (
		coordStrs []string
		err       error
	)
	if packagePattern != "" {
		coordStrs, err = readPackageModules(packagePattern)
	} else {
		// --gomod: the project's code dependencies (consistent with every other
		// go.mod command). --package narrows further to a single binary's import
		// closure, the most precise scope for a distributed NOTICE.
		coordStrs, err = resolveScopeModules(gomodPath, scopeCode)
	}
	if err != nil {
		return nil, err
	}
	coords := make([]fetchdomain.ModuleCoordinate, 0, len(coordStrs))
	for _, s := range coordStrs {
		coord, cerr := parseCoordinate(s)
		if cerr != nil {
			return nil, fmt.Errorf("invalid coordinate %q: %w", s, cerr)
		}
		coords = append(coords, coord)
	}
	return coords, nil
}

const noticeDiv = "================================================================================"

func writeNoticeDocument(entries []licensedomain.NoticeEntry, w io.Writer) error {
	ew := &errWriter{w: w}

	ew.printf("THIRD-PARTY-LICENSES\n\n")
	ew.printf("This project uses the following third-party software.\n\n")

	for _, e := range entries {
		ew.printf("%s\n", noticeDiv)
		if e.EffectiveSource() == licensedomain.NoticeSourceCopied {
			// Copied source is not a linked module: label it so a reader can
			// tell transcribed code from a dependency, and name the first-party
			// files carrying it.
			ew.printf("Copied source: %s\n", e.Name)
			ew.printf("Origin:  %s\n", e.Coordinate)
			ew.printf("Used in: %s\n", strings.Join(e.SourcePaths, ", "))
		} else {
			ew.printf("Module:  %s\n", e.Coordinate)
		}
		ew.printf("License: %s\n", e.SPDX)
		if len(e.Copyrights) > 0 {
			ew.printf("\nCopyright notices:\n")
			for _, c := range e.Copyrights {
				ew.printf("  %s\n", c)
			}
		}
		for _, lf := range e.LicenseTexts {
			if lf.Path == "" {
				ew.printf("\n%s:\n\n", e.SPDX)
			} else {
				ew.printf("\n%s (%s):\n\n", e.SPDX, lf.Path)
			}
			ew.printf("%s\n", lf.Content)
		}
		for _, comp := range e.EmbeddedComponents {
			ew.printf("\nEmbedded component: %s\n", comp.PathPrefix)
			for _, spdx := range comp.SPDXs {
				ew.printf("  License: %s\n", spdx)
			}
			for _, lf := range comp.LicenseTexts {
				ew.printf("\n  %s (%s):\n\n", comp.PathPrefix, lf.Path)
				ew.printf("%s\n", lf.Content)
			}
		}
		ew.printf("\n")
	}

	if len(entries) > 0 {
		ew.printf("%s\n", noticeDiv)
	}

	return ew.err
}
