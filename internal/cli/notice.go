package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/oklog/ulid/v2"
	"github.com/spf13/cobra"

	"github.com/eitanity/kanonarion/internal/license/adapters/snippetscan"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// newNoticeCmd returns the 'notice' command that generates a deterministic
// THIRD-PARTY-LICENSES attribution document from stored license records.
// noticeFlags holds every flag the notice command registers. They live in one
// struct, rather than in a local variable each, so that a flag a dispatch path
// never receives is visible per field rather than only as a missing argument.
type noticeFlags struct {
	walkID         string
	gomodPath      string
	packagePattern string
	output         string
}

// newNoticeCmd builds the attribution command.
//
// It renders one form and only one: the THIRD-PARTY-LICENSES text document,
// which is the deliverable artefact rather than a rendering of something else.
// The global --json flag is a documented no-op here and returns the same bytes,
// by decision and not by omission — an attribution document has no separate
// machine-readable projection, and the data behind it is already served by
// license-list --json and by sbom. Do not add one.
func newNoticeCmd(stdout, stderr io.Writer) *cobra.Command {
	var f noticeFlags

	cmd := &cobra.Command{
		Use: "notice [<walk-id>]",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Generate a THIRD-PARTY-LICENSES attribution document",
		Long: `Generate a deterministic THIRD-PARTY-LICENSES file from stored license records.

The document includes per-module: module coordinate, SPDX identifier, verbatim
license text, and verbatim copyright notices.

The 'License:' line names the module's primary identifier. A module governed by
more than one grant carries a second 'License expression:' line with the full
SPDX expression, emitted only where it says something the primary does not.

Each licence block is headed by what the detector identified in THAT FILE, not
by the module's identifier. A file the detector could not classify is recorded
— path, size, hash, and any low-confidence fragment — and its content is not
reproduced: bytes with no identified grant are not a grant. A NOTICE file is
reproduced regardless, labelled as a notice, because Apache-2.0 section 4(d)
requires it to travel with the work.

Bundled components under directories the Go toolchain never compiles —
testdata, and "_"- or "."-prefixed directories, at any depth — are not
components of the artefact and are excluded. An examples directory and a nested
vendor directory ARE compiled, and stay.

Third-party code copied into first-party source is covered too. Such code has
no go.mod entry, so it is invisible to module license extraction; notice scans
first-party Go source for SPDX snippet tags (SPDX-SnippetBegin..SnippetEnd) and
renders each block as a first-class attribution entry.

Modules with Ambiguous or Multiple license status, or a missing copyright
notice, are reported on stderr and cause a non-zero exit — they require human
review before the document can be published. A malformed SPDX snippet block, or
one citing an SPDX identifier with no embedded license text, is the same gate.
The review gate exits 5 (policy gate fired on real findings), distinct from 20
(bad invocation), so CI can route it to a human rather than to a build fixer.

Use --package to scope the document to the modules actually linked into a
specific binary. This excludes dev tools, linters, and test-only dependencies
that appear in go.mod but are never distributed.`,
		Example: `  kanonarion notice 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion notice --package ./cmd/kanonarion
  kanonarion notice --walk-id <id>
  kanonarion notice --gomod ./go.mod
  kanonarion notice --walk-id <id> --output THIRD-PARTY-LICENSES`,
		Args: noticeArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				// Both spellings naming a walk is a conflict, not a precedence
				// rule: silently picking one of two scopes is the same defect
				// as silently discarding the argument.
				if f.walkID != "" {
					return fmt.Errorf("walk id given twice: %q positionally and %q via --walk-id; pass it once", args[0], f.walkID)
				}
				f.walkID = args[0]
			}
			flags := 0
			if f.walkID != "" {
				flags++
			}
			if f.gomodPath != "" {
				flags++
			}
			if f.packagePattern != "" {
				flags++
			}
			if flags > 1 {
				return fmt.Errorf("--walk-id, --gomod, and --package are mutually exclusive")
			}
			if flags == 0 {
				var rerr error
				f.gomodPath, rerr = resolveGoModPath("")
				if rerr != nil {
					return rerr
				}
			}
			return runNotice(cmd.Context(), f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.walkID, "walk-id", "", "walk to generate notice for")
	cmd.Flags().StringVar(&f.gomodPath, "gomod", "", "path to go.mod — the project's code dependencies; prefer --package to scope to a distributed binary")
	cmd.Flags().StringVar(&f.packagePattern, "package", "", "Go package pattern (e.g. ./cmd/kanonarion); scopes notice to modules linked into that binary")
	cmd.Flags().StringVar(&f.output, "output", "", "write the document to this file (default: stdout)")
	return cmd
}

// noticeArgs accepts at most one positional and only a walk id, refusing
// anything else by name. Without it cobra's default (ArbitraryArgs) accepts and
// discards the argument, and notice falls through to its go.mod scope — a
// confident, exit-coded answer to a question nobody asked. Every sibling command
// (sbom, vuln-scan, extract, walk-show) takes the walk id positionally; notice
// was the exception, and it is the one command where the wrong scope is a legal
// question rather than a reporting one.
func noticeArgs(_ *cobra.Command, args []string) error {
	switch len(args) {
	case 0:
		return nil
	case 1:
		if _, err := ulid.ParseStrict(args[0]); err != nil {
			return fmt.Errorf(
				"%q is not a walk id: notice takes an optional walk id (a 26-character identifier, as 'kanonarion walk-list' prints), "+
					"or --gomod <path> / --package <pattern> to scope from the working tree",
				args[0])
		}
		return nil
	default:
		return fmt.Errorf("notice takes at most one walk id, got %d arguments: %s", len(args), strings.Join(args, " "))
	}
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

func runNotice(ctx context.Context, f noticeFlags, stdout, stderr io.Writer) error {
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

	// The snippet root is the directory holding the resolved go.mod, derived
	// here rather than by the caller so the two scopes it depends on arrive
	// together with the flags that set them.
	return noticeWith(ctx, ctr, f.walkID, f.gomodPath, f.packagePattern, snippetRoot(f.gomodPath), f.output, stdout, stderr)
}

// noticeWith holds the notice logic over an injected Container: it resolves the
// module set, refuses to emit the document when any module requires human
// review (failing loudly to stderr with a non-nil error rather than publishing
// an incomplete NOTICE), and otherwise writes the attribution document. Split
// from runNotice so the review-gate contract is testable without a live store.
func noticeWith(ctx context.Context, ctr *Container, walkID, gomodPath, packagePattern, snippetDir, output string, stdout, stderr io.Writer) error {
	mods, scope, err := resolveNoticeModules(ctx, walkID, gomodPath, packagePattern, ctr)
	if err != nil {
		return err
	}

	// Name the scope before anything derived from it. A walk scope and a go.mod
	// scope answer different questions and disagree about replaced modules, so
	// an operator reading only the output must be able to tell which one
	// produced the review list without re-deriving the invocation.
	if _, werr := fmt.Fprintf(stderr, "notice: scope: %s (%d module(s))\n", scope, len(mods)); werr != nil {
		return fmt.Errorf("writing scope: %w", werr)
	}

	// Third-party code copied into first-party source carries its licence in
	// SPDX snippet tags, not in go.mod. Scan for it before the module-count
	// short-circuit below: a project with no dependencies can still redistribute
	// copied source, and omitting it is exactly the gap this closes.
	snippetEntries, err := collectSnippetEntries(snippetDir)
	if err != nil {
		return err
	}

	if len(mods) == 0 && len(snippetEntries) == 0 {
		if _, werr := fmt.Fprintln(stderr, "no modules found"); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		return nil
	}

	coords, replaced, localReviews := partitionNoticeModules(mods)

	result, err := ctr.GenerateNotice.Generate(ctx, licapp.NoticeRequest{
		Coordinates:  coords,
		Declarations: noticeDeclarations(ctr.Config),
	})
	if err != nil {
		return fmt.Errorf("generating notice: %w", err)
	}

	// Fail loudly if any modules require review.
	reviews := make([]licensedomain.ReviewItem, 0, len(localReviews)+len(result.ReviewItems))
	reviews = append(reviews, localReviews...)
	reviews = append(reviews, result.ReviewItems...)
	sort.SliceStable(reviews, func(i, j int) bool { return reviews[i].Coordinate.String() < reviews[j].Coordinate.String() })
	if len(reviews) > 0 {
		if _, werr := fmt.Fprintf(stderr, "notice: %d module(s) require human review before publishing:\n\n", len(reviews)); werr != nil {
			return fmt.Errorf("writing review header: %w", werr)
		}
		for _, item := range reviews {
			name := item.Coordinate.String()
			if orig, ok := replaced[item.Coordinate]; ok {
				name = fmt.Sprintf("%s (replaces %s)", name, orig)
			}
			if _, werr := fmt.Fprintf(stderr, "  %s: %s\n", name, item.Reason); werr != nil {
				return fmt.Errorf("writing review item: %w", werr)
			}
		}
		if werr := writeCopyrightRemedy(reviews, stderr); werr != nil {
			return werr
		}
		return &exitError{code: ExitPolicy, msg: fmt.Sprintf("%d module(s) require review", len(reviews))}
	}

	entries := append(append([]licensedomain.NoticeEntry{}, result.Entries...), snippetEntries...)
	licensedomain.SortNoticeEntries(entries)

	// The document is rendered into memory before --output so a render failure
	// cannot leave a half-written NOTICE on disk that looks publishable. The
	// stdout path streams as before.
	if output == "" {
		return writeNoticeDocument(entries, replaced, stdout)
	}
	var doc bytes.Buffer
	if werr := writeNoticeDocument(entries, replaced, &doc); werr != nil {
		return werr
	}
	// The acknowledgement goes to stderr, not stdout: an operator capturing the
	// document redirects stdout, and notice already reports scope and the review
	// list on stderr, so the two streams stay one document and one commentary.
	return writeArtefactFile("NOTICE", output, doc.Bytes(), stderr)
}

// noticeDeclarations builds the operator's recorded copyrights from the loaded
// configuration. The config context keeps its values primitive, so the mapping
// to the licence domain's set happens here, at the one place both are in scope.
func noticeDeclarations(cfg domain.Config) licensedomain.CopyrightDeclarationSet {
	if len(cfg.CopyrightDeclarations) == 0 {
		return licensedomain.CopyrightDeclarationSet{}
	}
	entries := make(map[string]licensedomain.CopyrightDeclaration, len(cfg.CopyrightDeclarations))
	for key, d := range cfg.CopyrightDeclarations {
		entries[key] = licensedomain.CopyrightDeclaration{
			Copyright:  d.Copyright,
			DeclaredBy: d.DeclaredBy,
			DeclaredOn: d.DeclaredOn,
			Basis:      d.Basis,
		}
	}
	return licensedomain.NewCopyrightDeclarationSet(entries)
}

// writeCopyrightRemedy names the way out of a missing-copyright refusal, so the
// operator is not left with a correct refusal and no next step. It is printed
// only when a missing copyright is among the reasons: it is no remedy for an
// ambiguous licence or a local-path replace, and offering it there would send an
// operator to record an attribution that changes nothing.
func writeCopyrightRemedy(reviews []licensedomain.ReviewItem, stderr io.Writer) error {
	first := ""
	for _, item := range reviews {
		if item.MissingCopyright {
			first = item.Coordinate.Path()
			break
		}
	}
	if first == "" {
		return nil
	}
	const remedy = `
notice: where the module genuinely carries no copyright, read the upstream
notice: repository and record what you found in <store-root>/config.yaml:
notice:
notice:   copyright_declarations:
notice:     %s:
notice:       copyright: "Copyright <year> <holder>"
notice:       declared_by: "you@example.com"
notice:       declared_on: "YYYY-MM-DD"
notice:       basis: "the upstream file or page you read, and when"
notice:
notice: The key may be pinned to a version ("path@version"). An extracted notice
notice: always wins: a declaration beside one is kept as corroboration, never as
notice: a replacement.
`
	if _, err := fmt.Fprintf(stderr, remedy, first); err != nil {
		return fmt.Errorf("writing review remedy: %w", err)
	}
	return nil
}

// partitionNoticeModules splits the resolved scope into the coordinates the
// generator can attribute, the require entry each replacement stands in for, and
// the review items for modules that have no attributable coordinate at all.
//
// A local-path replace is the second kind: the code that builds is a directory
// on this machine, so there is no fetchable coordinate to look a licence up
// under. Handing the upstream require entry to the generator instead would
// attribute a licence and copyright for code the build never compiles, which is
// the one error a NOTICE exists to prevent — so it is reported for review with
// the path named.
func partitionNoticeModules(mods []noticeModule) (
	[]coordinate.ModuleCoordinate,
	map[coordinate.ModuleCoordinate]coordinate.ModuleCoordinate,
	[]licensedomain.ReviewItem,
) {
	coords := make([]coordinate.ModuleCoordinate, 0, len(mods))
	replaced := make(map[coordinate.ModuleCoordinate]coordinate.ModuleCoordinate)
	var reviews []licensedomain.ReviewItem
	for _, m := range mods {
		if m.localPath != "" {
			reviews = append(reviews, licensedomain.ReviewItem{
				Coordinate: m.original,
				Reason: fmt.Sprintf(
					"replaced by local path %s: what builds is that directory, not this coordinate — attribute it by hand",
					m.localPath),
			})
			continue
		}
		coords = append(coords, m.coord)
		if m.original.Path() != "" {
			replaced[m.coord] = m.original
		}
	}
	return coords, replaced, reviews
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

// noticeModule is one module the document must account for: the coordinate whose
// code actually compiles into the target, plus the require entry a replace
// directive acted on when there was one. The two are carried together rather
// than one instead of the other — a NOTICE attributes the code that ships, and a
// reader still needs to see which requirement produced it.
type noticeModule struct {
	// coord is what compiles. It is the zero value only for a local-path
	// replace, which has no fetchable replacement coordinate.
	coord coordinate.ModuleCoordinate
	// original is the require entry a replace acted on; zero when the module
	// was not replaced.
	original coordinate.ModuleCoordinate
	// localPath is the on-disk target of a local-path replace; empty otherwise.
	localPath string
}

// resolveNoticeModules resolves the scope to attribute and a human-readable name
// for it. All three branches resolve to the coordinates that COMPILE: a replaced
// requirement is reported under its replacement, because attributing the module
// that was replaced away cites the upstream project's licence and copyright for
// code that is not distributed.
func resolveNoticeModules(
	ctx context.Context,
	walkID, gomodPath, packagePattern string,
	ctr *Container,
) ([]noticeModule, string, error) {
	if walkID != "" {
		rec, err := ctr.QueryWalks.GetWalk(ctx, walkID)
		if err != nil {
			return nil, "", fmt.Errorf("loading walk %s: %w", walkID, err)
		}
		mods := make([]noticeModule, 0, len(rec.Graph.Nodes))
		for _, n := range rec.Graph.Nodes {
			if n.ResolutionSource == walkdomain.ResolutionLocalReplace {
				// Such a node keeps the original require as its Coordinate:
				// no fetchable replacement exists, and LocalPath records what
				// the build actually compiles.
				mods = append(mods, noticeModule{original: n.Coordinate, localPath: n.LocalPath})
				continue
			}
			mods = append(mods, noticeModule{coord: n.Coordinate, original: n.OriginalCoordinate})
		}
		return mods, "walk " + walkID, nil
	}

	if packagePattern != "" {
		// --package narrows to a single binary's import closure, the most
		// precise scope for a distributed NOTICE.
		mods, err := goListNoticeModules("", []string{packagePattern}, false)
		return mods, "package " + packagePattern, err
	}
	// --gomod: the project's code dependencies (consistent with every other
	// go.mod command).
	mods, err := goListNoticeModules(filepath.Dir(gomodPath), []string{"./..."}, true)
	return mods, "go.mod " + gomodPath, err
}

// noticeModuleFmt is the `go list -f` template emitting one tab-separated record
// per package: the coordinate that compiles, the require entry a replace acted
// on, and the on-disk target of a local-path replace.
//
// `go list`'s .Module.Path and .Module.Version are the REQUIRE entry; for a
// replaced module the code that compiles is .Module.Replace. The plain
// "{{.Module.Path}}@{{.Module.Version}}" template the shared scope helpers use
// therefore names a module the build never compiles, which is harmless for a
// coverage question and wrong for an attribution one. Standard-library packages
// and the main module emit an all-empty record and are dropped on parse.
const noticeModuleFmt = `{{if and .Module (not .Standard)}}{{with .Module}}` +
	`{{if .Replace}}` +
	`{{if .Replace.Version}}{{.Replace.Path}}@{{.Replace.Version}}{{end}}` + "\t" +
	`{{.Path}}@{{.Version}}` + "\t" +
	`{{if not .Replace.Version}}{{.Replace.Path}}{{end}}` +
	`{{else}}` +
	`{{if .Version}}{{.Path}}@{{.Version}}{{end}}` + "\t\t" +
	`{{end}}{{end}}{{end}}`

// goListNoticeModules runs `go list -deps [-test] <patterns>` in dir and returns
// the de-duplicated, sorted modules the patterns compile against, replacements
// applied.
func goListNoticeModules(dir string, patterns []string, withTest bool) ([]noticeModule, error) {
	args := []string{"list", "-deps"}
	if withTest {
		args = append(args, "-test")
	}
	args = append(args, "-f", noticeModuleFmt)
	args = append(args, patterns...)
	out, err := runGoList(dir, args)
	if err != nil {
		return nil, err
	}
	return parseNoticeModuleRecords(out)
}

// parseNoticeModuleRecords turns the raw noticeModuleFmt output into modules. It
// is split from the toolchain call so the record shapes — plain, replaced, and
// local-path replaced — are testable without a module tree on disk.
func parseNoticeModuleRecords(out []byte) ([]noticeModule, error) {
	seen := make(map[string]bool)
	var records []string
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(strings.ReplaceAll(line, "\t", "")) == "" || seen[line] {
			continue
		}
		seen[line] = true
		records = append(records, line)
	}
	sort.Strings(records)

	mods := make([]noticeModule, 0, len(records))
	for _, rec := range records {
		fields := strings.Split(rec, "\t")
		if len(fields) != 3 {
			return nil, fmt.Errorf("go list emitted an unreadable module record %q: expected three tab-separated fields", rec)
		}
		m := noticeModule{localPath: fields[2]}
		if fields[0] != "" {
			coord, cerr := parseCoordinate(fields[0])
			if cerr != nil {
				return nil, fmt.Errorf("invalid coordinate %q: %w", fields[0], cerr)
			}
			m.coord = coord
		}
		if fields[1] != "" {
			orig, cerr := parseCoordinate(fields[1])
			if cerr != nil {
				return nil, fmt.Errorf("invalid coordinate %q: %w", fields[1], cerr)
			}
			m.original = orig
		}
		mods = append(mods, m)
	}
	return mods, nil
}

// writeNoticeLicenseFile renders one file's attribution block, headed by what
// the pipeline identified IN THAT FILE. It is never headed by the module's
// primary identifier: a file the detector could not classify carries no
// identifier, and labelling it with the module's asserts a grant the bytes do
// not make.
//
// prefix is the embedded component's path prefix, or "" for a root-level file.
func writeNoticeLicenseFile(ew *errWriter, prefix string, lf licensedomain.NoticeLicenseFile) {
	indent := ""
	label := lf.SPDX
	if prefix != "" {
		indent = "  "
		label = prefix
	}

	switch lf.Classification {
	case licensedomain.ClassificationNotice:
		ew.printf("\n%sNotice file (%s):\n\n", indent, lf.Path)
		ew.printf("%s\n", lf.Content)

	case licensedomain.ClassificationUnclassified:
		// Recorded, not reproduced: enough for a reader to fetch the bytes
		// from the module archive and judge them, without this document
		// presenting them as a licence it cannot name.
		ew.printf("\n%sUnclassified (%s):\n\n", indent, lf.Path)
		ew.printf("%s  the licence detector identified no licence in this file; its content is not reproduced here\n", indent)
		ew.printf("%s  %d bytes, %s\n", indent, lf.FileSize, lf.FileHash)
		if lf.LowConfidenceSPDX != "" {
			ew.printf("%s  low-confidence match: %s (%.0f%% coverage)\n",
				indent, lf.LowConfidenceSPDX, lf.LowConfidenceCoverage*100)
		}

	case licensedomain.ClassificationLicence:
		fallthrough
	default:
		if lf.Path == "" {
			ew.printf("\n%s%s:\n\n", indent, label)
		} else {
			ew.printf("\n%s%s (%s):\n\n", indent, label, lf.Path)
		}
		ew.printf("%s\n", lf.Content)
	}
}

// writeNoticeDeclaration renders the operator's recorded copyright, saying which
// of the two things it is: the attribution itself, where extraction found
// nothing, or corroboration standing beside a measured notice.
//
// It is never merged into the "Copyright notices:" list. A reader building an
// obligations list must be able to tell a line taken from the module archive
// from a line a person asserted, and the provenance is what makes the second
// kind checkable at all.
func writeNoticeDeclaration(ew *errWriter, e licensedomain.NoticeEntry) {
	if e.Declaration == nil {
		return
	}
	d := e.Declaration
	if e.DeclarationAttributes() {
		ew.printf("\nCopyright notices (human-supplied; none found in the module):\n")
	} else {
		ew.printf("\nHuman-supplied copyright (corroboration; the extracted notice above is authoritative):\n")
	}
	ew.printf("  %s\n", d.Copyright)
	ew.printf("    declared by %s on %s\n", d.DeclaredBy, d.DeclaredOn)
	ew.printf("    basis: %s\n", d.Basis)
}

const noticeDiv = "================================================================================"

func writeNoticeDocument(
	entries []licensedomain.NoticeEntry,
	replaced map[coordinate.ModuleCoordinate]coordinate.ModuleCoordinate,
	w io.Writer,
) error {
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
			// A replace directive redirected a requirement here. The document
			// attributes what ships, and names the requirement it stands in
			// for so a reader can reconcile it against go.mod.
			if orig, ok := replaced[e.Coordinate]; ok {
				ew.printf("Replaces: %s\n", orig)
			}
		}
		ew.printf("License: %s\n", e.SPDX)
		// The primary alone understates a module governed by several grants.
		// The extra line is emitted only where the expression says something
		// the primary does not: this document is read by a person building an
		// obligations list, and "License: MIT / Expression: MIT" on every
		// single-licence module trains that reader to skip the line that
		// matters. Additive by design — the License: line keeps its meaning
		// for anything already parsing it.
		if e.Expression != "" && e.Expression != e.SPDX {
			ew.printf("License expression: %s\n", e.Expression)
		}
		if len(e.Copyrights) > 0 {
			ew.printf("\nCopyright notices:\n")
			for _, c := range e.Copyrights {
				ew.printf("  %s\n", c)
			}
		}
		writeNoticeDeclaration(ew, e)
		for _, lf := range e.LicenseTexts {
			writeNoticeLicenseFile(ew, "", lf)
		}
		for _, comp := range e.EmbeddedComponents {
			ew.printf("\nEmbedded component: %s\n", comp.PathPrefix)
			for _, spdx := range comp.SPDXs {
				ew.printf("  License: %s\n", spdx)
			}
			for _, lf := range comp.LicenseTexts {
				writeNoticeLicenseFile(ew, comp.PathPrefix, lf)
			}
		}
		ew.printf("\n")
	}

	if len(entries) > 0 {
		ew.printf("%s\n", noticeDiv)
	}

	return ew.err
}
