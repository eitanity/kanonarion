package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	licapp "github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"github.com/spf13/cobra"
)

type licenseFlags struct {
	force     bool
	recursive bool
	all       bool
	perFile   bool
	history   bool
	// walkID pins the walk --recursive reports the closure of. Empty leaves the
	// choice to the default rule, which states the walk it picked.
	walkID string
}

// -- license extract command --

func newLicenseCmd(stdout, stderr io.Writer) *cobra.Command {
	var f licenseFlags

	cmd := &cobra.Command{
		Use: "license <module>@<version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentCreate,
			annotationNetworkUse:  NetworkNever,
		},
		// The docs and the store speak British English; accept both spellings so
		// neither the documented form nor the SPDX-conventional one is wrong.
		Aliases: []string{"licence"},
		Short:   "Extract and persist license information for a Go module",
		Example: `  kanonarion license github.com/spf13/cobra@v1.8.1
  kanonarion license github.com/spf13/cobra@v1.8.1 --json
  kanonarion license github.com/spf13/cobra@v1.8.1 --force
  kanonarion license example.com/project@local --recursive --walk-id 01KZ42BGN0T95D932JMC1GXX3C`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageErr(cmd)
			}
			if len(args) > 1 {
				return fmt.Errorf("accepts 1 arg, received %d", len(args))
			}
			return runLicenseExtract(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().BoolVar(&f.force, "force", false, "re-extract even if cached")
	cmd.Flags().BoolVar(&f.recursive, "recursive", false, "report licenses for dependencies recursively")
	cmd.Flags().BoolVar(&f.all, "all", false, "show all dependencies and their licenses")
	cmd.Flags().BoolVar(&f.perFile, "per-file", false, "scan root-level .go files for SPDX headers when no license file is found")
	cmd.Flags().BoolVar(&f.history, "history", false, "show every stored generation for the module instead of extracting")
	cmd.Flags().StringVar(&f.walkID, "walk-id", "", "with --recursive: report the closure of this walk instead of the one the default rule picks")

	return cmd
}

func runLicenseExtract(ctx context.Context, arg string, f licenseFlags, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	// The standard library never arrives through the module proxy, so extraction
	// has nothing to open and the refusal it produced named `kanonarion fetch` —
	// a command that rejects the coordinate outright. Its licence is on the
	// chain of custody instead, which is where every other surface reads it.
	if isStdlibCoordinate(coord) {
		return runStdlibLicense(ctx, coord, f, ctr.StdlibCustody, stdout)
	}

	if f.history {
		return runLicenseHistory(ctx, coord, ctr.QueryLicense, stdout)
	}

	result, err := ctr.ExtractLicense.Execute(ctx, licapp.ExtractRequest{
		Coordinate: coord,
		Force:      f.force,
		PerFile:    f.perFile,
	})
	if err != nil {
		return fmt.Errorf("extracting license: %w", err)
	}

	if err := printLicenseRecord(result.Record, result.FromCache || result.Reused, jsonOut, stdout); err != nil {
		return err
	}
	if result.Reused {
		// Said plainly, because the two are different facts and the distinction is
		// the one a reader chasing a stale answer needs: the extraction DID run,
		// and it came back saying what the ledger already said.
		if _, err := fmt.Fprintln(stderr,
			"re-extracted and found identical to the generation already recorded; no new generation was written"); err != nil {
			return fmt.Errorf("writing re-extraction note: %w", err)
		}
	}

	if (f.recursive || f.all) && !jsonOut {
		if err := printLicenseRecursive(ctx, coord, ctr.QueryWalks, ctr.ExtractLicense, ctr.QueryLicense, ctr.StdlibCustody, f, stdout, stderr); err != nil {
			return fmt.Errorf("recursive license report: %w", err)
		}
	}

	return nil
}

// runStdlibLicense answers `license stdlib@<version>` from the recorded chain
// of custody.
//
// It reports the same identity and the same basis audit and the SBOM report
// for the same node, and where nothing has been recorded it says so and names
// the command that would record it. It never names `kanonarion fetch`: the
// standard library has no fetchable module path, so that remedy could not be
// followed even in principle.
func runStdlibLicense(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	f licenseFlags,
	custody StdlibCustodyReader,
	stdout io.Writer,
) error {
	if f.history {
		return runStdlibLicenceHistory(ctx, coord, custody, stdout)
	}

	answer, err := resolveStdlibLicence(ctx, coord, custody)
	if err != nil {
		return err
	}
	if jsonOut {
		return printStdlibLicenceJSON(answer, stdout)
	}
	return printStdlibLicenceText(answer, stdout)
}

// stdlibLicenceJSON is the machine-readable shape of the standard library's
// licence answer. It is deliberately not the licence-record shape: there is no
// record, and emitting one would put an extraction's field names around an
// answer no extraction produced.
type stdlibLicenceJSON struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	SPDX    string `json:"primary_spdx"`
	Status  string `json:"status"`
	Custody struct {
		Established  bool   `json:"established"`
		Basis        string `json:"basis"`
		Verification string `json:"verification,omitempty"`
		Detail       string `json:"detail,omitempty"`
		Route        string `json:"route,omitempty"`
		SourceURL    string `json:"source_url,omitempty"`
		VCSURL       string `json:"vcs_url,omitempty"`
		VCSRef       string `json:"vcs_ref,omitempty"`
		VCSCommit    string `json:"vcs_commit,omitempty"`
		SHA256       string `json:"sha256,omitempty"`
		AcquiredAt   string `json:"acquired_at,omitempty"`
		Statement    string `json:"statement"`
		Remedy       string `json:"remedy,omitempty"`
	} `json:"custody"`
	Obligations domain.Obligations `json:"obligations"`
}

func printStdlibLicenceJSON(a stdlibLicence, stdout io.Writer) error {
	// a.SPDX is walkdomain.StdlibLicense's resolution — one identifier, never
	// an expression — so a single lookup is the whole answer here.
	out := stdlibLicenceJSON{
		Module:      a.Coordinate.Path(),
		Version:     a.Coordinate.Version(),
		SPDX:        a.SPDX,
		Status:      stdlibLicenceStatus(a),
		Obligations: domain.LookupObligations(a.SPDX),
	}
	out.Custody.Established = a.Established()
	out.Custody.Basis = a.Basis
	out.Custody.Verification = a.Verification
	out.Custody.Detail = a.Detail
	out.Custody.Route = a.Route
	out.Custody.SourceURL = a.SourceURL
	out.Custody.VCSURL = a.VCSURL
	out.Custody.VCSRef = a.VCSRef
	out.Custody.VCSCommit = a.VCSCommit
	out.Custody.SHA256 = a.SHA256
	if !a.AcquiredAt.IsZero() {
		out.Custody.AcquiredAt = a.AcquiredAt.UTC().Format(time.RFC3339)
	}
	out.Custody.Statement = a.basisStatement()
	if !a.Established() {
		out.Custody.Remedy = stdlibCustodyRemedy
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

// stdlibLicenceStatus is the status word audit prints for the same node:
// Detected relays extracted evidence, Known relays published knowledge.
func stdlibLicenceStatus(a stdlibLicence) string {
	if a.Basis == stdlibLicenceBasisTarball {
		return domain.LicenseStatusDetected.String()
	}
	return "Known"
}

func printStdlibLicenceText(a stdlibLicence, stdout io.Writer) error {
	if _, err := fmt.Fprintf(stdout, "%s: %s — %s\n",
		a.Coordinate, stdlibLicenceStatus(a), a.SPDX); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if _, err := fmt.Fprintf(stdout, "  basis: %s\n", a.basisStatement()); err != nil {
		return fmt.Errorf("writing basis: %w", err)
	}
	if a.Established() {
		rows := [][2]string{
			{"acquired via", a.Route},
			{"source", a.SourceURL},
			{"sha256", a.SHA256},
			{"vcs", strings.TrimSpace(a.VCSURL + " " + a.VCSRef)},
			{"commit", a.VCSCommit},
			{"detail", a.Detail},
		}
		for _, row := range rows {
			if row[1] == "" {
				continue
			}
			if _, err := fmt.Fprintf(stdout, "  %-13s %s\n", row[0]+":", row[1]); err != nil {
				return fmt.Errorf("writing custody detail: %w", err)
			}
		}
		if !a.AcquiredAt.IsZero() {
			if _, err := fmt.Fprintf(stdout, "  %-13s %s\n", "acquired at:",
				a.AcquiredAt.UTC().Format(time.RFC3339)); err != nil {
				return fmt.Errorf("writing custody detail: %w", err)
			}
		}
	}
	if _, err := fmt.Fprintln(stdout,
		"  note: the standard library ships with the toolchain and holds no licence record;"); err != nil {
		return fmt.Errorf("writing note: %w", err)
	}
	if _, err := fmt.Fprintln(stdout,
		"        this identity is the chain of custody the walk stage records for it"); err != nil {
		return fmt.Errorf("writing note: %w", err)
	}
	return printObligationsSection(a.SPDX, stdout)
}

// runStdlibLicenceHistory prints every custody measurement the ledger holds for
// the toolchain version, oldest first. It is the standard library's answer to
// the question --history asks of every other module: what was believed before,
// and on the strength of which bytes.
func runStdlibLicenceHistory(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	custody StdlibCustodyReader,
	stdout io.Writer,
) error {
	goVersion := stdlibdomain.CanonicalGoVersion(coord.Version())
	lister, ok := custody.(StdlibCustodyLister)
	if !ok {
		return fmt.Errorf("this store keeps no standard-library custody history")
	}
	measurements, err := lister.ListFactsFor(ctx, goVersion)
	if err != nil {
		return fmt.Errorf("listing standard-library custody measurements for %s: %w", goVersion, err)
	}
	if len(measurements) == 0 {
		if _, werr := fmt.Fprintf(stdout,
			"no chain of custody recorded for %s (%s); establish one with: %s\n",
			coord, goVersion, stdlibCustodyRemedy); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		return nil
	}
	if _, werr := fmt.Fprintf(stdout, "%d custody measurement(s) for %s (%s):\n",
		len(measurements), coord, goVersion); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	for _, m := range measurements {
		spdx := m.LicenseSPDX
		if spdx == "" {
			spdx = "-"
		}
		if _, werr := fmt.Fprintf(stdout, "  %s  %-20s %-26s via %s\n    artefact: sha256:%s\n",
			m.AcquiredAt.UTC().Format(time.RFC3339), spdx,
			string(m.VerificationStatus), m.AcquisitionRoute.String(), m.Digests.SHA256); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	}
	return nil
}

// runLicenseHistory prints every generation the ledger holds for a coordinate,
// oldest first, and marks the one composition serves.
//
// The served record is marked rather than printed alone, because the point of
// the ledger is that the two are different things: what is believed now, and
// what was believed before and on the strength of which bytes.
func runLicenseHistory(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryLicenseUseCase, stdout io.Writer) error {
	recs, err := uc.LicenseHistory(ctx, coord, licapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("reading license history: %w", err)
	}
	if len(recs) == 0 {
		if _, werr := fmt.Fprintf(stdout, "no license records for %s\n", coord); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		return nil
	}

	// A conflict is reported, not hidden: the history view is precisely where an
	// operator goes to see why the composed read refused to pick.
	servedHash := ""
	served, found, gerr := uc.GetLicenseRecord(ctx, coord, licapp.PipelineVersion)
	switch {
	case gerr != nil:
		if _, werr := fmt.Fprintf(stdout, "composed answer: unavailable — %v\n\n", gerr); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	case found:
		servedHash = served.ContentHash
	}

	if _, werr := fmt.Fprintf(stdout, "%d generation(s) for %s at pipeline %s:\n",
		len(recs), coord, licapp.PipelineVersion); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	for _, r := range recs {
		marker := " "
		if r.ContentHash != "" && r.ContentHash == servedHash {
			marker = "*"
		}
		artefact := r.ArtefactIdentity
		if artefact == "" {
			artefact = "(no artefact recorded)"
		}
		spdx := r.PrimarySPDX
		if spdx == "" {
			spdx = "-"
		}
		if _, werr := fmt.Fprintf(stdout, "%s %s  %-20s conf=%.2f  %s\n    artefact: %s\n    record:   %s\n",
			marker, ledgerStamp(r.ExtractedAt), spdx, r.PrimaryConfidence,
			r.OverallStatus.String(), artefact, r.ContentHash); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	}
	if _, werr := fmt.Fprintln(stdout, "\n* served by the composed read (highest confidence, then most recent)"); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	return nil
}

// closureLicenceReader returns the per-module read the closure listing drives.
//
// A project walk carries the standard library as a node, and extraction can
// only ever miss on it: it is toolchain-provided, never fetched. The listing
// used to show that miss as `run 'kanonarion fetch' first` against a coordinate
// fetch rejects. Its licence comes off the chain of custody, carried here in
// the shape the caller reads — the identifier — and never persisted, because no
// extraction produced it.
func closureLicenceReader(
	extractUC ExtractLicenseUseCase,
	custody StdlibCustodyReader,
	force bool,
) func(context.Context, coordinate.ModuleCoordinate) (domain.LicenseRecord, error) {
	return func(ctx context.Context, coord coordinate.ModuleCoordinate) (domain.LicenseRecord, error) {
		if isStdlibCoordinate(coord) {
			answer, cerr := resolveStdlibLicence(ctx, coord, custody)
			if cerr != nil {
				return domain.LicenseRecord{}, cerr
			}
			return domain.LicenseRecord{Coordinate: coord, PrimarySPDX: answer.SPDX}, nil
		}
		res, err := extractUC.Execute(ctx, licapp.ExtractRequest{Coordinate: coord, Force: force})
		if err != nil {
			return domain.LicenseRecord{}, fmt.Errorf("extracting license for %s: %w", coord, err)
		}
		return res.Record, nil
	}
}

func printLicenseRecursive(
	ctx context.Context,
	target coordinate.ModuleCoordinate,
	walksUC QueryWalksUseCase,
	extractUC ExtractLicenseUseCase,
	queryUC QueryLicenseUseCase,
	custody StdlibCustodyReader,
	f licenseFlags,
	stdout, stderr io.Writer,
) error {
	// Which walk's closure is being listed. --recursive reports a build's
	// dependency set, and a store holding several walks of one project holds
	// several different ones; the caller either names the walk or is told which
	// was named for them.
	var choice walkChoice
	if f.walkID != "" {
		rec, perr := resolvePinnedWalk(ctx, walksUC, f.walkID, target)
		if perr != nil {
			return perr
		}
		choice = pinnedWalkChoice(rec)
	} else {
		summaries, lerr := walksUC.ListWalks(ctx, walkports.WalkFilter{Target: &target})
		if lerr != nil {
			return fmt.Errorf("listing walks: %w", lerr)
		}
		if len(summaries) == 0 {
			return walkTargetMiss(ctx, walksUC, target, stderr)
		}
		choice = chooseWalk(ctx, walksUC, summaries, "")
	}

	extractFn := closureLicenceReader(extractUC, custody, f.force)

	depResults, err := queryUC.ResolveForWalk(ctx, choice.summary.ID, target, extractFn)
	if err != nil {
		return fmt.Errorf("resolving walk licenses: %w", err)
	}
	if len(depResults) == 0 {
		return nil
	}

	primaryLic := "Unknown"
	if primaryRec, found, err := queryUC.GetLicenseRecord(ctx, target, licapp.PipelineVersion); err == nil && found {
		if covered := domain.ReadCoverage(primaryRec); covered.PrimarySPDX != "" {
			primaryLic = covered.PrimarySPDX
		} else {
			primaryLic = "None"
		}
	}

	// Which walk answered, and in which frame. A closure listed here is the
	// closure of one platform's build — GOOS gates which files, and so which
	// modules, that build selects — and the choice between the store's walks of
	// this target is stated on the line below when there was a choice to make.
	if _, err := fmt.Fprintf(stdout, "\nAnswered from walk %s (frame %s)\n", choice.summary.ID, choice.summary.BuildFrame()); err != nil {
		return fmt.Errorf("writing walk frame: %w", err)
	}
	if note := choice.statement(); note != "" {
		if _, err := fmt.Fprint(stdout, note); err != nil {
			return fmt.Errorf("writing walk selection notice: %w", err)
		}
	}

	if f.all {
		if _, err := fmt.Fprintf(stdout, "\nDependency Licenses:\n"); err != nil {
			return fmt.Errorf("writing header: %w", err)
		}
		for _, d := range depResults {
			status := d.PrimarySPDX
			if d.Err != nil {
				status = fmt.Sprintf("Error: %v", d.Err)
			}
			if _, err := fmt.Fprintf(stdout, "  %-50s: %s\n", d.Coordinate, status); err != nil {
				return fmt.Errorf("writing dep: %w", err)
			}
		}
		return nil
	}

	// Summarize.
	licenseCounts := make(map[string]int)
	for _, d := range depResults {
		lic := d.PrimarySPDX
		if d.Err != nil {
			lic = "Unknown"
		}
		licenseCounts[lic]++
	}

	different := false
	for lic := range licenseCounts {
		if lic != primaryLic {
			different = true
			break
		}
	}

	if !different {
		if _, err := fmt.Fprintf(stdout, "  All %d dependencies use the same license (%s).\n", len(depResults), primaryLic); err != nil {
			return fmt.Errorf("writing summary: %w", err)
		}
		return nil
	}

	if _, err := fmt.Fprintf(stdout, "\nDependency License Summary:\n"); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	licenses := make([]string, 0, len(licenseCounts))
	for l := range licenseCounts {
		licenses = append(licenses, l)
	}
	sort.Strings(licenses)
	for _, l := range licenses {
		if _, err := fmt.Fprintf(stdout, "  %s: %d modules\n", l, licenseCounts[l]); err != nil {
			return fmt.Errorf("writing summary line: %w", err)
		}
	}
	return nil
}

func printLicenseRecord(r domain.LicenseRecord, fromCache bool, jsonOut bool, stdout io.Writer) error {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(newLicenseDocument(r)); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	cached := ""
	if fromCache {
		cached = " (cached)"
	}
	// The record is published through what each of its licences covers, so a
	// bundled font's licence is never handed over as the module's own. The
	// record itself is left as measured: Expression, ExpressionBasis and
	// PrimarySPDX are inside its content hash.
	coverage := domain.ReadCoverage(r)
	displayLicense := coverage.PrimarySPDX
	if coverage.Expression != "" {
		displayLicense = coverage.Expression
	}
	if _, err := fmt.Fprintf(stdout, "%s@%s: %s — %s%s\n",
		r.Coordinate.Path(), r.Coordinate.Version(),
		r.OverallStatus.String(), displayLicense,
		cached,
	); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if r.FailureDetail != "" {
		if _, err := fmt.Fprintf(stdout, "  failure: %s\n", r.FailureDetail); err != nil {
			return fmt.Errorf("writing failure detail: %w", err)
		}
	}
	// An expression carrying an operator makes a legal claim — a choice under
	// OR, a set of obligations under AND — so the reader is shown what settled
	// it, and any grant that was read as somebody else's rather than this
	// module's, which is the one fact the expression deliberately omits.
	if coverage.Basis != "" {
		if _, err := fmt.Fprintf(stdout, "  basis: %s\n", coverage.Basis); err != nil {
			return fmt.Errorf("writing expression basis: %w", err)
		}
	}
	if len(r.BundledSPDXs) > 0 {
		if _, err := fmt.Fprintf(stdout,
			"  bundled in the licence file, not a licence of this module: %s\n",
			strings.Join(r.BundledSPDXs, ", "),
		); err != nil {
			return fmt.Errorf("writing bundled grants: %w", err)
		}
	}
	for _, f := range r.LicenseFiles {
		vendored := ""
		if f.IsVendored {
			vendored = " [vendored]"
		}
		if _, err := fmt.Fprintf(stdout, "  %s: %s (%.0f%%)%s — %s\n",
			f.Path, f.SPDX, f.Confidence*100, vendored, coverage.ByPath[f.Path].Covers(),
		); err != nil {
			return fmt.Errorf("writing file entry: %w", err)
		}
	}
	if err := printPackageLicensesSection(r, stdout); err != nil {
		return err
	}
	if err := printCopyrightSection(r, stdout); err != nil {
		return err
	}
	if err := printProvenanceSection(r, stdout); err != nil {
		return err
	}
	// A dual licence (disjunctive expression) has no single obligation set:
	// the obligations in force are those of the elected arm, so each arm is
	// rendered per election rather than asserting the primary's obligations —
	// which would claim, e.g., GPL disclose-source of a consumer electing the
	// Apache arm.
	if arms := domain.DisjunctionArms(coverage.Expression); len(arms) >= 2 {
		return printElectiveObligationsSection(arms, stdout)
	}
	// A conjunction (A AND B) is the opposite case: there is no election. What
	// may be said about it turns on the record's own basis — arms granted one
	// file each state their coverage and cannot be merged into an owed set;
	// arms sharing a file cannot state coverage and all bind.
	switch reading := readLicenceObligations(r); {
	case reading.Maximal:
		return printSeparateGrantsSection(coverage.Expression, reading.Set, reading.Arms, reading.Grants, stdout)
	case len(reading.Arms) > 0:
		return printBindingObligationsSection(coverage.Expression, reading.Set, reading.Arms, stdout)
	}
	return printObligationsSection(coverage.PrimarySPDX, stdout)
}

// obligationsReadingMaximal qualifies an obligations set merged across
// separately granted arms. It is a statement rather than a flag because it has
// to survive being read on its own, next to the numbers it qualifies: a
// consumer who sees only this line must not act on the set beside it as though
// it were owed. One spelling, shared by every surface that publishes the set.
const obligationsReadingMaximal = "maximal: an upper bound across separately granted arms, not the set you owe"

// licenceObligationsReading is what a licence record says about the
// obligations it puts on a consumer: the set to publish, the arms that produce
// it, and — where the arms were granted one licence file each — the path that
// grants each arm and the warning that the set is an upper bound rather than
// what is owed.
type licenceObligationsReading struct {
	// Set is the obligations to publish. It is the owed set unless Maximal
	// says otherwise.
	Set domain.Obligations
	// Arms are the conjunction's arms, nil for every other expression shape.
	Arms []string
	// Grants maps an arm to the licence files granting it, non-nil only when
	// the arms were separately granted. It is the coverage evidence: the file
	// names what its arm covers.
	Grants map[string][]string
	// Maximal says Set is the upper bound across separately granted arms and
	// must not be rendered as the obligations a consumer owes.
	Maximal bool
}

// readLicenceObligations answers the obligations a licence record puts on a
// consumer, reading the record through what each of its licences covers and
// then the record's own basis for how the remaining arms relate.
//
// Coverage comes first because an arm that does not govern the module's code
// is not an obligation on using it: chroma's OFL-1.1 is a bundled font's
// licence, and merging it in handed a Go syntax-highlighting library's consumer
// a share-alike condition.
//
// A conjunction of arms granted by ONE file binds every arm at once — nothing
// attributes coverage, so the answer is the union of them all, never
// PrimarySPDX's, which is a backward-compatibility shim naming one arm and
// would report MIT's silence on patents as gopkg.in/yaml.v3's answer while its
// Apache-2.0 arm grants them expressly.
//
// A conjunction whose arms were granted one file EACH is a different claim.
// The file names what its arm covers, and whether a consumer owes that arm
// depends on whether the covered artefact reaches their binary — go-digest's
// CC-BY-SA-4.0 covers LICENSE.docs, not the Go package. The merged set is
// returned as maximal, and each arm comes back with the path that grants it,
// because that path is the coverage evidence and it is already in the record.
//
// A disjunction is not this function's case and is handled by its callers
// before they reach it.
func readLicenceObligations(r domain.LicenseRecord) licenceObligationsReading {
	coverage := domain.ReadCoverage(r)
	arms := domain.ConjunctionArms(coverage.Expression)
	switch {
	case len(arms) < 2:
		return licenceObligationsReading{Set: domain.LookupObligations(coverage.PrimarySPDX)}
	case domain.ArmsAreSeparatelyGranted(coverage.Basis):
		return licenceObligationsReading{
			Set:     domain.MaximalObligations(arms),
			Arms:    arms,
			Grants:  domain.ArmGrants(coverage.Expression, r.LicenseFiles),
			Maximal: true,
		}
	default:
		return licenceObligationsReading{Set: domain.UnionObligations(arms), Arms: arms}
	}
}

// printElectiveObligationsSection renders per-arm obligations for a
// dual-licensed module and names the election as an operator decision.
func printElectiveObligationsSection(arms []string, stdout io.Writer) error {
	if _, err := fmt.Fprintln(stdout, "  dual licence: obligations depend on the elected arm — the election is an"); err != nil {
		return fmt.Errorf("writing elective obligations header: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, "  operator decision, recorded as a license_overrides entry for this module"); err != nil {
		return fmt.Errorf("writing elective obligations header: %w", err)
	}
	for _, arm := range arms {
		ob := domain.LookupObligations(arm)
		if ob.Status == domain.ObligationStatusUnknown {
			if _, err := fmt.Fprintf(stdout, "  obligations if %s is elected: unknown (%s not in catalogue v%s)\n",
				arm, arm, domain.ObligationCatalogueVersion); err != nil {
				return fmt.Errorf("writing obligations: %w", err)
			}
			continue
		}
		if _, err := fmt.Fprintf(stdout, "  obligations if %s is elected (catalogue v%s):\n",
			arm, domain.ObligationCatalogueVersion); err != nil {
			return fmt.Errorf("writing obligations header: %w", err)
		}
		if err := printObligationRows(ob, stdout); err != nil {
			return err
		}
	}
	return nil
}

// printBindingObligationsSection renders a conjunction whose arms are
// inseparable: the union every arm binds the consumer to at once, then each
// arm's own set, so a reader can see which licence imposed which duty instead
// of being handed a merged answer with nothing to attribute it to.
func printBindingObligationsSection(expr string, union domain.Obligations, arms []string, stdout io.Writer) error {
	if _, err := fmt.Fprintln(stdout, "  conjunction: every arm binds at once, so the obligations below are the union"); err != nil {
		return fmt.Errorf("writing binding obligations header: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, "  of all arms — there is no election to make"); err != nil {
		return fmt.Errorf("writing binding obligations header: %w", err)
	}
	if union.Status == domain.ObligationStatusUnknown {
		if _, err := fmt.Fprintf(stdout, "  obligations (%s): incomplete — an arm is not in catalogue v%s\n",
			expr, domain.ObligationCatalogueVersion); err != nil {
			return fmt.Errorf("writing obligations: %w", err)
		}
	} else {
		if _, err := fmt.Fprintf(stdout, "  obligations (%s, catalogue v%s):\n",
			expr, domain.ObligationCatalogueVersion); err != nil {
			return fmt.Errorf("writing obligations header: %w", err)
		}
		if err := printObligationRows(union, stdout); err != nil {
			return err
		}
	}
	for _, arm := range arms {
		if err := printArmObligations(arm, "", stdout); err != nil {
			return err
		}
	}
	return nil
}

// printSeparateGrantsSection renders a conjunction whose arms were granted one
// licence file each. Each arm leads, named with the file that grants it,
// because that file is the only statement of what the arm covers. The merged
// set comes last and says on its own line that it is an upper bound: which
// arms a consumer actually owes turns on which artefacts reach their binary,
// and no licence record answers that.
func printSeparateGrantsSection(
	expr string,
	maximal domain.Obligations,
	arms []string,
	grants map[string][]string,
	stdout io.Writer,
) error {
	if _, err := fmt.Fprintln(stdout, "  separate grants: each arm is granted by its own licence file, named below, and"); err != nil {
		return fmt.Errorf("writing separate grants header: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, "  that file states what the arm covers"); err != nil {
		return fmt.Errorf("writing separate grants header: %w", err)
	}
	for _, arm := range arms {
		if err := printArmObligations(arm, strings.Join(grants[arm], ", "), stdout); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(stdout, "  maximal obligations across every arm (%s, catalogue v%s) — an upper bound,\n",
		expr, domain.ObligationCatalogueVersion); err != nil {
		return fmt.Errorf("writing maximal obligations header: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, "  not what you owe: which arms bind depends on which covered artefacts you ship"); err != nil {
		return fmt.Errorf("writing maximal obligations header: %w", err)
	}
	return printObligationRows(maximal, stdout)
}

// printArmObligations renders one arm's own obligation set, naming the file
// that grants it when the record attributes one.
func printArmObligations(arm, grantedBy string, stdout io.Writer) error {
	where := ""
	if grantedBy != "" {
		where = ", granted by " + grantedBy
	}
	ob := domain.LookupObligations(arm)
	if ob.Status == domain.ObligationStatusUnknown {
		if _, err := fmt.Fprintf(stdout, "  obligations required by %s%s: unknown (%s not in catalogue v%s)\n",
			arm, where, arm, domain.ObligationCatalogueVersion); err != nil {
			return fmt.Errorf("writing obligations: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "  obligations required by %s%s (catalogue v%s):\n",
		arm, where, domain.ObligationCatalogueVersion); err != nil {
		return fmt.Errorf("writing obligations header: %w", err)
	}
	return printObligationRows(ob, stdout)
}

func printPackageLicensesSection(r domain.LicenseRecord, stdout io.Writer) error {
	if len(r.PackageLicenses) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "  per-package licenses (%d sub-packages):\n", len(r.PackageLicenses)); err != nil {
		return fmt.Errorf("writing per-package header: %w", err)
	}
	for _, pl := range r.PackageLicenses {
		spdx := pl.SPDX
		if spdx == "" {
			spdx = "unclassified"
		}
		if _, err := fmt.Fprintf(stdout, "    %-40s %s (%.0f%%)\n",
			pl.PackagePath, spdx, pl.Confidence*100,
		); err != nil {
			return fmt.Errorf("writing per-package entry: %w", err)
		}
	}
	return nil
}

func printObligationsSection(spdxID string, stdout io.Writer) error {
	if spdxID == "" {
		return nil
	}
	ob := domain.LookupObligations(spdxID)
	if ob.Status == domain.ObligationStatusUnknown {
		if _, err := fmt.Fprintf(stdout, "  obligations: unknown (%s not in catalogue v%s)\n",
			spdxID, domain.ObligationCatalogueVersion); err != nil {
			return fmt.Errorf("writing obligations: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "  obligations (%s, catalogue v%s):\n",
		spdxID, domain.ObligationCatalogueVersion); err != nil {
		return fmt.Errorf("writing obligations header: %w", err)
	}
	return printObligationRows(ob, stdout)
}

// printObligationRows renders the labelled obligation rows shared by the
// single-licence and per-election obligation sections.
func printObligationRows(ob domain.Obligations, stdout io.Writer) error {
	rows := []struct {
		label string
		value string
	}{
		{"include-notice", boolStr(ob.IncludeNotice)},
		{"include-license-text", boolStr(ob.IncludeLicenseText)},
		{"state-changes", boolStr(ob.StateChanges)},
		{"disclose-source", boolStr(ob.DiscloseSource)},
		{"same-license", ob.SameLicense.String()},
		{"network-use-trigger", boolStr(ob.NetworkUseTrigger)},
		{"no-trademark-use", boolStr(ob.NoTrademarkUse)},
		{"explicit-patent-grant", boolStr(ob.ExplicitPatentGrant)},
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(stdout, "    %-22s %s\n", row.label+":", row.value); err != nil {
			return fmt.Errorf("writing obligations row: %w", err)
		}
	}
	return nil
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func printCopyrightSection(r domain.LicenseRecord, stdout io.Writer) error {
	switch r.CopyrightStatus {
	case domain.CopyrightStatusNotAnalysed:
		if _, err := fmt.Fprintln(stdout, "  copyright: not analysed"); err != nil {
			return fmt.Errorf("writing copyright status: %w", err)
		}
	case domain.CopyrightStatusNoneFound:
		if _, err := fmt.Fprintln(stdout, "  copyright: none found"); err != nil {
			return fmt.Errorf("writing copyright status: %w", err)
		}
	case domain.CopyrightStatusExtractionFailed:
		if _, err := fmt.Fprintln(stdout, "  copyright: extraction failed"); err != nil {
			return fmt.Errorf("writing copyright status: %w", err)
		}
	case domain.CopyrightStatusFound:
		seen := make(map[string]struct{})
		var stmts []domain.CopyrightStatement
		for _, f := range r.LicenseFiles {
			for _, s := range f.CopyrightStatements {
				if _, dup := seen[s.Verbatim]; dup {
					continue
				}
				seen[s.Verbatim] = struct{}{}
				stmts = append(stmts, s)
			}
		}
		if _, err := fmt.Fprintf(stdout, "  copyright (%d statements):\n", len(stmts)); err != nil {
			return fmt.Errorf("writing copyright header: %w", err)
		}
		for _, s := range stmts {
			if _, err := fmt.Fprintf(stdout, "    %s  [%s]\n", s.Verbatim, s.Source); err != nil {
				return fmt.Errorf("writing copyright statement: %w", err)
			}
		}
	}
	return nil
}

// provenanceSignalLabel maps a contribution-licensing provenance signal to a
// reader-facing label for the text view. Falls back to the machine token.
func provenanceSignalLabel(s domain.ProvenanceSignal) string {
	switch s {
	case domain.ProvenanceSignalInboundOutbound:
		return "inbound=outbound"
	case domain.ProvenanceSignalCLARequired:
		return "CLA required"
	case domain.ProvenanceSignalDCORequired:
		return "DCO required"
	case domain.ProvenanceSignalAuthorsFile:
		return "AUTHORS"
	case domain.ProvenanceSignalContributorsFile:
		return "CONTRIBUTORS"
	case domain.ProvenanceSignalPatentsFile:
		return "PATENTS"
	default:
		return s.String()
	}
}

// printProvenanceSection renders the contribution-licensing chain-of-title as
// the facts found in the module zip, not as a compressed confidence verdict:
// the chain of title is evidence the reader weighs, never a judgement we make.
// The confidence enum's zero value still gates analysed from not-analysed so
// absence is surfaced, never assumed clean.
func printProvenanceSection(r domain.LicenseRecord, stdout io.Writer) error {
	p := r.Provenance
	if p.Confidence == domain.ChainOfTitleNotAnalysed {
		if _, err := fmt.Fprintln(stdout, "  provenance: not analysed"); err != nil {
			return fmt.Errorf("writing provenance status: %w", err)
		}
		return nil
	}

	// Signals are pre-sorted by signal value, so contribution statements and
	// attribution files emit in a deterministic order.
	var statements, attribution []string
	for _, sig := range p.Signals {
		switch sig {
		case domain.ProvenanceSignalInboundOutbound,
			domain.ProvenanceSignalCLARequired,
			domain.ProvenanceSignalDCORequired:
			statements = append(statements, provenanceSignalLabel(sig))
		case domain.ProvenanceSignalAuthorsFile,
			domain.ProvenanceSignalContributorsFile,
			domain.ProvenanceSignalPatentsFile:
			attribution = append(attribution, provenanceSignalLabel(sig))
		}
	}

	if _, err := fmt.Fprintln(stdout, "  provenance:"); err != nil {
		return fmt.Errorf("writing provenance header: %w", err)
	}
	stmt := "none found"
	if len(statements) > 0 {
		stmt = strings.Join(statements, ", ")
	}
	if _, err := fmt.Fprintf(stdout, "    contribution-licensing statement: %s\n", stmt); err != nil {
		return fmt.Errorf("writing contribution-licensing statement: %w", err)
	}
	if len(attribution) > 0 {
		if _, err := fmt.Fprintf(stdout, "    attribution files: %s\n", strings.Join(attribution, ", ")); err != nil {
			return fmt.Errorf("writing attribution files: %w", err)
		}
	}
	return nil
}

// -- license-list command --

// licenseListFlags is one invocation's request.
type licenseListFlags struct {
	spdx      string
	copyright string
	// copyrightStatus restricts the listing to records holding one of these
	// statuses. It is the flag that turns the listing into the answer to "which
	// modules will block the attribution document".
	copyrightStatus []domain.CopyrightStatus
	// allGenerations lifts the pipeline-version restriction the default applies.
	allGenerations bool
	limit, offset  int
}

// generation is the pipeline version the listing restricts to, empty under
// --all-generations.
func (f licenseListFlags) generation() string {
	if f.allGenerations {
		return ""
	}
	return licapp.PipelineVersion
}

// licenseListGenerationJSON is the listing document's statement of which record
// generation answered.
//
// The text path prints the same fact as a line under the rows. It is a field of
// its own rather than words folded into `subject`, because the truncation line
// renders the subject mid-sentence — "showing license records 3-4" — and a
// subject carrying a version reads as a page range applied to a version.
type licenseListGenerationJSON struct {
	// Served is the pipeline version this build answers from, stated whether or
	// not the listing was restricted to it: a consumer comparing a row's
	// pipeline_version against it needs the value in both modes.
	Served string `json:"served"`
	// AllGenerations says the restriction was lifted. It is the field that names
	// the state, and it is present at both values.
	AllGenerations bool `json:"all_generations"`
	// Remedy is the flag that lifts the restriction, and it is empty under
	// --all-generations because there is nothing left to lift — conventions.md
	// keeps omitempty for strings on exactly that reading, with the field beside
	// it naming the state the document is in.
	Remedy string `json:"remedy,omitempty"`
}

// generationStatement renders the generation half of the document.
func (f licenseListFlags) generationStatement() licenseListGenerationJSON {
	out := licenseListGenerationJSON{Served: licapp.PipelineVersion, AllGenerations: f.allGenerations}
	if !f.allGenerations {
		out.Remedy = "--all-generations"
	}
	return out
}

// postFiltered reports whether this request's page is assembled in the CLI
// rather than by the port: --copyright decides on full records, and a scope
// narrows to a module set the filter cannot express.
func (f licenseListFlags) postFiltered(scope *licenceListScope) bool {
	return f.copyright != "" || scope != nil
}

func newLicenseListCmd(stdout, stderr io.Writer) *cobra.Command {
	var f licenseListFlags
	var copyrightStatus []string
	var sf licenceScopeFlags

	cmd := &cobra.Command{
		Use: "license-list",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Aliases: []string{"licence-list"},
		Short:   "List extracted license records",
		Long: `license-list reads back the records 'kanonarion license' writes, so a question
about a whole build can be asked once instead of once per module.

Every row carries the licence identity, the recorded copyright status, the
pipeline version the record was extracted at, and whether this build serves it.

--copyright-status takes one or more of the four statuses a record can hold,
comma-separated or repeated, and a record matching any of them is listed:

  found                copyright extraction ran and identified at least one notice
  none_found           extraction ran and identified none
  extraction_failed    extraction could not complete
  not_analysed         extraction has not run for this record

A value outside the four is refused rather than matched, because in a list it
would otherwise narrow the answer in silence.

--package, --gomod and --walk-id scope the listing to the modules a build
compiles, resolved exactly as 'kanonarion notice' resolves them. The modules in
scope holding no licence record are named rather than dropped. So the set that
will block an attribution document is one invocation:

  kanonarion license-list --package ./cmd/x --copyright-status none_found

By default only records at the pipeline version this build serves are listed,
one row per coordinate. A record from an earlier pipeline version answers no
query — it was measured by logic this build has replaced — so listing it beside
the others would pad the count of what is known. --all-generations includes them
and marks each one.`,
		Example: `  kanonarion license-list
  kanonarion license-list --spdx MIT
  kanonarion license-list --copyright-status none_found
  kanonarion license-list --package ./cmd/kanonarion --copyright-status none_found --limit 0
  kanonarion license-list --gomod ./go.mod --json
  kanonarion license-list --all-generations --limit 0`,
		// The command filters by flag only. Without this a stray positional was
		// accepted and silently ignored, so `license-list <module>` printed the
		// whole store and read as "this module holds every one of these".
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			values, verr := copyrightStatusFilter(copyrightStatus)
			if verr != nil {
				return verr
			}
			f.copyrightStatus = values
			if serr := sf.validate(); serr != nil {
				return serr
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			ovSet, err := ctr.LicenseOverrides.LoadOverrides(cmd.Context())
			if err != nil {
				return fmt.Errorf("loading license overrides: %w", err)
			}
			scope, serr := resolveLicenceListScope(cmd.Context(), sf, ctr)
			if serr != nil {
				return serr
			}
			return runLicenseList(cmd.Context(), f, scope, ctr.QueryLicense, ovSet, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.spdx, "spdx", "", "filter by SPDX identifier (e.g. MIT)")
	cmd.Flags().StringVar(&f.copyright, "copyright", "", "filter by copyright holder substring (case-insensitive; loads full records)")
	cmd.Flags().StringSliceVar(&copyrightStatus, "copyright-status", nil,
		"list only records with one of these copyright statuses (comma-separated): found, none_found, extraction_failed, not_analysed")
	cmd.Flags().BoolVar(&f.allGenerations, "all-generations", false,
		"also list records extracted at a superseded pipeline version, which this build does not serve")
	cmd.Flags().StringVar(&sf.packagePattern, "package", "",
		"Go package pattern (e.g. ./cmd/kanonarion); scopes the listing to the modules linked into that binary")
	cmd.Flags().StringVar(&sf.gomodPath, "gomod", "", "path to go.mod; scopes the listing to the project's code dependencies")
	cmd.Flags().StringVar(&sf.walkID, "walk-id", "", "walk id; scopes the listing to that walk's modules")
	cmd.Flags().IntVar(&f.limit, "limit", 50, "maximum number of records to return (0 = unlimited)")
	cmd.Flags().IntVar(&f.offset, "offset", 0, "skip this many records")

	return cmd
}

// copyrightStatuses is the vocabulary --copyright-status accepts, in the order
// docs/cli/license.md and the command's own help list the four.
var copyrightStatuses = []domain.CopyrightStatus{
	domain.CopyrightStatusFound,
	domain.CopyrightStatusNoneFound,
	domain.CopyrightStatusExtractionFailed,
	domain.CopyrightStatusNotAnalysed,
}

// copyrightStatusFilter validates the values a caller gave --copyright-status.
//
// An unrecognised value is refused rather than passed through to match nothing.
// On a single-value filter a zero result would at least be visible; in a list it
// would not — two good values and one typo returns rows, and the rows the typo
// should have added are missing with nothing in the output to say so.
func copyrightStatusFilter(values []string) ([]domain.CopyrightStatus, error) {
	known := map[string]domain.CopyrightStatus{}
	names := make([]string, 0, len(copyrightStatuses))
	for _, s := range copyrightStatuses {
		known[s.String()] = s
		names = append(names, s.String())
	}
	out := make([]domain.CopyrightStatus, 0, len(values))
	seen := map[domain.CopyrightStatus]bool{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		status, ok := known[v]
		if !ok {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf(
				"--copyright-status %q is not a status a licence record can hold; it accepts one or more of: %s",
				v, strings.Join(names, ", "))}
		}
		if seen[status] {
			continue
		}
		seen[status] = true
		out = append(out, status)
	}
	return out, nil
}

// licenseListEntry is one row of the listing, in both output modes.
type licenseListEntry struct {
	Module     string `json:"module"`
	Version    string `json:"version"`
	Status     string `json:"status"`
	License    string `json:"license"`
	Expression string `json:"expression,omitempty"`
	// CopyrightStatus is what copyright extraction concluded. It decides whether
	// `notice` can publish the module, and it is emitted on every row including
	// `not_analysed` — that is one of the four answers, not an absence.
	CopyrightStatus string `json:"copyright_status"`
	// PipelineVersion is the extraction logic that produced the record, and
	// Superseded says this build does not serve it. Both halves are on every
	// row: a consumer reading only the true ones could not tell a servable
	// record from one the pair was never computed for.
	PipelineVersion string `json:"pipeline_version"`
	Superseded      bool   `json:"superseded"`
	Source          string `json:"source"`
	// Conflict carries the disagreement composition refused to resolve. A
	// consumer parsing this must not read an absent license as "no licence".
	Conflict string `json:"conflict,omitempty"`
}

// toLicenseListEntry projects one summary onto the row, applying the operator's
// recorded determination where there is one.
func toLicenseListEntry(s ports.LicenseSummary, coord coordinate.ModuleCoordinate, overrides domain.LicenseOverrideSet) licenseListEntry {
	entry := licenseListEntry{
		Module:          s.ModulePath,
		Version:         s.ModuleVersion,
		CopyrightStatus: s.CopyrightStatus.String(),
		PipelineVersion: s.PipelineVersion,
		Superseded:      s.PipelineVersion != licapp.PipelineVersion,
		Source:          "scanner",
	}
	if s.Conflict != nil {
		entry.Status = "Conflict"
		entry.Conflict = s.Conflict.Error()
		return entry
	}
	entry.Status = s.OverallStatus.String()
	entry.License = s.PrimarySPDX
	entry.Expression = s.Expression
	if ov, ok := overrides.Resolve(coord); ok {
		entry.License = ov.SPDX
		entry.Expression = ""
		entry.Source = "override"
	}
	return entry
}

func runLicenseList(
	ctx context.Context,
	f licenseListFlags,
	scope *licenceListScope,
	uc QueryLicenseUseCase,
	overrides domain.LicenseOverrideSet,
	stdout, stderr io.Writer,
) error {
	// One row more than will be printed, so the extra row's presence answers
	// whether the limit bit. No count is taken: how many were withheld would
	// cost a second read this listing does not otherwise pay.
	// Paging goes to the port, which applies it to the same ordering the unpaged
	// listing produces — except where the population being paged is assembled
	// here, and a port offset would skip records the CLI's filter had not yet
	// seen. There the skip is applied below, on the only set that is the
	// caller's page.
	fetchLimit, fetchOffset := truncationFetchLimit(f.limit), f.offset
	if f.postFiltered(scope) {
		fetchLimit, fetchOffset = 0, 0
	}
	sums, err := uc.ListLicenseRecords(ctx, ports.LicenseFilter{
		SPDX:            f.spdx,
		CopyrightStatus: f.copyrightStatus,
		PipelineVersion: f.generation(),
		Limit:           fetchLimit,
		Offset:          fetchOffset,
	})
	if err != nil {
		return fmt.Errorf("listing license records: %w", err)
	}

	// The scope census is a second read, and it is a different question from the
	// page: a module whose record the status filter excluded still HOLDS a
	// record, so naming the modules that hold none cannot be derived from the
	// rows. It is paid only when a scope was asked for.
	var census []ports.LicenseSummary
	if scope != nil {
		census, err = uc.ListLicenseRecords(ctx, ports.LicenseFilter{PipelineVersion: f.generation()})
		if err != nil {
			return fmt.Errorf("listing the licence records in scope: %w", err)
		}
		sums = scope.keep(sums)
	}

	if f.copyright != "" {
		var matched []ports.LicenseSummary
		for _, s := range sums {
			coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
			if cErr != nil {
				return fmt.Errorf("license record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
			}
			rec, found, rerr := uc.GetLicenseRecord(ctx, coord, s.PipelineVersion)
			if rerr != nil || !found {
				continue
			}
			if domain.MatchesCopyrightHolder(rec.LicenseFiles, f.copyright) {
				matched = append(matched, s)
			}
		}
		sums = matched
	}
	if f.postFiltered(scope) {
		sums = skipList(sums, f.offset)
	}

	sums, truncated := truncateList(sums, f.limit)
	// The subject stays the bare plural rather than naming the generation in it,
	// as native-list's does: the ranged form of the truncation line reads
	// "showing <subject> 3-4", and a subject carrying a version renders that as
	// "showing license records at pipeline 1.4.0 3-4". The generation is stated
	// on its own line below instead, on every listing.
	trunc := listTruncation{limit: f.limit, subject: "license records", truncated: truncated, offset: f.offset}

	entries := make([]licenseListEntry, 0, len(sums))
	var conflicts []error
	for _, s := range sums {
		coord, cErr := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if cErr != nil {
			return fmt.Errorf("license record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, cErr)
		}
		entries = append(entries, toLicenseListEntry(s, coord, overrides))
		if s.Conflict != nil {
			conflicts = append(conflicts, s.Conflict)
		}
	}

	var zero *listZeroScope
	if len(entries) == 0 {
		z, serr := licenseListZeroScope(ctx, f, scope, census, uc)
		if serr != nil {
			return serr
		}
		zero = &z
	}

	if jsonOut {
		if derr := writeListDocumentWith(stdout, entries, trunc, zero, listDocumentFacts{
			scope:      scope.statement(census),
			generation: f.generationStatement(),
		}); derr != nil {
			return derr
		}
		return licenseListConflictErr(conflicts)
	}
	if perr := printLicenseListText(stdout, entries, f, scope, census, zero, trunc); perr != nil {
		return perr
	}
	// Every module is listed first, then the command fails. A licence in dispute
	// must not be reported as a clean run.
	return licenseListConflictErr(conflicts)
}

// printLicenseListText renders the page in the reader's terms: the scope it was
// taken over, the rows, the modules in scope that hold no record, which
// generation answered, and what the limit withheld.
func printLicenseListText(
	stdout io.Writer,
	entries []licenseListEntry,
	f licenseListFlags,
	scope *licenceListScope,
	census []ports.LicenseSummary,
	zero *listZeroScope,
	trunc listTruncation,
) error {
	if serr := scope.writeTextStatement(stdout, census); serr != nil {
		return serr
	}
	if zero != nil {
		return writeListZeroNotice(stdout, *zero)
	}
	for _, e := range entries {
		mark := ""
		if e.Superseded {
			mark = "  [superseded generation " + e.PipelineVersion + "]"
		}
		if e.Conflict != "" {
			if _, err := fmt.Fprintf(stdout, "%-50s %-12s %-20s %-18s %s\n",
				e.Module+"@"+e.Version, "CONFLICT", "unresolved", "-",
				"run 'kanonarion license "+e.Module+"@"+e.Version+" --history'"); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
			continue
		}
		if _, err := fmt.Fprintf(stdout, "%-50s %-12s %-20s %-18s %s%s\n",
			e.Module+"@"+e.Version,
			e.Status,
			licenceFromEntry(e),
			e.CopyrightStatus,
			e.Source,
			mark,
		); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if gerr := writeLicenseListGenerationNotice(stdout, f, entries); gerr != nil {
		return gerr
	}
	return writeListTruncationNotice(stdout, trunc)
}

// licenceFromEntry is the licence a text row states: the expression where the
// record has one, the primary otherwise.
//
// It is one function because the text listing, the JSON listing and the
// cross-surface control all have to ask it the same way, off the same projected
// row. A test that re-implements this rule agrees with the renderer only by
// coincidence, and the coincidence ended the day the licence surfaces started
// reading a record through what its licences cover: the mirrored rule kept
// passing while the listing served a Go library's embedded font licence.
//
// The identity itself is composed further upstream, where the record is read —
// see the licence store's summary projection.
func licenceFromEntry(e licenseListEntry) string {
	if e.Expression != "" {
		return e.Expression
	}
	return e.License
}

// writeLicenseListGenerationNotice states which generation the rows were drawn
// from.
//
// It prints on every listing, not only when something was excluded: a reader who
// is not told the rows were restricted to one generation has no way to tell a
// restricted count from a whole one.
func writeLicenseListGenerationNotice(stdout io.Writer, f licenseListFlags, entries []licenseListEntry) error {
	if !f.allGenerations {
		_, err := fmt.Fprintf(stdout,
			"listing license records at pipeline %s, the version this build serves; "+
				"records from a superseded pipeline version are not shown (--all-generations)\n",
			licapp.PipelineVersion)
		if err != nil {
			return fmt.Errorf("writing generation notice: %w", err)
		}
		return nil
	}
	superseded := 0
	for _, e := range entries {
		if e.Superseded {
			superseded++
		}
	}
	if superseded == 0 {
		return nil
	}
	_, err := fmt.Fprintf(stdout,
		"%d of %d listed record(s) were extracted at a superseded pipeline version; this build serves %s "+
			"and answers no query from them. Re-extract one:\n  kanonarion license <module>@<version>\n",
		superseded, len(entries), licapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("writing superseded notice: %w", err)
	}
	return nil
}

// licenseListConflictErr fails the run when the page held a disputed
// coordinate. The check is over the rows that were LISTED, so a disagreement
// inside a generation this build does not serve is reported only where those
// rows are — under --all-generations.
func licenseListConflictErr(conflicts []error) error {
	if len(conflicts) == 0 {
		return nil
	}
	return fmt.Errorf("%d module(s) hold conflicting license records: %w",
		len(conflicts), errors.Join(conflicts...))
}

// licenseListZeroScope lifts the filters and re-asks the store, so a zero
// distinguishes a value that matched nothing from a store with no licence
// records in it. Reached only when the listing came back empty.
//
// Every active filter is named: dropping one from the statement would send the
// reader to check a spelling that was not the one that excluded their module.
func licenseListZeroScope(
	ctx context.Context,
	f licenseListFlags,
	scope *licenceListScope,
	census []ports.LicenseSummary,
	uc QueryLicenseUseCase,
) (listZeroScope, error) {
	all := census
	if scope == nil {
		var err error
		all, err = uc.ListLicenseRecords(ctx, ports.LicenseFilter{PipelineVersion: f.generation()})
		if err != nil {
			return listZeroScope{}, fmt.Errorf("counting license records for the zero-result notice: %w", err)
		}
	} else {
		all = scope.keep(all)
	}
	z := listZeroScope{
		subject:    "license record",
		considered: len(all),
		produce:    "kanonarion license <module>@<version>",
		listAll:    "kanonarion license-list",
	}
	// The illustration has to be in the shape the filter compares against, and an
	// SPDX identifier is only that when --spdx is one of the filters that ran.
	if len(all) > 0 && f.spdx != "" {
		z.example = all[0].PrimarySPDX
	}
	var names, values, fields, matches []string
	if f.spdx != "" {
		names = append(names, "SPDX identifier")
		values = append(values, f.spdx)
		fields = append(fields, "primary SPDX identifier")
		matches = append(matches, matchExact)
	}
	if f.copyright != "" {
		names = append(names, "copyright holder")
		values = append(values, f.copyright)
		fields = append(fields, "the copyright holder in the licence files")
		matches = append(matches, matchSubstring)
	}
	if len(f.copyrightStatus) > 0 {
		names = append(names, "copyright status")
		values = append(values, copyrightStatusNames(f.copyrightStatus))
		fields = append(fields, "recorded copyright status")
		matches = append(matches, matchExact)
	}
	if len(names) > 0 {
		z.filterName = strings.Join(names, " and ")
		z.filterValue = strings.Join(values, " / ")
		z.field = strings.Join(fields, ", then ")
		z.matchKind = strings.Join(matches, " then ")
	}
	// An offset past the end empties the page without a filter having anything to
	// do with it, and the two look identical from the rows alone.
	// An empty corpus is not something a page can start past, so a zero over it
	// keeps the store-empty statement and its produce-a-record remedy.
	if z.filterValue == "" && len(all) > 0 && f.offset > 0 && f.offset >= len(all) {
		z.pagedPast = fmt.Sprintf("--offset %d starts past the last one", f.offset)
	}
	return z, nil
}

// copyrightStatusNames renders a status filter as the caller spelled it.
func copyrightStatusNames(statuses []domain.CopyrightStatus) string {
	names := make([]string, 0, len(statuses))
	for _, s := range statuses {
		names = append(names, s.String())
	}
	return strings.Join(names, ",")
}
