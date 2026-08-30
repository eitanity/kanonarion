package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/spf13/cobra"
)

// newVerificationCoverageCmd returns the command that reports a stored walk's
// verification coverage on its own, in a form a CI gate can assert on.
//
// It exists as a command because the figures are worth reading without
// re-walking: it reports them from a STORED walk, at any time after the run
// that produced it, which neither `walk` nor `audit` can do.
//
// It is no longer the only surface. `walk --json` carries the same aggregate
// under `verification_coverage`, embedding the contract published here so one
// fact keeps one spelling. The earlier rationale — that walk's stdout was the
// content-hashed record and had no room — was wrong in its conclusion: the
// record's keys are spliced through untouched and the coverage sits beside
// them, and nothing verifies a walk by hashing this document.
//
// Reporting from a stored walk rather than recomputing also means the audit path
// is covered by the same code: an audit leaves the project walk behind, so the
// graph this reads is the graph the audit reported on.
func newVerificationCoverageCmd(stdout, stderr io.Writer) *cobra.Command {
	var detail bool
	cmd := &cobra.Command{
		Use: "verification-coverage <walk-id>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Report how a walk's modules were verified",
		Long: `Report aggregate verification coverage over a stored walk's graph.

The figures say how many modules carry the strongest assurance — a checksum
database match cross-verified against the content of their VCS commit — how many
degraded to a weaker anchor, and how many carry none. A whole-graph collapse in
cross-verification is invisible in a populated status column, and this is the
figure that names it.

No host is named and no proxy is judged: the signal is coverage. A blocked
forge, a proxy that omits Origin metadata, a --skip-vcs-verify left set in CI and
a policy narrower than the forges a graph resolves to all degrade a graph the
same way, and a coverage figure catches all of them.

With --json the aggregate is emitted under stable field names, so a CI gate can
assert on cross_verified or collapsed directly, and every module is listed with
its class and the reason recorded for it. --detail prints that per-module list on
the text path: a count says how many modules are checksum-database-only, and the
reason says whether that was a proxy without Origin metadata, a forge that could
not be reached, or a skip flag left set — which is the answer a tampering
question actually needs.

Where the walk was taken from a project directory that is still present, the
report also states whether that project is vendored, because coverage describes
the modules the manifest resolved and a vendored project compiles the bytes under
vendor/.`,
		Example: `  kanonarion verification-coverage 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion verification-coverage <walk-id> --json | jq -e '.collapsed | not'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runVerificationCoverage(cmd.Context(), args[0], ctr.QueryWalks, ctr.QueryFetch, detail, stdout, stderr)
		},
	}
	cmd.Flags().BoolVar(&detail, "detail", false, "list every module with its verification class and the reason recorded for it")
	return cmd
}

// runVerificationCoverage loads the walk and reports over its graph. Unlike the
// coverage line on walk and audit — which is a side report and so goes to stderr
// — here the aggregate IS the command's answer, so it goes to stdout on both
// paths.
func runVerificationCoverage(
	ctx context.Context,
	walkID string,
	walks QueryWalksUseCase,
	records fetchRecordReader,
	detail bool,
	stdout, stderr io.Writer,
) error {
	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		if isWalkNotFound(err) {
			// ExitNotFound, not ExitConfig: the code exists so a script can tell
			// "no such record" from a policy denial, and this command is a new
			// surface with no older spelling to preserve.
			return walkIDMiss(ctx, walks, walkID, stderr)
		}
		if isWalkIntegrity(err) {
			return &exitError{code: ExitIntegrity, msg: fmt.Sprintf("walk record %q failed integrity check", walkID)}
		}
		return fmt.Errorf("getting walk: %w", err)
	}

	rows := graphVerificationRows(ctx, rec.Graph.Nodes, records)
	obs := make([]fetchdomain.CoverageObservation, 0, len(rows))
	for _, r := range rows {
		obs = append(obs, r.observation)
	}
	coverage := fetchdomain.VerificationCoverageOf(obs)
	// The walk's project directory is provenance, never an oracle: a tree that
	// has moved or gone answers "unknown", which the disclosure states by saying
	// nothing rather than by reporting a project as unvendored on the strength of
	// a path that no longer resolves.
	vendoring := detectBuildVendoringInDir(rec.ProjectDir)

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(verificationCoverageJSON(rec.ID, coverage, rows, vendoring, walkBuildOf(rec))); encErr != nil {
			return fmt.Errorf("encoding coverage: %w", encErr)
		}
		return nil
	}

	if _, werr := fmt.Fprintf(stdout, "walk %s\n", rec.ID); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	// Coverage is a statement about a graph, and which graph that is depends on
	// the platform and toolchain the walk resolved: build constraints select the
	// files that import the modules being counted, and the toolchain pins the
	// stdlib node among them.
	if berr := writeWalkBuild(stdout, rec, readerWalkToolchain(ctx, rec)); berr != nil {
		return berr
	}
	if verr := writeBuildVendoring(stdout, vendoring); verr != nil {
		return verr
	}
	if err := writeVerificationCoverage(stdout, coverage); err != nil {
		return err
	}
	if !detail {
		return nil
	}
	return writeVerificationDetail(stdout, rows)
}

// writeVerificationDetail lists every module with its class and its recorded
// reason. The rows keep the graph's order rather than being grouped by class:
// the reader arrived with a module in mind at least as often as with a class,
// and a stable order is what a diff between two runs needs.
//
// A module whose record recorded no reason says so in words rather than leaving
// the column blank. A blank reads as "nothing to report", which is the opposite
// of what an unrecorded basis means.
func writeVerificationDetail(stdout io.Writer, rows []moduleVerification) error {
	if len(rows) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "per-module verification (%d module(s)):\n", len(rows)); err != nil {
		return fmt.Errorf("writing detail header: %w", err)
	}
	for _, r := range rows {
		name := r.Coordinate
		if r.OriginalCoordinate != "" {
			name = r.Coordinate + " (replacing " + r.OriginalCoordinate + ")"
		}
		if _, err := fmt.Fprintf(stdout, "  %-36s %s\n    %s\n",
			r.Class, name, verificationReasonLine(r)); err != nil {
			return fmt.Errorf("writing detail row: %w", err)
		}
	}
	return nil
}

// verificationReasonLine renders one module's recorded basis: the status the
// record holds, and the prose it recorded beside it when it recorded any.
//
// A record with no status at all says so in words. Leaving the line blank would
// read as "nothing to report", which is the opposite of what an unrecorded basis
// means, and it is precisely the reading this whole surface exists to stop.
func verificationReasonLine(r moduleVerification) string {
	switch {
	case r.Status == "" && r.Reason == "":
		return "no verification status or reason is recorded for this module"
	case r.Reason == "":
		return "recorded status: " + r.Status
	case r.Status == "":
		return r.Reason
	default:
		return "recorded status: " + r.Status + " — " + r.Reason
	}
}

// coverageJSON is the machine-readable coverage document.
//
// The field names are a published contract, which is why this is a separate type
// rather than JSON tags on the domain aggregate: renaming a domain field is an
// internal refactor, and renaming one of these breaks a CI gate. The two are
// allowed to drift, and the mapping below is where that is decided.
//
// Every count is emitted even when zero. A gate asserting `.cross_verified == 0`
// must be able to distinguish a graph with no cross-verification from a document
// where the field was omitted, so omitempty is deliberately absent throughout.
type coverageJSON struct {
	WalkID string `json:"walk_id"`

	// Total is every node in the graph; the buckets below partition it.
	Total int `json:"total"`
	// Recorded is the modules a measurement was found for.
	Recorded int `json:"recorded"`
	// CrossVerifiable is the honest denominator for cross-verification: the
	// recorded modules that are not local source. Against Total, a project walk
	// would report a shortfall for its own main module, which has no remote
	// artefact to anchor.
	CrossVerifiable int `json:"cross_verifiable"`

	CrossVerified  int `json:"cross_verified"`
	ChecksumDBOnly int `json:"checksum_db_only"`
	GoSumOnly      int `json:"go_sum_only"`
	Unverified     int `json:"unverified"`
	LocalSource    int `json:"local_source"`
	Unrecorded     int `json:"unrecorded"`
	Unrecognised   int `json:"unrecognised"`

	// Collapsed is the condition this report exists to surface: a graph with
	// something to cross-verify, none of which was. It is derived rather than
	// left to the caller so every gate agrees on what a collapse is.
	Collapsed bool `json:"collapsed"`

	VCS coverageVCSJSON `json:"vcs"`

	// Build is what the coverage figures are about: the platform and toolchain
	// the walk was resolved under, and whether the project it was taken from
	// compiles from a vendored tree.
	//
	// It is emitted on every document. An unanswered question is stated as one —
	// vendoring_known is false where there was no project directory to look in,
	// and the platform and toolchain are empty where the walk recorded none —
	// which is a different statement from the key being absent, and neither may
	// decode as a negative answer.
	Build buildJSON `json:"build"`

	// Modules is every node with its class and the reason recorded for it. It is
	// always present on the JSON path — the classes without their reasons is
	// exactly the shape that sent readers to python3 over another command's
	// output, and a flag to opt into being told why is a flag to opt into an
	// answer that can be checked.
	Modules []moduleVerification `json:"modules"`
}

// coverageVCSJSON is what the fetch ledger says, which the status cannot: not
// how strong the assurance is but how fresh, and whether the record can speak to
// it at all.
type coverageVCSJSON struct {
	Rechecked int `json:"rechecked"`
	Inherited int `json:"inherited"`
	// Never is the only class where no cross-verification evidence exists.
	Never int `json:"never"`
	// NotMeasured is a record that predates the ledger and carries no legs. It
	// is NOT the same as never: the check may well have run, the record simply
	// cannot say, and a gate that treats the two alike calls an unmigrated
	// store a collapse.
	NotMeasured int `json:"not_measured"`
}

func verificationCoverageJSON(
	walkID string,
	c fetchdomain.VerificationCoverage,
	rows []moduleVerification,
	vendoring buildVendoring,
	env walkBuildJSON,
) coverageJSON {
	if rows == nil {
		rows = []moduleVerification{}
	}
	return coverageJSON{
		Build:           buildJSON{buildVendoring: vendoring, walkBuildJSON: env},
		Modules:         rows,
		WalkID:          walkID,
		Total:           c.Total,
		Recorded:        c.Recorded(),
		CrossVerifiable: c.CrossVerifiable(),
		CrossVerified:   c.CrossVerified,
		ChecksumDBOnly:  c.ChecksumDBOnly,
		GoSumOnly:       c.GoSumOnly,
		Unverified:      c.Unverified,
		LocalSource:     c.LocalSource,
		Unrecorded:      c.Unrecorded,
		Unrecognised:    c.Unrecognised,
		Collapsed:       c.IsCollapsed(),
		VCS: coverageVCSJSON{
			Rechecked:   c.VCSRechecked,
			Inherited:   c.VCSInherited,
			Never:       c.VCSNever,
			NotMeasured: c.VCSNotMeasured,
		},
	}
}
