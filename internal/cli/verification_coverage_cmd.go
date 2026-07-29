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
// It exists as a command rather than as fields in `walk --json` or `audit
// --json` because both of those stdout channels are already spoken for: walk's
// is the content-hashed walk record, and audit's is a documented array of
// per-module rows that every existing consumer indexes into. A report about a
// run belongs in neither artefact, so the figures get a channel of their own,
// where the field names are a contract with nothing else to preserve.
//
// Reporting from a stored walk rather than recomputing also means the audit path
// is covered by the same code: an audit leaves the project walk behind, so the
// graph this reads is the graph the audit reported on.
func newVerificationCoverageCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verification-coverage <walk-id>",
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
assert on cross_verified or collapsed directly.`,
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
			return runVerificationCoverage(cmd.Context(), args[0], ctr.QueryWalks, ctr.QueryFetch, stdout)
		},
	}
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
	stdout io.Writer,
) error {
	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		if isWalkNotFound(err) {
			// ExitNotFound, not ExitConfig: the code exists so a script can tell
			// "no such record" from a policy denial, and this command is a new
			// surface with no older spelling to preserve.
			return &exitError{code: ExitNotFound, msg: fmt.Sprintf("walk record %q not found", walkID)}
		}
		if isWalkIntegrity(err) {
			return &exitError{code: ExitIntegrity, msg: fmt.Sprintf("walk record %q failed integrity check", walkID)}
		}
		return fmt.Errorf("getting walk: %w", err)
	}

	coverage := graphVerificationCoverage(ctx, rec.Graph.Nodes, records)

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(verificationCoverageJSON(rec.ID, coverage)); encErr != nil {
			return fmt.Errorf("encoding coverage: %w", encErr)
		}
		return nil
	}

	if _, werr := fmt.Fprintf(stdout, "walk %s\n", rec.ID); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	return writeVerificationCoverage(stdout, coverage)
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

func verificationCoverageJSON(walkID string, c fetchdomain.VerificationCoverage) coverageJSON {
	return coverageJSON{
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
