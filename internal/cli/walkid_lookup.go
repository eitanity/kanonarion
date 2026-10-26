package cli

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"code.eitanity.com/kanonarion/internal/composition/storage"
	sbomdomain "code.eitanity.com/kanonarion/internal/sbom/domain"
	vuldomain "code.eitanity.com/kanonarion/internal/vuln/domain"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// annotationWalkIDArgs lists, comma-separated, the positional indices a command
// reads as walk ids. Flags need no declaration: walkIDFlags names them.
const annotationWalkIDArgs = "kanonarion/walk-id-args"

// walkIDFlags are the flags through which a command is handed a walk id.
var walkIDFlags = []string{"walk-id", "walk", "from-walk"}

// namedWalkIDs returns the walk ids an invocation names: its declared
// positionals, then its walk flags.
func namedWalkIDs(cmd *cobra.Command, args []string) (positional, flagged []string) {
	for _, field := range strings.Split(cmd.Annotations[annotationWalkIDArgs], ",") {
		i, err := strconv.Atoi(strings.TrimSpace(field))
		if err == nil && i < len(args) && args[i] != "" {
			positional = append(positional, args[i])
		}
	}
	for _, name := range walkIDFlags {
		fl := cmd.Flags().Lookup(name)
		if fl != nil && fl.Changed && fl.Value.Type() == "string" && fl.Value.String() != "" {
			flagged = append(flagged, fl.Value.String())
		}
	}
	return positional, flagged
}

// walkIDCheck is this invocation's pending walk-id lookup. It runs at the
// command's first store open, after the command's own argument refusals and
// against the store that open migrated, so a writer is refused before it writes.
type walkIDCheck struct {
	cmd    *cobra.Command
	args   []string
	stderr io.Writer
	done   bool
	// refusal is kept, so an open whose error a caller absorbs does not let the
	// next open through.
	refusal error
}

// walkIDLookup is the invocation's lookup, armed in PersistentPreRunE.
var walkIDLookup walkIDCheck

func (c *walkIDCheck) arm(cmd *cobra.Command, args []string, stderr io.Writer) {
	*c = walkIDCheck{cmd: cmd, args: args, stderr: stderr}
}

// beforeOpen answers a walk id on a store root that does not exist from the
// empty corpus, so the open that would create the store never happens.
func (c *walkIDCheck) beforeOpen(ctx context.Context, root string) error {
	if c.done || c.cmd == nil {
		return c.refusal
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		return nil
	}
	return c.settle(ctx, walkHolders{walks: noWalks{}})
}

// afterOpen runs the lookup once, over the store the command just opened.
func (c *walkIDCheck) afterOpen(ctx context.Context, st *storage.Storage) error {
	if c.done || c.cmd == nil {
		return c.refusal
	}
	held := walkHolders{walks: st.Walks}
	if st.Vulnerabilities != nil {
		held.runs = st.Vulnerabilities
	}
	if st.SBOMs != nil {
		held.sboms = st.SBOMs
	}
	return c.settle(ctx, held)
}

func (c *walkIDCheck) settle(ctx context.Context, held walkHolders) error {
	c.done = true
	if err := refuseMissingWalks(ctx, c.cmd, c.args, held, c.stderr); err != nil {
		c.refusal = &walkIDRefusal{err: err}
	}
	return c.refusal
}

// walkIDRefusal carries the lookup's answer through whatever the opening site
// wraps it in; Run prints it as itself.
type walkIDRefusal struct{ err error }

func (r *walkIDRefusal) Error() string { return r.err.Error() }

func (r *walkIDRefusal) Unwrap() error { return r.err }

// refuseMissingWalks answers a walk id the store does not hold the same way on
// every command (exit 4). A walk whose scan runs or SBOMs outlived it is still
// named by evidence, so the command answers from that; any other read failure
// is left to the command, which reports it as it always has.
func refuseMissingWalks(ctx context.Context, cmd *cobra.Command, args []string, held walkHolders, stderr io.Writer) error {
	positional, flagged := namedWalkIDs(cmd, args)
	if held.walks == nil {
		return nil
	}
	for _, id := range append(positional, flagged...) {
		if _, err := held.walks.GetWalk(ctx, id); !isWalkNotFound(err) || held.outlived(ctx, id) {
			continue
		}
		if len(positional) == 2 {
			return walkDiffMiss(ctx, held.walks, positional[0], positional[1], stderr)
		}
		return walkIDMiss(ctx, held.walks, id, stderr)
	}
	return nil
}

// walkHolders are the stores that can name a walk id: the walks themselves, and
// the records that outlive one.
type walkHolders struct {
	walks QueryWalksUseCase
	runs  interface {
		ListWalkScanRuns(ctx context.Context, walkID string) ([]vuldomain.WalkScanRun, error)
	}
	sboms interface {
		ListSBOMRecords(ctx context.Context, walkID string) ([]sbomdomain.SBOMRecord, error)
	}
}

// outlived reports whether a record still names a walk the store no longer
// holds. A read that fails counts as naming it: the command reads it again and
// says what it found.
func (h walkHolders) outlived(ctx context.Context, id string) bool {
	if h.runs != nil {
		if runs, err := h.runs.ListWalkScanRuns(ctx, id); err != nil || len(runs) > 0 {
			return true
		}
	}
	if h.sboms != nil {
		if sboms, err := h.sboms.ListSBOMRecords(ctx, id); err != nil || len(sboms) > 0 {
			return true
		}
	}
	return false
}

// noWalks is the walk corpus of a store root that holds no store.
type noWalks struct{}

func (noWalks) GetWalk(context.Context, string) (walkdomain.WalkRecord, error) {
	return walkdomain.WalkRecord{}, walkports.ErrWalkNotFound
}

func (noWalks) ListWalks(context.Context, walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	return nil, nil
}
