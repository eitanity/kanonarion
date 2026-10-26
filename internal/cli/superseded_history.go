package cli

import (
	"context"
	"fmt"

	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// supersededReader names the artefacts of a published coordinate that the
// fetch ledger holds only as local-source measurements.
type supersededReader interface {
	SupersededArtefacts(ctx context.Context, coord coordinate.ModuleCoordinate) (map[string]bool, error)
}

// supersededLine is how a history view marks a generation no read composes.
const supersededLine = "    superseded by identity: derived from a directory read under this published coordinate; not composed\n"

// History use cases carrying the fetch reader, so the history views can mark
// superseded generations without widening the run functions every test calls.
type (
	licenceHistoryUC struct {
		QueryLicenseUseCase
		supersededReader
	}
	interfaceHistoryUC struct {
		QueryInterfaceUseCase
		supersededReader
	}
	examplesHistoryUC struct {
		QueryExamplesUseCase
		supersededReader
	}
	callGraphShowUC struct {
		QueryCallGraphUseCase
		supersededReader
		localDependencyCheck
	}
)

// WorktreeRouting forwards the wrapped use case's optional capability, which
// embedding the interface would otherwise hide.
func (u callGraphShowUC) WorktreeRouting(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgports.WorktreeRouting, bool, error) {
	if r, ok := u.QueryCallGraphUseCase.(worktreeRouter); ok {
		return r.WorktreeRouting(ctx, coord, pipelineVersion) //nolint:wrapcheck // forwarded as the wrapped use case returns it
	}
	return cgports.WorktreeRouting{}, false, nil
}

// localDependencyCheck tells a dependency a project walk read from disk apart
// from a project root: both sit at <path>@local, but only the root is the
// target of a walk.
type localDependencyCheck struct {
	fetch fetchRecordReader
	walks QueryWalksUseCase
}

// IsLocalDependency reports a @local coordinate the fetch ledger holds a
// measurement of and no walk is rooted at.
func (c localDependencyCheck) IsLocalDependency(ctx context.Context, coord coordinate.ModuleCoordinate) bool {
	if c.fetch == nil || c.walks == nil || !coord.IsLocal() {
		return false
	}
	if _, found, err := c.fetch.ComposeFetchRecord(ctx, coord); err != nil || !found {
		return false
	}
	rooted, err := c.walks.ListWalks(ctx, walkports.WalkFilter{Target: &coord, Limit: 1})
	return err == nil && len(rooted) == 0
}

// localDependencyRemedy is the analysis of a dependency read from disk: by
// coordinate, from the record the walk stored, never from a working tree.
func localDependencyRemedy(ctx context.Context, uc any, coord coordinate.ModuleCoordinate) (string, bool) {
	c, ok := uc.(interface {
		IsLocalDependency(ctx context.Context, coord coordinate.ModuleCoordinate) bool
	})
	if !ok || !c.IsLocalDependency(ctx, coord) {
		return "", false
	}
	return "kanonarion callgraph " + coord.String() + targetFlagHint() +
		" (or 'kanonarion extract <walk-id> --stages callgraph' over the project walk that read it)", true
}

// asSupersededReader returns the container's fetch reader when it can name
// superseded artefacts, and a reader that names none otherwise.
func asSupersededReader(fetch any) (supersededReader, bool) {
	if r, ok := fetch.(supersededReader); ok && r != nil {
		return r, true
	}
	return noSuperseded{}, false
}

// noSuperseded is the reader of a store that cannot name superseded artefacts.
type noSuperseded struct{}

func (noSuperseded) SupersededArtefacts(context.Context, coordinate.ModuleCoordinate) (map[string]bool, error) {
	return nil, nil
}

// supersededFor reads the superseded artefacts of coord through uc when uc
// carries a reader, and none otherwise.
func supersededFor(ctx context.Context, uc any, coord coordinate.ModuleCoordinate) (map[string]bool, error) {
	r, ok := uc.(supersededReader)
	if !ok || r == nil {
		return nil, nil
	}
	ids, err := r.SupersededArtefacts(ctx, coord)
	if err != nil {
		return nil, fmt.Errorf("reading superseded local generations of %s: %w", coord, err)
	}
	return ids, nil
}

// supersededNote is the mark under a generation whose artefact is superseded,
// and nothing under any other.
func supersededNote(superseded map[string]bool, artefact string) string {
	if superseded[artefact] {
		return supersededLine
	}
	return ""
}

// supersededOnlyRefusal is the refusal for a published coordinate whose every
// generation derives from a directory read under it before local code had its
// own identity: they are held, and none answers. nil when that is not the case
// or uc cannot say.
func supersededOnlyRefusal(ctx context.Context, uc any, coord coordinate.ModuleCoordinate, artefacts []string, remedy string) error {
	if len(artefacts) == 0 || coord.IsLocal() {
		return nil
	}
	superseded, err := supersededFor(ctx, uc, coord)
	if err != nil {
		return err
	}
	for _, a := range artefacts {
		if !superseded[a] {
			return nil
		}
	}
	return &exitError{code: ExitNotFound, msg: fetchdomain.SupersededOnlyStatement(len(artefacts), coord) +
		"; measure the published module: " + remedy}
}
