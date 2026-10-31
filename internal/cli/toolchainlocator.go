package cli

import (
	"context"
	"errors"
	"fmt"

	vulnports "code.eitanity.com/kanonarion/internal/vuln/ports"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// walkProjectDirs answers where a walk's working tree is, for the refusals that
// have to name the command analysing it.
//
// It reads one column of the walk the record names. The directory is recorded
// and was being ignored: a project-rooted frame whose tree the ledger names was
// being told "no stored record names the working tree", which the store itself
// contradicts.
type walkProjectDirs struct {
	walks QueryWalksUseCase
}

// WalkProjectDir returns the directory the walk was rooted at. A walk that
// records none — a coordinate walk — answers false, and so does a store that
// would not answer: a directory that is not known is never guessed.
func (w walkProjectDirs) WalkProjectDir(ctx context.Context, walkID string) (string, bool, error) {
	if w.walks == nil || walkID == "" {
		return "", false, nil
	}
	rec, err := w.walks.GetWalk(ctx, walkID)
	if err != nil {
		return "", false, fmt.Errorf("reading walk %s for its project directory: %w", walkID, err)
	}
	if rec.ProjectDir == "" {
		return "", false, nil
	}
	return rec.ProjectDir, true, nil
}

// WalkModules returns the modules the walk selected, the standard library,
// TinyGo and the walk's own target excluded. It reads the same record WalkProjectDir does.
func (w walkProjectDirs) WalkModules(ctx context.Context, walkID string) ([]vulnports.BuildModule, bool, error) {
	if w.walks == nil || walkID == "" {
		return nil, false, nil
	}
	rec, err := w.walks.GetWalk(ctx, walkID)
	if errors.Is(err, walkports.ErrWalkNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading walk %s for its build list: %w", walkID, err)
	}
	var out []vulnports.BuildModule
	for _, n := range rec.Graph.Nodes {
		if n.ResolutionSource == walkdomain.ResolutionStdlib || n.ResolutionSource == walkdomain.ResolutionTinyGo || n.Coordinate.IsLocal() || n.Coordinate.IsZero() {
			continue
		}
		out = append(out, vulnports.BuildModule{
			Coordinate:   n.Coordinate,
			LocalReplace: n.ResolutionSource == walkdomain.ResolutionLocalReplace,
		})
	}
	return out, true, nil
}
