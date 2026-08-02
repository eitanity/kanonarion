package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// JudgeToolchain derives whether the advisory database's toolchain key says
// anything about the toolchain version a walk was built under.
//
// It is a read, not a measurement: the snapshot is one the store already holds
// and the version is one the walk already recorded, so nothing is fetched and
// nothing is written. That is deliberate — the judgment carries no record shape,
// owes no pipeline version, and classifies every walk ever taken the moment it
// exists.
//
// The toolchain key is disjoint from stdlib: it covers cmd/go, the compiler and
// the linker, which no scanned project imports and which no reachability
// analysis of project code can reach. Asking the stdlib node instead would
// answer a different question, so this asks the key by name.
//
// A snapshot the database cannot read at all is an error; a snapshot that is
// simply too old to carry the key is not, and comes back as an unjudged
// judgment naming that as the reason.
func (uc *ScanWalkUseCase) JudgeToolchain(ctx context.Context, snapshot domain.DatabaseSnapshot, toolchainVersion string) (domain.ToolchainJudgment, error) {
	if toolchainVersion == "" || snapshot.IsZero() {
		// Nothing to read: JudgeToolchain states which input was missing.
		return domain.JudgeToolchain(toolchainVersion, snapshot, domain.ToolchainAdvisorySet{}), nil
	}
	set, err := uc.moduleScanner.database.SnapshotToolchainAdvisories(ctx, snapshot)
	if err != nil {
		return domain.ToolchainJudgment{}, fmt.Errorf("reading the toolchain advisories of snapshot %s@%s: %w",
			snapshot.Source(), snapshot.Version(), err)
	}
	return domain.JudgeToolchain(toolchainVersion, snapshot, set), nil
}
