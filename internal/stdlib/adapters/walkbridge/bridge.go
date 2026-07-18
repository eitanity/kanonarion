// Package walkbridge adapts the standard-library acquisition use-case to the
// walk stage's StdlibAcquirer port. It lives outside the walk tree so the walk
// bounded context never imports stdlib: the composition root wires this bridge
// in, and the resolver depends only on the narrow walkports interface.
package walkbridge

import (
	"context"
	"fmt"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	stdlibapp "github.com/eitanity/kanonarion/internal/stdlib/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Bridge wraps a stdlib Acquisition (the online go.dev/dl Acquirer or the offline
// LocalAcquirer) and satisfies walkports.StdlibAcquirer, mapping the acquired
// facts onto the walk-domain shape the resolver attaches to the stdlib node.
type Bridge struct {
	acquirer stdlibapp.Acquisition
}

// New wraps an Acquisition as a walk StdlibAcquirer.
func New(acquirer stdlibapp.Acquisition) *Bridge { return &Bridge{acquirer: acquirer} }

// AcquireStdlib acquires the chain of custody and returns the walk-domain facts
// and the tarball digests separately, matching the resolver's expectation that
// digests live on GraphNode.Digests alongside every other node's.
func (b *Bridge) AcquireStdlib(ctx context.Context, goVersion string, force, skipVCS bool) (walkdomain.StdlibFacts, fetchdomain.ArtifactDigests, error) {
	facts, err := b.acquirer.Acquire(ctx, goVersion, stdlibapp.Options{Force: force, SkipVCS: skipVCS})
	if err != nil {
		return walkdomain.StdlibFacts{}, fetchdomain.ArtifactDigests{}, fmt.Errorf("acquiring stdlib custody: %w", err)
	}
	return walkdomain.StdlibFacts{
		LicenseSPDX:        facts.LicenseSPDX,
		VerificationStatus: string(facts.VerificationStatus),
		VerificationDetail: facts.VerificationDetail,
		PublishedSHA256:    facts.PublishedSHA256,
		SourceURL:          facts.SourceURL,
		VCSURL:             facts.VCSURL,
		VCSRef:             facts.VCSRef,
		VCSCommit:          facts.VCSCommit,
	}, facts.Digests, nil
}

var _ walkports.StdlibAcquirer = (*Bridge)(nil)
