// Package walkbridge adapts the TinyGo release acquirer to the walk stage's
// TinyGoReleaseAcquirer port, so the walk tree does not import this context.
package walkbridge

import (
	"context"

	"code.eitanity.com/kanonarion/internal/tinygo/application"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// Bridge serves the walk from an Acquirer.
type Bridge struct{ acq *application.Acquirer }

// New wraps acq as a walk TinyGoReleaseAcquirer.
func New(acq *application.Acquirer) *Bridge { return &Bridge{acq: acq} }

// AcquireTinyGoRelease maps the measurement onto the walk's projection of it.
func (b *Bridge) AcquireTinyGoRelease(ctx context.Context, version, goos, goarch string, force bool) walkdomain.TinyGoRelease {
	m := b.acq.Acquire(ctx, version, goos, goarch, force)
	return walkdomain.TinyGoRelease{
		Asset:           m.Asset,
		PublishedDigest: m.PublishedDigest,
		ObservedDigest:  m.ObservedDigest,
		Outcome:         walkdomain.TinyGoReleaseOutcome(m.Outcome),
		Reason:          m.Reason,
		MeasuredAt:      m.MeasuredAt,
		Manifest:        m.ManifestMap(),
	}
}

var _ walkports.TinyGoReleaseAcquirer = (*Bridge)(nil)
