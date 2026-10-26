// Package application measures a TinyGo release archive against the digest
// GitHub publishes for it, serving a held measurement when there is one.
package application

import (
	"context"
	"fmt"
	"log/slog"

	"code.eitanity.com/kanonarion/internal/tinygo/domain"
	"code.eitanity.com/kanonarion/internal/tinygo/ports"
)

// Acquirer measures release archives. It never fails: a leg that cannot run is
// a measurement whose outcome says so, with the reason.
type Acquirer struct {
	index   ports.ReleaseIndex
	archive ports.ArchiveReader
	store   ports.Store
	clock   ports.Clock
	logger  *slog.Logger
	// offline serves held measurements only, so no request leaves the machine.
	offline bool
}

// NewAcquirer wires an acquirer that reaches GitHub on a miss. A nil store keeps
// nothing and serves nothing.
func NewAcquirer(index ports.ReleaseIndex, archive ports.ArchiveReader, store ports.Store, clock ports.Clock, logger *slog.Logger) *Acquirer {
	return &Acquirer{index: index, archive: archive, store: store, clock: clock, logger: logger}
}

// NewOfflineAcquirer wires an acquirer that serves held measurements and
// reaches nothing.
func NewOfflineAcquirer(store ports.Store, clock ports.Clock, logger *slog.Logger) *Acquirer {
	return &Acquirer{store: store, clock: clock, logger: logger, offline: true}
}

// Acquire returns the measurement of version's archive for goos/goarch: the held
// one unless force is set, otherwise a new one, which is kept unless it only
// says the release could not be reached. force does not reach the network
// offline.
func (a *Acquirer) Acquire(ctx context.Context, version, goos, goarch string, force bool) domain.Measurement {
	asset := domain.AssetName(version, goos, goarch)
	m := domain.Measurement{Version: version, Asset: asset}
	if goos == "" || goarch == "" {
		return unmeasured(m, domain.Unavailable, "tinygo version reported no host platform, so no release archive can be named")
	}
	if a.store != nil && (!force || a.offline) {
		held, ok, err := a.store.Latest(ctx, version, asset)
		if err != nil {
			a.logger.WarnContext(ctx, "tinygo.release.store_unreadable", slog.String("tinygo.asset", asset), slog.String("error", err.Error()))
		}
		if ok {
			return held
		}
	}
	if a.offline {
		return unmeasured(m, domain.Unavailable, domain.ReasonOffline)
	}
	m = a.measure(ctx, m)
	if a.store != nil && m.Outcome.Kept() {
		if err := a.store.Append(ctx, m); err != nil {
			a.logger.WarnContext(ctx, "tinygo.release.not_recorded", slog.String("tinygo.asset", asset), slog.String("error", err.Error()))
		}
	}
	return m
}

func (a *Acquirer) measure(ctx context.Context, m domain.Measurement) domain.Measurement {
	tag := domain.Tag(m.Version)
	assets, found, err := a.index.Assets(ctx, tag)
	if err != nil {
		return unmeasured(m, domain.Unavailable, fmt.Sprintf("the TinyGo release %s could not be read: %v", tag, err))
	}
	if !found {
		return a.permanent(m, domain.AssetAbsent, fmt.Sprintf("TinyGo publishes no release %s", tag))
	}
	var listed *ports.Asset
	for i := range assets {
		if assets[i].Name == m.Asset {
			listed = &assets[i]
		}
	}
	if listed == nil {
		return a.permanent(m, domain.AssetAbsent, fmt.Sprintf("the TinyGo release %s has no asset %s", tag, m.Asset))
	}
	m.URL = listed.URL
	m.PublishedDigest = domain.PublishedSHA256(listed.Digest)
	if m.PublishedDigest == "" {
		return a.permanent(m, domain.NoDigest, fmt.Sprintf("the TinyGo release %s publishes no SHA-256 digest for %s", tag, m.Asset))
	}
	archive, err := a.archive.Read(ctx, listed.URL, m.Asset)
	if err != nil {
		return unmeasured(m, domain.Unavailable, fmt.Sprintf("the release archive %s could not be read: %v", m.Asset, err))
	}
	m.ObservedDigest, m.MeasuredAt = archive.SHA256, a.clock.Now().UTC()
	if m.ObservedDigest != m.PublishedDigest {
		m.Outcome = domain.DigestMismatch
		m.Reason = fmt.Sprintf("the release archive %s hashes to %s, not the published %s", m.Asset, m.ObservedDigest, m.PublishedDigest)
		return m
	}
	m.Outcome, m.Manifest = domain.DigestMatched, archive.Manifest
	domain.SortManifest(m.Manifest)
	return m
}

// permanent is a fact about the release that names no archive bytes; it is
// kept, so it carries the time it was read.
func (a *Acquirer) permanent(m domain.Measurement, o domain.Outcome, reason string) domain.Measurement {
	m.Outcome, m.Reason, m.Manifest, m.MeasuredAt = o, reason, nil, a.clock.Now().UTC()
	return m
}

// unmeasured is a transient outcome: it is not kept and carries no time.
func unmeasured(m domain.Measurement, o domain.Outcome, reason string) domain.Measurement {
	m.Outcome, m.Reason, m.Manifest = o, reason, nil
	return m
}
