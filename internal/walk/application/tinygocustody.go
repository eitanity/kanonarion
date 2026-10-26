package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"code.eitanity.com/kanonarion/internal/adapters/interrupt"
	"code.eitanity.com/kanonarion/internal/adapters/ziparchive"
	"code.eitanity.com/kanonarion/internal/coordinate"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
	domain3 "code.eitanity.com/kanonarion/internal/walk/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// WithTinyGoReleaseAcquirer returns a shallow copy of the resolver that
// establishes, on a TinyGo walk, whether the installed TinyGo source the build
// compiles is the source TinyGo released. Without one the TinyGo node carries
// no custody.
func (r *GraphResolver) WithTinyGoReleaseAcquirer(acq walkports.TinyGoReleaseAcquirer) *GraphResolver {
	clone := *r
	clone.tinygoRelease = acq
	return &clone
}

// establishTinyGoCustody attaches custody to the node carrying the TinyGo split.
// Like the stdlib's it is best-effort: a leg that cannot run leaves its files
// not established and logs one warning, and the walk goes on.
func (r *GraphResolver) establishTinyGoCustody(ctx context.Context, g *domain3.Graph, bl walkports.BuildList, force bool) {
	if r.tinygoRelease == nil || bl.TinyGo == nil {
		return
	}
	at := -1
	for i := range g.Nodes {
		if g.Nodes[i].TinyGo != nil {
			at = i
		}
	}
	released, ok := domain3.TinyGoNode(bl.TinyGoVersion, domain3.TinyGoFacts{})
	if at < 0 || !ok {
		return
	}
	in := r.tinygoModuleLeg(ctx, released.Coordinate, bl.TinyGoFiles)
	if interrupt.Stopped(ctx) {
		interrupt.Note(interrupt.TinyGoCustody)
		return
	}
	if in.ModuleFailure == "" && len(in.AbsentFromModule()) > 0 {
		rel := r.tinygoRelease.AcquireTinyGoRelease(ctx, bl.TinyGoVersion, bl.TinyGoHostGOOS, bl.TinyGoHostGOARCH, force)
		if interrupt.Stopped(ctx) {
			interrupt.Note(interrupt.TinyGoCustody)
			return
		}
		if rel.Outcome != domain3.TinyGoReleaseDigestMatched {
			r.logger.WarnContext(ctx, "walk.tinygo.custody.release_unavailable",
				slog.String("tinygo.asset", rel.Asset),
				slog.String("outcome", string(rel.Outcome)),
				slog.String("reason", rel.Reason),
			)
		}
		in.Release = &rel
	}
	custody := domain3.ClassifyTinyGoCustody(in)
	if len(custody.Differs) > 0 {
		r.logger.WarnContext(ctx, "walk.tinygo.custody.differs",
			slog.String("module", custody.Module),
			slog.Int("files", len(custody.Differs)),
		)
	}
	facts := *g.Nodes[at].TinyGo
	facts.Custody = &custody
	g.Nodes[at].TinyGo = &facts
}

// tinygoModuleLeg fetches TinyGo's module through the walk's own fetcher, so it
// is verified and recorded like any module, and hashes the src/<path> entry of
// every compiled file its zip carries. The zip is read through the blob store,
// which refuses bytes that do not hash to their identity.
func (r *GraphResolver) tinygoModuleLeg(ctx context.Context, coord coordinate.ModuleCoordinate, files []domain3.TinyGoSourceFile) domain3.TinyGoCustodyInput {
	in := domain3.TinyGoCustodyInput{Module: coord.String(), Files: files}
	status, entries, err := r.readTinyGoModule(ctx, coord, files)
	if err != nil {
		if !interrupt.Stopped(ctx) {
			r.logger.WarnContext(ctx, "walk.tinygo.custody.module_unavailable",
				slog.String("module", coord.String()),
				slog.String("error", err.Error()),
			)
		}
		in.ModuleFailure = err.Error()
		return in
	}
	in.ModuleVerification, in.ModuleFiles = status, entries
	return in
}

func (r *GraphResolver) readTinyGoModule(ctx context.Context, coord coordinate.ModuleCoordinate, files []domain3.TinyGoSourceFile) (string, map[string]string, error) {
	res, err := r.fetcher.EnsureFetched(ctx, coord)
	if err != nil {
		return "", nil, fmt.Errorf("fetching %s: %w", coord, err)
	}
	identity, hasZip, err := fetchports.ZipIdentity(res.Record.FactRecord)
	if err != nil {
		return "", nil, fmt.Errorf("deriving the zip address of %s: %w", coord, err)
	}
	if !hasZip {
		return "", nil, errors.New("the fetch record of " + coord.String() + " names no module zip")
	}
	data, err := r.readBlob(ctx, identity)
	if err != nil {
		return "", nil, fmt.Errorf("reading the module zip of %s: %w", coord, fetchports.AttributeBlobTamper(err, coord))
	}
	archive, err := ziparchive.New(data)
	if err != nil {
		return "", nil, fmt.Errorf("opening the module zip of %s: %w", coord, err)
	}
	entries := map[string]string{}
	prefix := coord.Path() + "@" + coord.Version() + "/src/"
	for _, f := range files {
		body, found, rerr := archive.ReadFile(prefix + f.Path)
		if rerr != nil {
			return "", nil, fmt.Errorf("reading src/%s from the module zip of %s: %w", f.Path, coord, rerr)
		}
		if found {
			sum := sha256.Sum256(body)
			entries[f.Path] = hex.EncodeToString(sum[:])
		}
	}
	return res.Record.VerificationStatus, entries, nil
}
