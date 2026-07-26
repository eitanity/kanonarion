package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	blobstore "github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// blobAdoptionMarker is the file whose presence means the one-time re-addressing
// below has already run for this store.
const blobAdoptionMarker = ".blobs-adopted"

// adoptLegacyBlobs re-addresses artefacts written under the old store-chosen
// blob handles so they are reachable by artefact identity.
//
// The blob store used to choose its own address — the SHA-256 of whatever bytes
// it was handed — and that address was written into the fact record. Artefacts
// are now addressed by the h1 identity the fetch pipeline measured, so without
// this pass every artefact already on disk would read as absent the instant the
// addressing changed, and a store built up over months would silently re-download
// itself. Absence is a legitimate state (it simply re-acquires), which is exactly
// why the loss would be silent, and exactly why it must not be left to happen.
//
// The fact records carry both the old handle and the artefact's h1, so the
// mapping is known exactly and nothing is guessed. Each artefact is hard-linked
// to its new address: the old path keeps working, the new one is live
// immediately, and the two names share one inode so the pass costs no disk.
//
// It runs once per store, guarded by a marker file, and is best-effort by
// design. A blob that cannot be adopted is reported and skipped rather than
// failing the command: the artefact reads as absent and is re-acquired, which is
// ordinary behaviour, whereas refusing to start would make an unreadable store
// unusable rather than merely slower.
func adoptLegacyBlobs(db sqlitestore.DB, blobs *blobstore.Store, storeRoot string, logger *slog.Logger) error {
	marker := filepath.Join(storeRoot, blobAdoptionMarker)
	if _, err := os.Stat(marker); err == nil {
		return nil
	}

	const q = `SELECT module_hash, go_mod_hash, content_location, go_mod_location FROM fetch_records`
	rows, err := db.DB().Query(q) //nolint:rowserrcheck // rows.Err is checked after the loop
	if err != nil {
		return fmt.Errorf("reading fetch records to re-address blobs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var adopted, skipped int
	for rows.Next() {
		var moduleHash, goModHash, contentLocation, goModLocation string
		if err := rows.Scan(&moduleHash, &goModHash, &contentLocation, &goModLocation); err != nil {
			return fmt.Errorf("scanning fetch record to re-address blobs: %w", err)
		}
		for _, artefact := range []struct {
			kind   fetchports.BlobKind
			hash   string
			legacy string
		}{
			{fetchports.BlobKindZip, moduleHash, contentLocation},
			{fetchports.BlobKindGoMod, goModHash, goModLocation},
		} {
			h, perr := fetchdomain.ParseModuleHash(artefact.hash)
			if perr != nil || h.IsZero() || artefact.legacy == "" {
				continue
			}
			ok, aerr := blobs.AdoptLegacyBlob(fetchports.BlobIdentity{Kind: artefact.kind, Hash: h}, artefact.legacy)
			switch {
			case aerr != nil:
				logger.Warn("blob_readdress_failed",
					slog.String("legacy_handle", artefact.legacy),
					slog.String("error", aerr.Error()),
				)
				skipped++
			case ok:
				adopted++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating fetch records to re-address blobs: %w", err)
	}

	if adopted > 0 || skipped > 0 {
		logger.Info("blobs_readdressed_by_artefact_identity",
			slog.Int("adopted", adopted),
			slog.Int("skipped", skipped),
		)
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		return fmt.Errorf("recording blob re-addressing marker: %w", err)
	}
	return nil
}
