package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	blobstore "github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
)

// A record whose hash does not parse cannot have its legacy blob re-addressed.
// That is counted and logged, never passed over as a record with no blob; a
// recorded absence or a record with no legacy handle stays silent.
func TestAdoptRowBlobs_AHashThatDoesNotParseIsCountedAndLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	blobs := blobstore.New(t.TempDir())

	adopted, skipped := adoptRowBlobs(blobs, logger, "notahash", ":", "sha256:legacy-zip", "")
	if adopted != 0 || skipped != 1 {
		t.Errorf("adopted=%d skipped=%d, want 0 and 1", adopted, skipped)
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN msg=blob_readdress_failed") || !strings.Contains(out, "legacy-zip") || !strings.Contains(out, `invalid module hash \"notahash\"`) {
		t.Errorf("log = %q, want a warn naming the legacy handle and the parse error", out)
	}

	buf.Reset()
	adopted, skipped = adoptRowBlobs(blobs, logger, ":", "notahash", "", "")
	if adopted != 0 || skipped != 0 || buf.Len() != 0 {
		t.Errorf("control: adopted=%d skipped=%d log=%q, want a silent no-op for an absence and an empty handle", adopted, skipped, buf.String())
	}
}
