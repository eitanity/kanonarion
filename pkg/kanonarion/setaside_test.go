package kanonarion_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"

	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// The set-aside and unreadable-row types are the internal ones, so a consumer
// matching the façade name matches what the stores return.
var (
	_ *kanonarion.SetAside        = (*recordseal.SetAside)(nil)        //nolint:errcheck // a compile-time type identity, not a call
	_ *kanonarion.NothingServable = (*recordseal.NothingServable)(nil) //nolint:errcheck // as above
	_ kanonarion.SetAsideRow      = recordseal.SetAsideRow{}
	_ *kanonarion.UnreadableRows  = (*vulnports.UnreadableRows)(nil) //nolint:errcheck // as above
	_ kanonarion.UnreadableRow    = vulnports.UnreadableRow{}
)

// A library caller that passes WithSetAsideReporter receives the record a
// store set aside, and the read it made matches the façade's NothingServable;
// one that passes none still gets the refusal.
func TestOpen_SetAsideReachesTheLibraryCaller(t *testing.T) {
	root := t.TempDir()
	_, cleanup, err := kanonarion.Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	const walkID = "01HZTEST0000000000000LIB01"
	seal := seedDriftedWalk(t, filepath.Join(root, "mirror.db"), walkID)

	var got []kanonarion.SetAsideRow
	queries, cleanup, err := kanonarion.Open(root, kanonarion.WithSetAsideReporter(func(rows []kanonarion.SetAsideRow) {
		got = append(got, rows...)
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := cleanup(); cerr != nil {
			t.Errorf("closing: %v", cerr)
		}
	})

	_, err = queries.Walks.GetWalk(context.Background(), walkID)
	var none *kanonarion.NothingServable
	if !errors.As(err, &none) || !errors.Is(err, kanonarion.ErrGenerationDrift) {
		t.Fatalf("GetWalk = %v, want *kanonarion.NothingServable", err)
	}
	if len(got) != 1 || got[0].ContentHash != seal || got[0].ID != walkID {
		t.Errorf("reporter received %+v, want the walk named by %s", got, seal)
	}
}

func seedDriftedWalk(t *testing.T, dbPath, walkID string) string {
	t.Helper()
	db, err := sqlitestore.Open(dbPath, nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	target := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	at := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	rec := walkdomain.NewWalkRecord(walkID, "lib", "1", walkdomain.WalkScopeCode, walkdomain.WalkDepthFull,
		walkdomain.WalkOutcome{
			Target: target,
			Graph: walkdomain.Graph{Target: target, ResolvedAt: at,
				Nodes: []walkdomain.GraphNode{{Coordinate: target, ResolutionSource: walkdomain.ResolutionTarget}}},
			StartedAt: at, CompletedAt: at.Add(time.Second), OverallStatus: walkdomain.WalkSucceeded,
		}, walkdomain.DefaultDepthPolicy(), "")
	rec, err = walkdomain.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := walksqlite.New(db).PutWalk(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	raw, merr := walkdomain.WalkRecordHasher{}.Marshal(rec)
	if merr != nil {
		t.Fatalf("Marshal: %v", merr)
	}
	widened := append([]byte(`{"retired_field":"x",`), raw[1:]...)
	stamped := []byte(`"content_hash":"` + rec.ContentHash + `"`)
	sum := sha256.Sum256(bytes.Replace(widened, stamped, []byte(`"content_hash":""`), 1))
	seal := "sha256:" + hex.EncodeToString(sum[:])
	widened = bytes.Replace(widened, stamped, []byte(`"content_hash":"`+seal+`"`), 1)
	if _, err := db.DB().Exec(`UPDATE walks SET serialised = ?, content_hash = ? WHERE id = ?`,
		blobcodec.Encode(widened), seal, walkID); err != nil {
		t.Fatal(err)
	}
	return seal
}
