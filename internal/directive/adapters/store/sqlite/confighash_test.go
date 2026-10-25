package sqlite_test

import (
	"context"
	"encoding/json"
	directivesqlite "github.com/eitanity/kanonarion/internal/directive/adapters/store/sqlite"
	"strings"
	"testing"
	"time"
)

// A record written before the config hash was kept has no ConfigHash key in
// its stored bytes and still reads; a new one carries the hash back.
func TestConfigHash_OlderRecordReadsUnrecordedAndNewOneRoundTrips(t *testing.T) {
	ctx := context.Background()
	store := func() *directivesqlite.Store { s, _ := openTestStore(t); return s }()
	older := mkRecord(t, "scan-old", "example.com/cfg", time.Unix(1, 0))
	raw, err := json.Marshal(older)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ConfigHash") {
		t.Fatalf("a record with no hash grew a ConfigHash key: %s", raw)
	}
	if perr := store.PutDirectiveRecord(ctx, older); perr != nil {
		t.Fatal(perr)
	}
	got, found, err := store.GetDirectiveRecord(ctx, "example.com/cfg")
	if err != nil || !found {
		t.Fatalf("older record: found=%v err=%v", found, err)
	}
	if got.ConfigHash != "" {
		t.Errorf("older record read ConfigHash %q", got.ConfigHash)
	}

	newer := mkRecord(t, "scan-old", "example.com/cfg", time.Unix(1, 0))
	newer.ConfigHash = "sha256:cfg"
	newer.ID, newer.CompletedAt = "scan-new", time.Unix(2, 0)
	if perr := store.PutDirectiveRecord(ctx, newer); perr != nil {
		t.Fatal(perr)
	}
	if got, _, err = store.GetDirectiveRecord(ctx, "example.com/cfg"); err != nil || got.ConfigHash != "sha256:cfg" {
		t.Errorf("new record: ConfigHash %q err %v", got.ConfigHash, err)
	}
}
