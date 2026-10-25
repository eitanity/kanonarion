package sqlite_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// A record written before the config hash was kept has no ConfigHash key in
// its stored bytes and still reads; a new one carries the hash back.
func TestConfigHash_OlderRecordReadsUnrecordedAndNewOneRoundTrips(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	older := mkRecord("example.com/cfg")
	raw, err := json.Marshal(older)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ConfigHash") {
		t.Fatalf("a record with no hash grew a ConfigHash key: %s", raw)
	}
	if perr := store.PutGoDebugRecord(ctx, older); perr != nil {
		t.Fatal(perr)
	}
	got, found, err := store.GetGoDebugRecord(ctx, "example.com/cfg")
	if err != nil || !found {
		t.Fatalf("older record: found=%v err=%v", found, err)
	}
	if got.ConfigHash != "" {
		t.Errorf("older record read ConfigHash %q", got.ConfigHash)
	}

	newer := mkRecord("example.com/cfg")
	newer.ConfigHash = "sha256:cfg"
	if perr := store.PutGoDebugRecord(ctx, newer); perr != nil {
		t.Fatal(perr)
	}
	if got, _, err = store.GetGoDebugRecord(ctx, "example.com/cfg"); err != nil || got.ConfigHash != "sha256:cfg" {
		t.Errorf("new record: ConfigHash %q err %v", got.ConfigHash, err)
	}
}
