package sqlite_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/composition/storage"
	sqlitestorage "github.com/eitanity/kanonarion/internal/composition/storage/sqlite"
	"github.com/eitanity/kanonarion/internal/config"
)

func TestBackend_IsTheSQLiteBackendUnderItsOwnSection(t *testing.T) {
	b := sqlitestorage.Backend()
	if b.Name != "sqlite" || b.Section != "sqlite" || b.Open == nil {
		t.Fatalf("Backend() = %+v", b)
	}
	c, ok := b.Defaults.(config.Commented)
	if !ok || !strings.Contains(c.ConfigComment(), "derive from the store") {
		t.Errorf("Defaults carry no comment on the store-root paths: %+v", b.Defaults)
	}

	root := t.TempDir()
	for _, section := range [][]byte{nil, []byte("{}\n")} {
		st, err := b.Open(context.Background(), storage.Request{StoreRoot: root, Intent: storage.IntentCreate, Section: section})
		if err != nil {
			t.Fatalf("Open with section %q: %v", section, err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "mirror.db")); err != nil {
		t.Errorf("the backend opened no database: %v", err)
	}
}

// A key in the sqlite section is a setting the backend does not have, so it is
// refused rather than ignored, and nothing is opened.
func TestBackend_RefusesASettingItDoesNotHave(t *testing.T) {
	root := t.TempDir()
	_, err := sqlitestorage.Backend().Open(context.Background(), storage.Request{
		StoreRoot: root, Intent: storage.IntentCreate, Section: []byte("path: /elsewhere\n"),
	})
	if err == nil || !strings.Contains(err.Error(), "config.yaml section sqlite") || !strings.Contains(err.Error(), "path") {
		t.Fatalf("Open = %v, want the unknown key refused", err)
	}
	if entries, rerr := os.ReadDir(root); rerr != nil || len(entries) != 0 {
		t.Errorf("the refusal left %v (%v)", entries, rerr)
	}
}

func TestOpen_InspectIntentRefusesARootWithNoDatabase(t *testing.T) {
	root := t.TempDir()
	_, err := sqlitestorage.Open(storage.Request{StoreRoot: root, Intent: storage.IntentInspect})
	var notFound *storage.NotFoundError
	if !errors.As(err, &notFound) || notFound.Location != filepath.Join(root, "mirror.db") {
		t.Fatalf("Open = %v, want a NotFoundError naming mirror.db", err)
	}
	if entries, rerr := os.ReadDir(root); rerr != nil || len(entries) != 0 {
		t.Errorf("the inspection left %v (%v)", entries, rerr)
	}
}
