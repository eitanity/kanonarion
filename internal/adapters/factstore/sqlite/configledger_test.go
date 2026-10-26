package sqlite

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/audit"
)

func driftEvent(old, new string) audit.Event {
	return audit.Event{Type: audit.EventConfigDriftObserved, Payload: map[string]any{"old_hash": old, "new_hash": new}}
}

// record appends e as the CLI does under the SQLite backend: through the
// store's log, with the marker told before and after.
func record(l *ConfigHashMarker, root string, e audit.Event, hash string) error {
	if err := l.BeforeConfigHashAppend(); err != nil {
		return err
	}
	if err := NewAuditLog(AuditLogPath(root)).RecordEvent(e); err != nil {
		return err
	}
	return l.AfterConfigHashAppend(hash)
}

func lastHash(t *testing.T, l *ConfigHashMarker) (string, bool) {
	t.Helper()
	h, found, err := l.LastConfigHash()
	if err != nil {
		t.Fatalf("LastConfigHash: %v", err)
	}
	return h, found
}

func TestConfigHashMarker_NoLogRecordsNoHash(t *testing.T) {
	if h, found := lastHash(t, NewConfigHashMarker(t.TempDir())); found || h != "" {
		t.Errorf("an absent log answered %q, %v", h, found)
	}
}

func TestConfigHashMarker_RecordMovesTheHashAndAnOverrideDoesNot(t *testing.T) {
	root := t.TempDir()
	l := NewConfigHashMarker(root)
	if err := record(l, root, driftEvent("", "sha256:a"), "sha256:a"); err != nil {
		t.Fatal(err)
	}
	if err := record(l, root, audit.Event{Type: audit.EventConfigChanged, Payload: map[string]any{"new_hash": "sha256:b"}}, "sha256:b"); err != nil {
		t.Fatal(err)
	}
	if err := NewAuditLog(AuditLogPath(root)).RecordEvent(audit.Event{Type: audit.EventConfigOverride, Payload: map[string]any{"config_hash": "sha256:b"}}); err != nil {
		t.Fatal(err)
	}
	if h, _ := lastHash(t, l); h != "sha256:b" {
		t.Errorf("from the marker: %q, want sha256:b", h)
	}
	if err := os.Remove(filepath.Join(root, configMarkerName)); err != nil {
		t.Fatal(err)
	}
	if h, _ := lastHash(t, NewConfigHashMarker(root)); h != "sha256:b" {
		t.Errorf("from the log: %q, want sha256:b", h)
	}
	if _, err := os.Stat(filepath.Join(root, configMarkerName)); err != nil {
		t.Errorf("a scan did not re-seat the marker: %v", err)
	}
}

// The marker is a cache. One that is unreadable, empty or describes a longer
// log than the one on disk is ignored and the log answers.
func TestConfigHashMarker_AMarkerThatCannotSpeakForTheLogIsIgnored(t *testing.T) {
	for name, marker := range map[string]string{
		"garbage":     "{",
		"no hash":     `{"hash":"","ledger_size":1}`,
		"longer log":  `{"hash":"sha256:stale","ledger_size":999999999}`,
		"not a file?": "",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			l := NewConfigHashMarker(root)
			if err := record(l, root, driftEvent("", "sha256:real"), "sha256:real"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, configMarkerName), []byte(marker), 0o600); err != nil {
				t.Fatal(err)
			}
			if h, _ := lastHash(t, l); h != "sha256:real" {
				t.Errorf("got %q, want the log's sha256:real", h)
			}
		})
	}
}

// The scan reads backwards across chunk boundaries, skips torn lines and
// ignores a config event type quoted inside another event's payload.
func TestConfigHashMarker_ScanFindsTheNewestAcrossChunksAndSkipsNoise(t *testing.T) {
	root := t.TempDir()
	var b strings.Builder
	b.WriteString(`{"event_type":"config_drift_observed","timestamp":"t","payload":{"new_hash":"sha256:old"}}` + "\n")
	b.WriteString(`{"event_type":"config_changed","timestamp":"t","payload":{"new_hash":"sha256:new"}}` + "\n")
	pad := strings.Repeat("x", 1000)
	for i := 0; b.Len() < 3*configScanChunk; i++ {
		fmt.Fprintf(&b, `{"event_type":"fact_record_written","timestamp":"t","module_path":"%d%s"}`+"\n", i, pad)
	}
	b.WriteString(`{"event_type":"config_changed","timestamp":"t","payload":{"new_hash":""}}` + "\n")
	b.WriteString(`{"event_type":"walk_completed","timestamp":"t","payload":{"note":"\"event_type\":\"config_changed\"","new_hash":"sha256:wrong"}}` + "\n")
	b.WriteString(`{"event_type":"config_changed", torn` + "\n")
	if err := os.WriteFile(AuditLogPath(root), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if h, found := lastHash(t, NewConfigHashMarker(root)); !found || h != "sha256:new" {
		t.Errorf("got %q, %v; want sha256:new", h, found)
	}
}

func TestConfigHashMarker_ALogWithNoConfigEventRecordsNone(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(AuditLogPath(root), []byte(`{"event_type":"walk_completed","timestamp":"t"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if h, found := lastHash(t, NewConfigHashMarker(root)); found || h != "" {
		t.Errorf("got %q, %v", h, found)
	}
}

// A failed append leaves no marker, so the next read asks the log rather than
// trusting a hash the log never recorded.
func TestConfigHashMarker_AFailedAppendLeavesNoMarker(t *testing.T) {
	root := t.TempDir()
	l := NewConfigHashMarker(root)
	if err := record(l, root, driftEvent("", "sha256:a"), "sha256:a"); err != nil {
		t.Fatal(err)
	}
	if err := record(l, root, audit.Event{Type: "not_a_type"}, "sha256:b"); err == nil {
		t.Fatal("an invalid event was appended")
	}
	if _, err := os.Stat(filepath.Join(root, configMarkerName)); !os.IsNotExist(err) {
		t.Errorf("marker survived a failed append: %v", err)
	}
	if h, _ := lastHash(t, l); h != "sha256:a" {
		t.Errorf("got %q, want sha256:a", h)
	}
}

func TestConfigHashMarker_UnreadableLogIsAnError(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(AuditLogPath(root), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewConfigHashMarker(root).LastConfigHash(); err == nil {
		t.Error("a log that cannot be read answered")
	}
}

func TestConfigHashMarker_TheFirstLineIsRead(t *testing.T) {
	root := t.TempDir()
	log := `{"event_type":"config_changed","timestamp":"t","payload":{"new_hash":"sha256:first"}}` + "\n" +
		`{"event_type":"walk_completed","timestamp":"t"}` + "\n"
	if err := os.WriteFile(AuditLogPath(root), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	if h, found := lastHash(t, NewConfigHashMarker(root)); !found || h != "sha256:first" {
		t.Errorf("got %q, %v; want sha256:first", h, found)
	}
}

// A config event cut in two by a chunk boundary is joined before it is read.
func TestConfigHashMarker_ALineAcrossAChunkBoundaryIsJoined(t *testing.T) {
	root := t.TempDir()
	cfg := `{"event_type":"config_changed","timestamp":"t","payload":{"new_hash":"sha256:split"}}` + "\n"
	filler := `{"event_type":"walk_completed","timestamp":"t","payload":{"note":"` + strings.Repeat("f", 200) + `"}}` + "\n"
	want := configScanChunk - len(cfg)/2 // the boundary falls mid-line
	var b strings.Builder
	b.WriteString(cfg)
	for b.Len()-len(cfg)+len(filler) <= want {
		b.WriteString(filler)
	}
	pad := want - (b.Len() - len(cfg)) - len(`{"event_type":"walk_completed","timestamp":"t","payload":{"note":""}}`+"\n")
	b.WriteString(`{"event_type":"walk_completed","timestamp":"t","payload":{"note":"` + strings.Repeat("g", pad) + `"}}` + "\n")
	if got := b.Len() - len(cfg); got != want {
		t.Fatalf("fixture tail is %d bytes, want %d", got, want)
	}
	if err := os.WriteFile(AuditLogPath(root), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if h, found := lastHash(t, NewConfigHashMarker(root)); !found || h != "sha256:split" {
		t.Errorf("got %q, %v; want sha256:split", h, found)
	}
}
