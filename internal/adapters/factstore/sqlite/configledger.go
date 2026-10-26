package sqlite

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"code.eitanity.com/kanonarion/internal/audit"
)

// configMarkerName caches the last config hash the ledger recorded, so finding
// it costs one small read instead of a scan of the whole log.
const configMarkerName = "audit.config-hash"

// ConfigHashMarker answers which config hash a store's assurance log last
// recorded, for the SQLite backend's Storage.ConfigHashes.
//
// The log is the evidence and the marker only a cache of it. The marker is
// removed before each hash-setting append and rewritten after, so a crash
// between the two leaves no marker and the next read falls back to the log.
type ConfigHashMarker struct {
	path   string
	marker string
}

// NewConfigHashMarker returns the config hash marker of the store under storeRoot.
func NewConfigHashMarker(storeRoot string) *ConfigHashMarker {
	return &ConfigHashMarker{path: AuditLogPath(storeRoot), marker: filepath.Join(storeRoot, configMarkerName)}
}

// configMarker is the marker file's content. LedgerSize is the log's length
// after the append it describes: a shorter log was replaced, and the marker
// no longer speaks for it.
type configMarker struct {
	Hash       string `json:"hash"`
	LedgerSize int64  `json:"ledger_size"`
}

// LastConfigHash returns the new_hash of the last config_changed or
// config_drift_observed event; found is false when the log holds none.
func (l *ConfigHashMarker) LastConfigHash() (hash string, found bool, err error) {
	info, err := os.Stat(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading audit log %s: %w", l.path, err)
	}
	if raw, rerr := os.ReadFile(l.marker); rerr == nil { // #nosec G304 -- path constructed from operator-controlled store root
		var m configMarker
		if json.Unmarshal(raw, &m) == nil && m.Hash != "" && m.LedgerSize <= info.Size() {
			return m.Hash, true, nil
		}
	}
	hash, found, err = lastConfigHashInLog(l.path)
	if err != nil || !found {
		return hash, found, err
	}
	// Re-seat the cache so the scan is paid once. Failing to write it costs the
	// next command a scan, not a wrong answer.
	_ = l.writeMarker(hash) //nolint:errcheck // a cache miss, see above
	return hash, true, nil
}

// BeforeConfigHashAppend clears the marker ahead of an append that sets the hash.
func (l *ConfigHashMarker) BeforeConfigHashAppend() error {
	if err := os.Remove(l.marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clearing config hash marker: %w", err)
	}
	return nil
}

// AfterConfigHashAppend remembers hash, with the log's size after the append.
func (l *ConfigHashMarker) AfterConfigHashAppend(hash string) error { return l.writeMarker(hash) }

func (l *ConfigHashMarker) writeMarker(hash string) error {
	info, err := os.Stat(l.path)
	if err != nil {
		return fmt.Errorf("reading audit log %s: %w", l.path, err)
	}
	raw, err := json.Marshal(configMarker{Hash: hash, LedgerSize: info.Size()})
	if err != nil {
		return fmt.Errorf("encoding config hash marker: %w", err)
	}
	if err := os.WriteFile(l.marker, raw, 0o600); err != nil {
		return fmt.Errorf("writing config hash marker: %w", err)
	}
	return nil
}

// configScanChunk is how much of the log is read per step backwards.
const configScanChunk = 256 << 10

// configEventTypes are the events that set the recorded hash.
var configEventTypes = [][]byte{
	[]byte(`"event_type":"` + string(audit.EventConfigChanged) + `"`),
	[]byte(`"event_type":"` + string(audit.EventConfigDriftObserved) + `"`),
}

// lastConfigHashInLog reads the log backwards to the newest event that set
// the config hash, reusing two buffers so a long log costs time, not memory. A
// line that does not parse is skipped, as ReadLedger does.
func lastConfigHashInLog(path string) (string, bool, error) {
	f, err := os.Open(path) // #nosec G304 -- path constructed from operator-controlled store root
	if err != nil {
		return "", false, fmt.Errorf("opening audit log %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", false, fmt.Errorf("reading audit log %s: %w", path, err)
	}
	chunk := make([]byte, configScanChunk)
	var work, tail []byte // tail: a line cut by the chunk boundary, carried back
	for end := info.Size(); end > 0; {
		start := max(end-configScanChunk, 0)
		n := int(end - start)
		if _, err := f.ReadAt(chunk[:n], start); err != nil && !errors.Is(err, io.EOF) {
			return "", false, fmt.Errorf("reading audit log %s: %w", path, err)
		}
		work = append(append(work[:0], chunk[:n]...), tail...)
		rest := work
		for i := bytes.LastIndexByte(rest, '\n'); i >= 0; i = bytes.LastIndexByte(rest, '\n') {
			if hash, ok := configHashOfLine(rest[i+1:]); ok {
				return hash, true, nil
			}
			rest = rest[:i]
		}
		if start == 0 {
			hash, ok := configHashOfLine(rest)
			return hash, ok, nil
		}
		tail = append(tail[:0], rest...)
		end = start
	}
	return "", false, nil
}

func configHashOfLine(line []byte) (string, bool) {
	matched := false
	for _, t := range configEventTypes {
		matched = matched || bytes.Contains(line, t)
	}
	if !matched {
		return "", false
	}
	var env struct {
		EventType audit.EventType `json:"event_type"`
		Payload   struct {
			NewHash string `json:"new_hash"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(line, &env); err != nil || env.Payload.NewHash == "" {
		return "", false
	}
	if env.EventType != audit.EventConfigChanged && env.EventType != audit.EventConfigDriftObserved {
		return "", false
	}
	return env.Payload.NewHash, true
}
