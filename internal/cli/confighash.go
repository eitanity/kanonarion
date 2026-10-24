package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/composition/storage"
	"github.com/eitanity/kanonarion/internal/config/domain"
	configports "github.com/eitanity/kanonarion/internal/config/ports"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// configOverride is a flag that changed a gate for this invocation only.
type configOverride struct {
	Flag  string `json:"flag"`
	Value string `json:"value"`
}

// observeGateConfig returns the hash of the configuration in force and, when
// the backend last recorded a different one (or none, or keeps none), appends
// config_drift_observed through its audit sink. Only commands that evaluate a
// gate call it, so a read stays a read.
func observeGateConfig(ctr *Container) (string, error) {
	if ctr == nil || ctr.Audit == nil {
		return "", errors.New("no audit sink to record the config hash in")
	}
	hash, err := activeConfig.Hash()
	if err != nil {
		return "", err //nolint:wrapcheck // the domain error names the hashing
	}
	last, observedAt := "", "first_use"
	note := "observed by the first command to evaluate a gate; the edit itself was not witnessed"
	if ctr.ConfigHashes == nil {
		observedAt = "every_gate"
		note = "the storage backend keeps no last recorded config hash, so every gate-evaluating command records the hash in use"
	} else {
		var found bool
		if last, found, err = ctr.ConfigHashes.LastConfigHash(); err != nil {
			return "", fmt.Errorf("reading the last recorded config hash: %w", err)
		}
		if found && last == hash {
			return hash, nil
		}
	}
	ev := audit.Event{Type: audit.EventConfigDriftObserved, Payload: map[string]any{
		"old_hash":    last,
		"new_hash":    hash,
		"observed_at": observedAt,
		"note":        note,
		"command":     invokedCommand,
	}}
	if err := recordConfigHash(ctr.Audit, ctr.ConfigHashes, ev, hash); err != nil {
		return "", fmt.Errorf("recording config drift: %w", err)
	}
	return hash, nil
}

// recordConfigHash appends e, an event that sets the recorded hash, telling
// the backend's last-hash memory before and after so a crash between them
// leaves it unsure rather than wrong.
func recordConfigHash(sink fetchports.AuditSink, hashes configports.ConfigHashLedger, e audit.Event, hash string) error {
	if hashes != nil {
		if err := hashes.BeforeConfigHashAppend(); err != nil {
			return fmt.Errorf("before appending %s: %w", e.Type, err)
		}
	}
	if err := sink.RecordEvent(e); err != nil {
		return fmt.Errorf("appending %s: %w", e.Type, err)
	}
	if hashes == nil {
		return nil
	}
	if err := hashes.AfterConfigHashAppend(hash); err != nil {
		return &lastHashNotKeptError{event: e.Type, cause: err}
	}
	return nil
}

// lastHashNotKeptError is a failure after the event was appended: the log
// holds it, and only the backend's last-hash memory is left unsure.
type lastHashNotKeptError struct {
	event audit.EventType
	cause error
}

func (e *lastHashNotKeptError) Error() string {
	return fmt.Sprintf("after appending %s: %v", e.event, e.cause)
}

func (e *lastHashNotKeptError) Unwrap() error { return e.cause }

// recordConfigOverrides appends one config_override event per override. An
// override names the hash it overrode and does not replace it.
func recordConfigOverrides(ctr *Container, hash string, overrides []configOverride) error {
	for _, o := range overrides {
		if err := ctr.Audit.RecordEvent(audit.Event{Type: audit.EventConfigOverride, Payload: map[string]any{
			"flag":        o.Flag,
			"value":       o.Value,
			"config_hash": hash,
			"command":     invokedCommand,
		}}); err != nil {
			return fmt.Errorf("recording config override %s: %w", o.Flag, err)
		}
	}
	return nil
}

// noConfigHashRecorded is how a record from before the hash was kept reads.
const noConfigHashRecorded = "no config hash recorded"

// configHashLine is the text form: the hash a gate was evaluated under, and
// any flag that overrode it for this run.
func configHashLine(hash string, overrides []configOverride) string {
	if hash == "" {
		hash = noConfigHashRecorded
	}
	line := "config: " + hash
	if len(overrides) > 0 {
		flags := make([]string, 0, len(overrides))
		for _, o := range overrides {
			flags = append(flags, o.Flag+"="+o.Value)
		}
		line += " (overridden for this run: " + strings.Join(flags, ", ") + ")"
	}
	return line
}

// writeConfigHashLine writes configHashLine on its own line.
func writeConfigHashLine(w io.Writer, hash string, overrides []configOverride) error {
	if _, err := fmt.Fprintln(w, configHashLine(hash, overrides)); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// recordConfigChange appends config_changed when the file `config set` just
// wrote hashes differently from the one it replaced. A file the loader refuses
// is in force for no command, so it has no hash: a refused "before" reads as
// an empty old hash, and a refused "after" is left for the first gate to find.
//
// The event goes to the store the new file names, opened as a writing command
// opens it. A store that cannot record it leaves the change unrecorded: the
// file is written, so the command says so and the next gate records drift.
func recordConfigChange(root, key string, before domain.Config, beforeErr error, stderr io.Writer) error {
	after, err := loadStoreConfig(root)
	if err != nil {
		return nil //nolint:nilerr // the refusal is reported by the next command that loads it
	}
	newHash, err := after.Hash()
	if err != nil {
		return err //nolint:wrapcheck // the domain error names the hashing
	}
	oldHash := ""
	if beforeErr == nil {
		if oldHash, err = before.Hash(); err != nil {
			return err //nolint:wrapcheck // the domain error names the hashing
		}
	}
	if oldHash == newHash {
		return nil
	}
	ev := audit.Event{Type: audit.EventConfigChanged, Payload: map[string]any{
		"key":      key,
		"old_hash": oldHash,
		"new_hash": newHash,
		"command":  invokedCommand,
	}}
	err = appendConfigChange(root, after, ev, newHash, stderr)
	if err == nil {
		return nil
	}
	// After a failed after-call the backend is unsure, not wrong: it re-reads its
	// log or forgets, so the next gate may record the same hash again.
	notice := "config set: the change was written but not recorded in the assurance log: %v\n" +
		"  the next command that evaluates a gate will record it as config drift\n"
	var notKept *lastHashNotKeptError
	if errors.As(err, &notKept) {
		notice = "config set: the change was recorded, but the backend's last config hash could not be updated: %v\n" +
			"  the next command that evaluates a gate may record the same hash again as config drift\n"
		err = notKept.cause
	}
	if _, werr := fmt.Fprintf(stderr, notice, err); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	return nil
}

// appendConfigChange opens the store cfg names, as config set declares it may
// create it, and appends ev there.
func appendConfigChange(root string, cfg domain.Config, ev audit.Event, hash string, stderr io.Writer) error {
	st, err := openStorage(storage.Request{
		StoreRoot: root,
		Intent:    storage.IntentCreate,
		SetAside:  storeSetAside.report,
		Logger:    buildLogger(logLevel, stderr),
		Config:    cfg,
	})
	if err != nil {
		return err
	}
	defer releaseStore(storageCloser(st))
	if err := admitStorage(st, root); err != nil {
		return err
	}
	return recordConfigHash(st.Audit, st.ConfigHashes, ev, hash)
}
