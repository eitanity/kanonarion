// Package ports defines the interfaces the config bounded context exposes.
package ports

import (
	"context"

	"code.eitanity.com/kanonarion/internal/config/domain"
)

// ConfigStore loads a Config from a versioned source.
// The default implementation is adapters/store/yaml.
// Future adapters may load from etcd, Vault, or other remote sources.
type ConfigStore interface {
	LoadConfig(ctx context.Context) (domain.Config, error)
}

// ConfigHashLedger answers which configuration hash a backend's audit sink
// last recorded, so a gate-evaluating command can tell drift from a hash it
// has already recorded without reading the whole log.
//
// It is told before and after each append that sets the hash, so a crash
// between the two leaves it unsure (found false, or a re-read of the log)
// rather than answering a hash the log never recorded.
type ConfigHashLedger interface {
	// LastConfigHash returns the new_hash of the last config_changed or
	// config_drift_observed event; found is false when none was recorded.
	LastConfigHash() (hash string, found bool, err error)
	// BeforeConfigHashAppend is called before an append that sets the hash.
	BeforeConfigHashAppend() error
	// AfterConfigHashAppend is called once that append succeeded.
	AfterConfigHashAppend(hash string) error
}
