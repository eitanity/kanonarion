// Package yaml implements license/ports.LicenseOverrideStore over the
// license_overrides section of config.yaml.
//
// The config file is parsed once by the config bounded context; to
// avoid a second parse of the same file this adapter is constructed from the
// already-decoded "path[@version] → SPDX" map rather than re-reading disk.
// Alternate backends (e.g. a database-backed store) can implement the same
// port instead of this one.
package yaml

import (
	"context"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

// Store serves a fixed LicenseOverrideSet built from config.yaml's
// license_overrides section.
type Store struct {
	set domain.LicenseOverrideSet
}

// New builds a Store from the decoded license_overrides map. A nil or empty
// map yields a store that never overrides.
func New(entries map[string]string) *Store {
	return &Store{set: domain.NewLicenseOverrideSet(entries)}
}

// LoadOverrides returns the configured override set. It never errors: an
// absent section is an empty set, mirroring the config context's first-run
// behaviour.
func (s *Store) LoadOverrides(_ context.Context) (domain.LicenseOverrideSet, error) {
	return s.set, nil
}
