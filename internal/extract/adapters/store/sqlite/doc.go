// Package sqlite implements ports.ExtractionStore on SQLite.
//
// It persists the ExtractionRun aggregate and verifies the stored content
// hash on read, so a corrupted or tampered run is rejected rather than
// silently returned. Migrations are versioned per module (Module + Version
// primary key).
package sqlite
