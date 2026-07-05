// Package sqlite implements ports.VulnerabilityStore on SQLite.
//
// It persists the VulnerabilityRecord and WalkScanRun aggregates plus pinned
// database snapshots, and verifies the stored content hash on read so a
// corrupted or tampered record is rejected rather than silently returned.
// Migrations are versioned per module (Module + Version primary key).
package sqlite
