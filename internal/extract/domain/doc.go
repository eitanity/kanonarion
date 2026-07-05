// Package domain defines the types and invariants for a coordinated
// extraction operation.
//
// The aggregate root is ExtractionRun: the per-module, per-stage outcome of
// running the extraction stages over every module in a walk, together with
// the pipeline versions used and a content hash over the canonical record.
//
// Invariants:
//
// - Serialisation is canonical and deterministic — ExtractionRun marshals
// through ExtractionRunHasher (not the default encoder) so the
// map[ModuleCoordinate] keys are ordered and two runs over the same
// inputs produce byte-identical JSON and the same content hash.
// - OverallStatus is a roll-up of the per-stage StageResults, not set
// independently by callers.
//
// The package is pure: no I/O, no clock, no stage execution. It reuses
// fetch/domain.ModuleCoordinate as the module identity.
package domain
