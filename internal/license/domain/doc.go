// Package domain defines the license bounded context's core model: the
// per-module license extraction record produced by scanning module zips for
// license files, classifying each against known SPDX identifiers, and
// deriving a primary license determination.
//
// Invariants:
// - LicenseRecord.LicenseFiles is always sorted lexicographically by Path.
// - LicenseFileEntry.AltMatches is sorted by Confidence descending.
// - LicenseRecord.ContentHash is computed over canonical JSON with the field
// zeroed; call LicenseRecordHasher.SetContentHash after construction.
// - A record with OverallStatus ExtractionFailed always has a non-empty
// FailureDetail.
// - OverallStatus None means no license files were found; it is a valid
// state, not an error.
//
// This package imports fetch/domain for the shared ModuleCoordinate value
// object. No other cross-context imports are permitted here.
package domain
