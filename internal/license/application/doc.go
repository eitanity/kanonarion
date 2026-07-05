// Package application contains the license extraction use case: reading a
// module's zip from the blob store, scanning it for license files, classifying
// each with the configured detector, and persisting a LicenceRecord.
//
// The use case depends on domain types and port interfaces only. It has no
// knowledge of SQLite, licensecheck internals, or filesystem mechanics.
//
// Extraction is downstream of fetch: a module must have a FactRecord before
// its license can be extracted. Attempting extraction for an unfetched module
// returns ErrModuleNotFetched.
package application
