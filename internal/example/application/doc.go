// Package application contains the example-function harvesting use case:
// reading a module's zip from the blob store, scanning _test.go files for
// Example* functions, extracting their bodies and output comments via the Go
// AST, and persisting an ExampleRecord.
//
// The use case depends on domain types and port interfaces only. It has no
// knowledge of SQLite or filesystem mechanics.
//
// No fetched code is executed. All extraction operates on source as inert text.
// Extraction is downstream of fetch: a module must have a FactRecord before
// its examples can be harvested.
package application
