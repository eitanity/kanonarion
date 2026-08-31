// Package application orchestrates the embedded-native-component measurement:
// read the module's verified zip through the blob port, decide which files the
// Go build compiles as native code, hand them to the domain for identification,
// and persist the record.
//
// It contains no archive format knowledge beyond the shared ziparchive adapter,
// no Go parsing (that is the GoImportReader port), and no C parsing at all.
package application
