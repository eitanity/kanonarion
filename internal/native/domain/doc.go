// Package domain holds the pure rules for the embedded-native-component
// context: which files inside a module artefact the Go build compiles as
// native code, which third-party library those files are, and the canonical
// ordering and content hash of the resulting record.
//
// A cgo module can carry a complete third-party C library in its published zip
// and compile it into the shipped binary. Nothing downstream models it: the
// module's licence record describes the Go wrapper, and a vulnerability scan
// over the binary reports on the Go coordinate. This context records the
// component so the silence is replaced by a fact a reader can act on.
//
// Three rules define the whole context, and each is a decision rather than a
// heuristic:
//
//   - Only code the build compiles is in scope. Shipping a .c file is not
//     enough — a module can carry C it never builds — so a native source counts
//     only when it sits in a package directory that uses cgo.
//   - Identification is a per-library recipe against a named declaration.
//     There is no C parser here and no inference from a file name or path.
//   - Presence with no matching recipe is a value, not an omission. Such an
//     artefact is recorded as present-but-unidentified, carrying the file
//     evidence, because a coverage gap a reader can see is worth more than
//     silence.
//
// The package performs no I/O. Reading the artefact and parsing Go imports are
// port-backed adapter concerns.
package domain
