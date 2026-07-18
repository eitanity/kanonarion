// Package application wires the capability domain analysis to a source of
// stored call graph records. It reads a module's persisted call graph, selects
// library-style roots, and produces a capability report; the diff use case does
// the same for two versions and compares the results with diff-parity honoured.
//
// It holds no analysis logic of its own — classification, witnessing paths and
// caveating all live in capability/domain — so the use cases stay thin and the
// soundness rules have a single home.
package application
