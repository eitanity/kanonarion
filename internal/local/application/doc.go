// Package application orchestrates local workspace analysis. It loads
// dependency callgraph records from the global store into an ephemeral
// AnalysisSession and performs cross-module edge resolution entirely in
// memory — no local facts are ever written to the persistent store.
package application
