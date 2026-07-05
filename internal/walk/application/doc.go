// Package application implements the GraphResolver: a service that takes a target
// module coordinate and produces a complete, deterministic dependency Graph
// representing the transitive closure under Go's minimum version selection (MVS).
//
// Architecture:
// - GraphResolver depends on domain (pure model) and ports (I/O abstractions).
// - It does not import the fetch application layer directly; it accesses fetch
// capabilities through the ModuleFetcher port.
// - BlobStore and Clock are imported directly from fetch/ports because they are
// shared infrastructure, not fetch-specific concerns.
//
// Error handling:
// - A failure to fetch or parse the TARGET module is fatal: Resolve returns an error.
// - A failure to fetch or parse a TRANSITIVE dependency produces a partial graph.
// The failed node is recorded with ResolutionFetchFailed or ResolutionParseFailed
// and the graph's Partial flag is set. Resolution continues for sibling nodes.
// - Context cancellation produces a partial graph with PartialReason = "cancelled".
// - Every error that propagates out of Resolve is wrapped with call-site context.
package application
