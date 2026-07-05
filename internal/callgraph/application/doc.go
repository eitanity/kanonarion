// Package application contains the callgraph use cases.
//
// - ExtractCallGraphUseCase orchestrates reading a module zip from the blob
// store, delegating to a CallGraphAnalyser, sorting the result for
// determinism, hashing, and persisting the CallGraphRecord.
// - QueryCallGraphUseCase answers caller/callee questions. TraverseCallers
// and TraverseCallees perform a breadth-first walk hop by hop: each hop
// issues a fresh FindCallers/FindCallees store query for the frontier
// symbols rather than loading an entire CallGraphRecord into memory.
// This keeps traversal bounded by the reachable sub-graph (and by
// maxDepth) and lets it span records, so it belongs in the application
// layer, not in pure domain.
//
// The layer depends only on callgraph/ports and reused fetch/ports
// (BlobStore); it performs no static analysis or persistence itself.
package application
