// Package ports defines the interfaces the callgraph application layer
// requires from the outside world.
//
// The driven ports are:
//
// - CallGraphAnalyser — performs static call-graph analysis of a module's
// source (the staticcha/CHA adapter), returning a CallGraphRecord.
// - CallGraphStore — persists CallGraphRecords and answers caller/callee
// edge queries (FindCallers/FindCallees return CallEdgeRefs), which is
// what makes hop-by-hop traversal in the application possible without
// loading a whole record.
//
// The callgraph context reuses coordinate.ModuleCoordinate as the module
// identity and BlobStore from fetch/ports (injected in the application
// Config); neither is re-declared here.
package ports
