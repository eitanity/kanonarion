// Package reachability implements ports.ReachabilityAnalyser using static
// call-graph analysis.
//
// Given a CallGraphProjection and the symbols a finding touches, it performs a
// BFS from the call graph's entry points to decide whether vulnerable symbols
// are reachable. It operates only on the projection supplied through the port;
// it neither builds call graphs nor imports the callgraph context.
package reachability
