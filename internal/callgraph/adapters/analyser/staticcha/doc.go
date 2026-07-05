// Package staticcha implements ports.CallGraphAnalyser using Class Hierarchy
// Analysis (CHA) via golang.org/x/tools/go/callgraph/cha. It extracts the
// module zip to a temporary directory, loads all packages using go/packages
// with full type information, constructs an SSA program, runs CHA, and walks
// the resulting call graph to produce a CallGraphRecord.
//
// CHA is a conservative over-approximation: it considers every method that
// satisfies an interface as a potential callee of any interface dispatch site.
// This makes it faster than RTA but less precise.
//
// Package loading invokes the host Go toolchain (go list / export data) and
// requires that the module's transitive dependencies are available in the
// local module cache (GOMODCACHE). If loading fails, the record carries status
// LoadFailed and callers should ensure dependencies are available (e.g. via
// 'go mod download').
package staticcha
