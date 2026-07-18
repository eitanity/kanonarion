// Package domain implements capability (permission) analysis over a Go
// module's static call graph.
//
// For a module it reports which sensitive capabilities its reachable code can
// exercise — NETWORK, FILES, EXEC, REFLECT, UNSAFE_POINTER and so on — as a
// first-class inclusion/vetting signal ("what can this dependency actually
// do?") and an update-validity signal ("did this update expand the capability
// set?").
//
// The taxonomy is adopted from capslock (github.com/google/capslock) so reports
// are comparable, but the analysis runs on kanonarion's own call graph rather
// than shelling out, so capability findings share our reachability model and
// its per-edge confidence tags. Two soundness properties follow directly from
// that choice and are load-bearing:
//
//   - Every finding carries the weakest edge confidence along its witnessing
//     path. A capability reached only through interface over-approximation
//     (DynamicDispatch) is reported with that weaker tag, so a reviewer can
//     separate "EXEC via a resolved direct call" from "EXEC via interface
//     fanout" instead of conflating them into a single inflated set.
//   - A report computed over a Partial call graph is flagged Partial and
//     carries a Caveat (parity with capslock's UNANALYZED bucket); a capability
//     set is never presented as clean when the underlying graph did not fully
//     resolve.
//
// The package is pure: no I/O, no toolchain invocation, no clock. It reuses
// callgraph/domain value objects (CallGraphRecord, CallNode, EdgeConfidence).
package domain
