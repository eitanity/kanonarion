// Package tinylower names the runtime functions TinyGo's compiler calls for
// constructs go/ssa represents as instructions or builtins rather than calls:
// map and channel operations, string operators, append, panics, bounds checks,
// heap allocation and the rest. The table is keyed by TinyGo version and is read
// off that version's compiler/ source; Sites maps a function's instructions onto
// it. Nothing here knows about call graphs.
package tinylower
