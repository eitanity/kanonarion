package cli

// TestBinaryIsCLIEnv marks a process tree in which os.Executable() resolves to a
// Go TEST binary rather than to the kanonarion binary.
//
// The callgraph and extract stages run as a fresh child of os.Executable(), so
// that a child holding a multi-gigabyte SSA closure dies with its work. Inside a
// test that drives Run in process, os.Executable() is the test binary, and a test
// binary handed `callgraph <module>@<version>` does not run the CLI: Go's testing
// package stops flag parsing at the first non-flag argument, finds no -run
// filter, and runs the WHOLE suite — including the test whose Run call caused the
// spawn, which spawns again. It is a fork bomb, and it is not theoretical: one
// filled a 31G tmpfs with 1025 half-built stores and cost 254 OOM kills.
//
// A TestMain that may spawn itself therefore sets this variable for its children
// and, when it sees the variable already set, answers as the CLI instead of as a
// second copy of the suite. The variable is named here, beside the command
// registry, so the two TestMains that honour it cannot drift onto different
// spellings of it.
const TestBinaryIsCLIEnv = "KANONARION_TEST_BINARY_IS_THE_CLI"
