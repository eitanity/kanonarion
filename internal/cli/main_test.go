package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestMain isolates the entire package-cli test binary from the
// developer's real ~/.kanonarion. Many in-process Run tests
// omit --store-root; without this they resolve to defaultStoreRoot
// (~/.kanonarion) and pollute the production store with fixture walks
// (e.g. stray github.com/foo/bar records). Pointing KANONARION_STORE at a
// throwaway temp dir routes every such call into disposable storage,
// regardless of whether an individual test remembers to pass
// --store-root. Tests that do pass --store-root still win (flag > env).
//
// This lives in package cli (not the testscript cmd_test package): the
// testscript suite runs the CLI as subprocesses with its own sandboxed
// HOME and must keep using defaultStoreRoot, so it is left untouched.
func TestMain(m *testing.M) {
	// Answered before anything else: this process may be a child the extract or
	// callgraph stage spawned from os.Executable() while a test above it drove
	// Run in process, in which case os.Executable() is this test binary and the
	// testing package would run the whole suite again. See TestBinaryIsCLIEnv.
	if os.Getenv(TestBinaryIsCLIEnv) == "1" && len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-test.") {
		if err := Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
			// Mirror cmd/kanonarion/main.go: the CLI silences cobra's own error
			// printing, so the entry point must surface the error itself.
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// Set for this suite's children, never for the suite: this process was started
	// by `go test`, and the variable is what tells its descendants apart from that.
	if err := os.Setenv(TestBinaryIsCLIEnv, "1"); err != nil {
		fmt.Fprintf(os.Stderr, "marking test-binary children as the CLI: %v\n", err)
		os.Exit(1)
	}

	dir, err := os.MkdirTemp("", "kanonarion-cli-test-store-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating isolated test store: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("KANONARION_STORE", dir); err != nil {
		fmt.Fprintf(os.Stderr, "setting KANONARION_STORE: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
