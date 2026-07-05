package cli

import (
	"fmt"
	"os"
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
