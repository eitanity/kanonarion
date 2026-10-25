package gopackages

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// TestLoadEnvMatchesTheWorktreePosture holds the symbol load to the posture its
// sibling working-tree children are held to.
func TestLoadEnvMatchesTheWorktreePosture(t *testing.T) {
	dir := t.TempDir()
	p, ok := goenv.For("worktree")
	if !ok {
		t.Fatal(`no posture named "worktree" is stated`)
	}
	for _, v := range goenv.Verify(p, os.Environ(), loadEnv(dir)) {
		t.Error(v)
	}
}

// TestAnalyseSymbolsDoesNotRunAPackagesDriver plants a driver that records it
// ran, and asserts the load goes through the go command instead.
func TestAnalyseSymbolsDoesNotRunAPackagesDriver(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "driver-ran")
	driver := filepath.Join(t.TempDir(), "driver")
	script := "#!/bin/sh\ntouch \"" + marker + "\"\nexit 1\n"
	if err := os.WriteFile(driver, []byte(script), 0o700); err != nil { // #nosec G306 -- a driver this test expects go/packages to refuse must be executable
		t.Fatalf("writing driver: %v", err)
	}
	t.Setenv("GOPACKAGESDRIVER", driver)

	root := t.TempDir()
	files := map[string]string{
		"go.mod":  "module example.com/m\n\ngo 1.21\n",
		"main.go": "package main\n\nfunc main() {}\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	if _, err := New().AnalyseSymbols(context.Background(), root); err != nil {
		t.Fatalf("AnalyseSymbols: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("go/packages ran the GOPACKAGESDRIVER program instead of the go command")
	}
}
