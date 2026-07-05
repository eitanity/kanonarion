package cmd_test

import (
	"os/exec"
	"testing"
)

// TestGoVet ensures all packages pass go vet.
func TestGoVet(t *testing.T) {
	cmd := exec.Command("go", "vet", "./...")
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go vet:\n%s", out)
	}
}

// TestStaticcheck runs staticcheck on all packages if it is installed.
func TestStaticcheck(t *testing.T) {
	if _, err := exec.LookPath("staticcheck"); err != nil {
		t.Skip("staticcheck not in PATH")
	}
	cmd := exec.Command("staticcheck", "./...")
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("staticcheck:\n%s", out)
	}
}
