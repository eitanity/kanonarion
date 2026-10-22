package domain

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// A checkout that cannot be listed, or a file that vanished after the walk,
// is reported as such rather than hashed as a smaller tree.
func TestCheckoutFiles_FailuresAreReported(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	_, err := NewVerifier(nil).HashDirAsModuleZip(missing, coordinatetest.MustNew("example.com/m", "v1.0.0"))
	if err == nil || !strings.Contains(err.Error(), "listing checkout files") {
		t.Errorf("hashing a missing checkout = %v, want a listing failure", err)
	}

	f := checkoutFile{path: missing, slashPath: "gone"}
	if _, err := f.Lstat(); err == nil || !strings.Contains(err.Error(), "stat gone") {
		t.Errorf("Lstat of a vanished file = %v, want it named", err)
	}
	if _, err := f.Open(); err == nil || !strings.Contains(err.Error(), "opening gone") {
		t.Errorf("Open of a vanished file = %v, want it named", err)
	}
}
