package vendortree_test

import (
	"context"
	"path/filepath"
	"testing"

	fipsvendortree "github.com/eitanity/kanonarion/internal/fips/adapters/vendortree"
	venlocalfs "github.com/eitanity/kanonarion/internal/vendortree/adapters/scanner/localfs"
)

const corpus = "../../../../test/fixtures/supplychain/fips"

func reader() *fipsvendortree.Reader {
	return fipsvendortree.New(venlocalfs.New(nil))
}

// TestVendoredModulePaths_ReadsTheListing: the paths come back as
// vendor/modules.txt names them, through the vendor context's one parser of
// that file.
func TestVendoredModulePaths_ReadsTheListing(t *testing.T) {
	got, err := reader().VendoredModulePaths(context.Background(),
		filepath.Join(corpus, "unlisted-in-vendor", "go.mod"))
	if err != nil {
		t.Fatalf("VendoredModulePaths: %v", err)
	}
	if len(got) != 1 || got[0] != "example.com/listed" {
		t.Errorf("paths = %v, want [example.com/listed]", got)
	}
}

// TestVendoredModulePaths_NotVendoredIsAnAnswer: a project with no
// vendor/modules.txt yields no paths and no error. It has no vendored file to
// attribute, so absence is the answer rather than a scan failure.
func TestVendoredModulePaths_NotVendoredIsAnAnswer(t *testing.T) {
	got, err := reader().VendoredModulePaths(context.Background(),
		filepath.Join(corpus, "clean-bc", "go.mod"))
	if err != nil {
		t.Fatalf("VendoredModulePaths: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("paths = %v, want none", got)
	}
}
