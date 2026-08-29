package vendortree_test

import (
	"context"
	"path/filepath"
	"testing"

	gdvendortree "github.com/eitanity/kanonarion/internal/godebug/adapters/vendortree"
	venlocalfs "github.com/eitanity/kanonarion/internal/vendortree/adapters/scanner/localfs"
)

const corpus = "../../../../test/fixtures/supplychain/godebug"

func reader() *gdvendortree.Reader {
	return gdvendortree.New(venlocalfs.New(nil))
}

// TestVendoredModulePaths_ReadsTheListing: the paths come back as
// vendor/modules.txt names them, through the vendor context's one parser of
// that file — including the two entries that nest, which is what makes
// longest-prefix matching downstream meaningful.
func TestVendoredModulePaths_ReadsTheListing(t *testing.T) {
	got, err := reader().VendoredModulePaths(context.Background(),
		filepath.Join(corpus, "vendored-modules", "go.mod"))
	if err != nil {
		t.Fatalf("VendoredModulePaths: %v", err)
	}
	want := []string{
		"github.com/IBM/ibm-cos-sdk-go",
		"github.com/minio/minio-go",
		"github.com/minio/minio-go/v7",
		"golang.org/x/crypto",
		"k8s.io/client-go",
	}
	if len(got) != len(want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("paths[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestVendoredModulePaths_NotVendoredIsAnAnswer: a project with no
// vendor/modules.txt yields no paths and no error. It has no vendored file to
// attribute, so absence is the answer rather than a scan failure.
func TestVendoredModulePaths_NotVendoredIsAnAnswer(t *testing.T) {
	got, err := reader().VendoredModulePaths(context.Background(),
		filepath.Join(corpus, "clean", "go.mod"))
	if err != nil {
		t.Fatalf("VendoredModulePaths: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("paths = %v, want none", got)
	}
}
