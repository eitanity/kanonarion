package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/vendortree/domain"
)

// listed is the shape vendor/modules.txt takes on a real tree: module paths of
// three different segment counts, plus a major-version module nested inside the
// directory of the module it succeeds.
var listed = []string{
	"github.com/IBM/ibm-cos-sdk-go",
	"golang.org/x/crypto",
	"github.com/minio/minio-go",
	"github.com/minio/minio-go/v7",
	"cloud.google.com/go/storage",
}

// TestVendoredModuleIndex_Module_SegmentCounts: a module path is not a segment
// count. Each case below has a different one, and any fixed split of the
// vendored path is wrong for all but one of them.
func TestVendoredModuleIndex_Module_SegmentCounts(t *testing.T) {
	idx := domain.NewVendoredModuleIndex(listed)
	cases := map[string]string{
		"vendor/github.com/IBM/ibm-cos-sdk-go/aws/signer/v4/v4.go": "github.com/IBM/ibm-cos-sdk-go",
		"vendor/golang.org/x/crypto/md4/md4.go":                    "golang.org/x/crypto",
		"vendor/cloud.google.com/go/storage/hmac.go":               "cloud.google.com/go/storage",
	}
	for rel, want := range cases {
		if got := idx.Module(rel, "example.com/project"); got != want {
			t.Errorf("Module(%q) = %q, want %q", rel, got, want)
		}
	}
}

// TestVendoredModuleIndex_Module_LongestPrefixWins: both minio-go and its /v7
// successor are listed and the v7 directory lives inside minio-go's, so a first
// match would attribute every v7 file to the module it replaced.
func TestVendoredModuleIndex_Module_LongestPrefixWins(t *testing.T) {
	idx := domain.NewVendoredModuleIndex(listed)
	const rel = "vendor/github.com/minio/minio-go/v7/pkg/encrypt/server-side.go"
	if got := idx.Module(rel, "example.com/project"); got != "github.com/minio/minio-go/v7" {
		t.Errorf("Module(%q) = %q, want github.com/minio/minio-go/v7", rel, got)
	}
	const parent = "vendor/github.com/minio/minio-go/api.go"
	if got := idx.Module(parent, "example.com/project"); got != "github.com/minio/minio-go" {
		t.Errorf("Module(%q) = %q, want github.com/minio/minio-go", parent, got)
	}
}

// TestVendoredModuleIndex_Module_UnlistedPathIsUnresolved: a vendored path no
// listed module owns is reported as such. The prefixes of it that LOOK like
// modules — github.com/aliyun, golang.org/x — are exactly the values this
// refuses to invent, because there is nothing there to upgrade, pin or exempt.
func TestVendoredModuleIndex_Module_UnlistedPathIsUnresolved(t *testing.T) {
	idx := domain.NewVendoredModuleIndex(listed)
	for _, rel := range []string{
		"vendor/github.com/aliyun/aliyun-oss-go-sdk/oss/conn.go",
		"vendor/golang.org/x/net/http2/hpack/huffman.go",
		"vendor/github.com/IBM/other-sdk/x.go",
		"vendor/loose.go",
	} {
		if got := idx.Module(rel, "example.com/project"); got != domain.ModuleUnresolved {
			t.Errorf("Module(%q) = %q, want %q", rel, got, domain.ModuleUnresolved)
		}
	}
}

// TestVendoredModuleIndex_Module_ProjectOwnsNonVendoredFiles: the path that was
// already correct, held still. A file outside vendor/ is the project's own
// whatever modules.txt lists.
func TestVendoredModuleIndex_Module_ProjectOwnsNonVendoredFiles(t *testing.T) {
	idx := domain.NewVendoredModuleIndex(listed)
	for _, rel := range []string{"main.go", "pkg/loki/loki.go", "internal/vendoring/x.go"} {
		if got := idx.Module(rel, "github.com/grafana/loki/v3"); got != "github.com/grafana/loki/v3" {
			t.Errorf("Module(%q) = %q, want the project module", rel, got)
		}
	}
}

// TestVendoredModuleIndex_Module_NoListingResolvesNothing: an index over no
// modules attributes no vendored file. A project with no vendored tree has no
// such file at all, so the project module still answers for its own code.
func TestVendoredModuleIndex_Module_NoListingResolvesNothing(t *testing.T) {
	idx := domain.NewVendoredModuleIndex(nil)
	if got := idx.Module("vendor/github.com/x/y/z.go", "example.com/project"); got != domain.ModuleUnresolved {
		t.Errorf("Module under vendor/ with nothing listed = %q, want %q", got, domain.ModuleUnresolved)
	}
	if got := idx.Module("cmd/main.go", "example.com/project"); got != "example.com/project" {
		t.Errorf("Module outside vendor/ = %q, want the project module", got)
	}
}

// TestVendoredModuleIndex_Vendored_ReportsBothHalves: the under-vendor flag and
// the module come from one reading of the path. A caller that records "this
// does not affect the current build" needs the flag to agree with the module it
// stored beside it.
func TestVendoredModuleIndex_Vendored_ReportsBothHalves(t *testing.T) {
	idx := domain.NewVendoredModuleIndex(listed)
	cases := []struct {
		rel          string
		wantVendored bool
		wantModule   string
	}{
		{"vendor/golang.org/x/crypto/md4/md4.go", true, "golang.org/x/crypto"},
		{"vendor/github.com/nobody/thing/x.go", true, domain.ModuleUnresolved},
		{"cmd/loki/main.go", false, ""},
	}
	for _, c := range cases {
		gotVendored, gotModule := idx.Vendored(c.rel)
		if gotVendored != c.wantVendored || gotModule != c.wantModule {
			t.Errorf("Vendored(%q) = (%v, %q), want (%v, %q)",
				c.rel, gotVendored, gotModule, c.wantVendored, c.wantModule)
		}
	}
}
