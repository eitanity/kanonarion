package application_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// buildZip creates a valid zip with the given entries (name → content).
func buildZip(entries map[string]string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			panic("buildZip create: " + err.Error())
		}
		if _, err := io.WriteString(f, content); err != nil {
			panic("buildZip write: " + err.Error())
		}
	}
	if err := w.Close(); err != nil {
		panic("buildZip close: " + err.Error())
	}
	return buf.Bytes()
}

// proxyWithZip returns a fakeProxy whose Download returns the given zip bytes
// and standalone go.mod content, with matching hashes pre-set.
func proxyWithZip(coord domain2.ModuleCoordinate, zipBytes []byte, standaloneGoMod string) *fakeProxy {
	return &fakeProxy{
		downloads: map[string]fakeDownload{
			coord.String(): {
				zipData:   string(zipBytes),
				goModData: standaloneGoMod,
				zipHash:   domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="},
				goModHash: domain2.ModuleHash{Algorithm: "h1", Value: "fakegomodhash=="},
			},
		},
	}
}

// TestVerify_ZipVersionPrefix_Failure exercises checkZipVersionPrefix when a
// zip entry carries the wrong module@version prefix.
func TestVerify_ZipVersionPrefix_Failure(t *testing.T) {
	coord := domain2.ModuleCoordinate{Path: "example.com/foo/bar", Version: "v1.0.0"}
	// Entry uses wrong module path prefix.
	zipBytes := buildZip(map[string]string{
		"example.com/wrong/path@v1.0.0/go.mod": "module example.com/wrong/path",
	})
	proxy := proxyWithZip(coord, zipBytes, "module example.com/foo/bar")

	uc := newUseCase(proxy, &fakeVCS{}, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus == string(domain2.Verified) {
		t.Error("expected unverified status due to wrong zip prefix")
	}
	if !strings.Contains(result.Record.VerificationDetail, "does not start with expected prefix") {
		t.Errorf("unexpected detail: %q", result.Record.VerificationDetail)
	}
}

// TestVerify_GoModConsistency_Failure exercises checkGoModConsistency when the
// standalone go.mod differs from the one embedded in the zip.
func TestVerify_GoModConsistency_Failure(t *testing.T) {
	coord := domain2.ModuleCoordinate{Path: "example.com/foo/bar", Version: "v1.0.0"}
	goModContent := "module example.com/foo/bar\n\ngo 1.21\n"
	differentGoMod := "module example.com/foo/bar\n\ngo 1.20\n"
	zipBytes := buildZip(map[string]string{
		"example.com/foo/bar@v1.0.0/go.mod": goModContent,
		"example.com/foo/bar@v1.0.0/doc.go": "package bar",
	})
	// Standalone go.mod differs from the embedded one.
	proxy := proxyWithZip(coord, zipBytes, differentGoMod)

	uc := newUseCase(proxy, &fakeVCS{}, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.UnverifiedGoModInconsistent) {
		t.Errorf("status = %q, want UnverifiedGoModInconsistent", result.Record.VerificationStatus)
	}
}

// TestVerify_GoModConsistency_Match exercises the happy-path branch of
// checkGoModConsistency when standalone and embedded go.mod match.
func TestVerify_GoModConsistency_Match(t *testing.T) {
	coord := domain2.ModuleCoordinate{Path: "example.com/foo/bar", Version: "v1.0.0"}
	goModContent := "module example.com/foo/bar\n\ngo 1.21\n"
	zipBytes := buildZip(map[string]string{
		"example.com/foo/bar@v1.0.0/go.mod": goModContent,
	})
	proxy := proxyWithZip(coord, zipBytes, goModContent)
	sumdb := availableSumDB(domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="})

	uc := newUseCaseWithSumDB(proxy, &fakeVCS{}, newFakeBlob(), newFakeFacts(), sumdb)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus == string(domain2.UnverifiedGoModInconsistent) {
		t.Error("go.mod should be consistent; unexpected inconsistency status")
	}
}

// TestVerify_Retracted_SingleVersion exercises parseRetracted for a single
// retracted version where v == low (no range comparison needed).
func TestVerify_Retracted_SingleVersion(t *testing.T) {
	coord := domain2.ModuleCoordinate{Path: "example.com/foo/bar", Version: "v1.0.0"}
	// The module's own go.mod declares v1.0.0 as retracted.
	goModWithRetract := "module example.com/foo/bar\n\ngo 1.21\n\nretract v1.0.0 // security issue\n"
	zipBytes := buildZip(map[string]string{
		"example.com/foo/bar@v1.0.0/go.mod": goModWithRetract,
	})
	proxy := proxyWithZip(coord, zipBytes, goModWithRetract)

	uc := newUseCase(proxy, &fakeVCS{}, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.Record.Retracted {
		t.Error("module should be marked retracted")
	}
}

// TestVerify_Retracted_VersionRange exercises parseRetracted and versionInRange
// for a range retract directive, including the compareVersion fallback path.
func TestVerify_Retracted_VersionRange(t *testing.T) {
	coord := domain2.ModuleCoordinate{Path: "example.com/foo/bar", Version: "v1.1.0"}
	// v1.1.0 falls within the retracted range [v1.0.0, v1.2.0].
	goModWithRange := "module example.com/foo/bar\n\ngo 1.21\n\nretract [v1.0.0, v1.2.0] // broken range\n"
	zipBytes := buildZip(map[string]string{
		"example.com/foo/bar@v1.1.0/go.mod": goModWithRange,
	})
	proxy := proxyWithZip(coord, zipBytes, goModWithRange)

	uc := newUseCase(proxy, &fakeVCS{}, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.Record.Retracted {
		t.Error("v1.1.0 should be marked retracted (within range v1.0.0–v1.2.0)")
	}
}

// TestVerify_Retracted_OutsideRange confirms that a version outside a retract
// range is NOT flagged as retracted, and exercises the false branch of versionInRange.
func TestVerify_Retracted_OutsideRange(t *testing.T) {
	coord := domain2.ModuleCoordinate{Path: "example.com/foo/bar", Version: "v1.3.0"}
	// v1.3.0 is outside the retracted range [v1.0.0, v1.2.0].
	goModWithRange := "module example.com/foo/bar\n\ngo 1.21\n\nretract [v1.0.0, v1.2.0]\n"
	zipBytes := buildZip(map[string]string{
		"example.com/foo/bar@v1.3.0/go.mod": goModWithRange,
	})
	proxy := proxyWithZip(coord, zipBytes, goModWithRange)

	uc := newUseCase(proxy, &fakeVCS{}, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.Retracted {
		t.Error("v1.3.0 should NOT be marked retracted (outside range v1.0.0–v1.2.0)")
	}
}

// TestVerify_ZipVersionPrefix_NoGoMod_NoFail confirms that a zip without any
// go.mod entry is not flagged for prefix failures (some pre-module modules lack go.mod).
func TestVerify_ZipVersionPrefix_NoGoMod(t *testing.T) {
	coord := domain2.ModuleCoordinate{Path: "example.com/foo/bar", Version: "v1.0.0"}
	// A correct-prefix zip but with no go.mod.
	zipBytes := buildZip(map[string]string{
		"example.com/foo/bar@v1.0.0/README.md": "readme",
	})
	proxy := proxyWithZip(coord, zipBytes, "module example.com/foo/bar")

	uc := newUseCase(proxy, &fakeVCS{}, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains(result.Record.VerificationDetail, "does not start with expected prefix") {
		t.Errorf("no prefix violation expected: detail = %q", result.Record.VerificationDetail)
	}
}

// TestVerify_SumDB_GoModHashMatch exercises the sumdb go.mod hash verification
// path and the GoModHash field.
func TestVerify_SumDB_GoModHashMatch(t *testing.T) {
	coord := domain2.ModuleCoordinate{Path: "example.com/foo/bar", Version: "v1.0.0"}
	goModContent := "module example.com/foo/bar\n\ngo 1.21\n"
	zipBytes := buildZip(map[string]string{
		"example.com/foo/bar@v1.0.0/go.mod": goModContent,
	})
	proxy := &fakeProxy{
		downloads: map[string]fakeDownload{
			coord.String(): {
				zipData:   string(zipBytes),
				goModData: goModContent,
				zipHash:   domain2.ModuleHash{Algorithm: "h1", Value: "correcthash=="},
				goModHash: domain2.ModuleHash{Algorithm: "h1", Value: "gomodhash=="},
			},
		},
	}
	sumdb := &fakeSumDB{result: ports.SumDBResult{
		Available: true,
		ZipHash:   domain2.ModuleHash{Algorithm: "h1", Value: "correcthash=="},
		GoModHash: domain2.ModuleHash{Algorithm: "h1", Value: "gomodhash=="},
	}}

	uc := newUseCaseWithSumDB(proxy, &fakeVCS{}, newFakeBlob(), newFakeFacts(), sumdb)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.GoModHash == "" {
		t.Error("GoModHash should be recorded")
	}
}
