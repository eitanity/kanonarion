package application_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	godocextractor "github.com/eitanity/kanonarion/internal/iface/adapters/extractor/godoc"
	"github.com/eitanity/kanonarion/internal/iface/application"
	domain3 "github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"
)

func TestExecute_ModuleNotFetched(t *testing.T) {
	uc := buildUseCase(t, nil, nil, nil, nil)
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")

	_, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if !errors.Is(err, ports.ErrModuleNotFetched) {
		t.Fatalf("expected ErrModuleNotFetched, got %v", err)
	}
}

func TestExecute_CacheHit(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	factStore := &fakeFactStore{}
	ifaceStore := &fakeInterfaceStore{}

	putFact(t, factStore, coord, "blob:content")

	existing := domain3.InterfaceRecord{
		SchemaVersion:   domain3.InterfaceSchemaVersion,
		Coordinate:      coord,
		OverallStatus:   domain3.InterfaceStatusExtracted,
		ExtractedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: application.PipelineVersion,
	}
	var h domain3.InterfaceRecordHasher
	existing, err := h.SetContentHash(existing)
	if err != nil {
		t.Fatal(err)
	}
	if err := ifaceStore.PutInterfaceRecord(context.Background(), existing); err != nil {
		t.Fatal(err)
	}

	uc := buildUseCase(t, factStore, nil, ifaceStore, nil)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Error("expected FromCache = true")
	}
}

func TestExecute_ForceBypassesCache(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	ifaceStore := &fakeInterfaceStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"client.go": "package client\ntype Client struct{}\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatal(err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	existing := domain3.InterfaceRecord{
		SchemaVersion:   domain3.InterfaceSchemaVersion,
		Coordinate:      coord,
		OverallStatus:   domain3.InterfaceStatusExtracted,
		ExtractedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: application.PipelineVersion,
	}
	var h domain3.InterfaceRecordHasher
	existing, _ = h.SetContentHash(existing)
	_ = ifaceStore.PutInterfaceRecord(context.Background(), existing)

	ext := &fakeExtractor{record: domain3.InterfaceRecord{
		SchemaVersion:   domain3.InterfaceSchemaVersion,
		OverallStatus:   domain3.InterfaceStatusExtracted,
		ExtractedAt:     time.Now().UTC(),
		PipelineVersion: application.PipelineVersion,
	}}
	uc := buildUseCase(t, factStore, blobStore, ifaceStore, ext)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord, Force: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("Force should bypass cache")
	}
}

func TestExecute_CorruptZip(t *testing.T) {
	coord := mustCoord(t, "example.com/corrupt", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	ifaceStore := &fakeInterfaceStore{}

	handle, err := blobStore.Put(context.Background(), bytes.NewReader([]byte("not a zip")))
	if err != nil {
		t.Fatal(err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, ifaceStore, nil)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute should not error on corrupt zip; got %v", err)
	}
	if result.Record.OverallStatus != domain3.InterfaceStatusExtractionFailed {
		t.Errorf("OverallStatus = %s, want ExtractionFailed", result.Record.OverallStatus)
	}
	if result.Record.FailureDetail == "" {
		t.Error("FailureDetail should be set on corrupt zip")
	}
}

func TestExecute_Persists(t *testing.T) {
	coord := mustCoord(t, "example.com/persist", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	ifaceStore := &fakeInterfaceStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"client.go": "package client\ntype Client struct{}\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatal(err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, ifaceStore, nil)
	_, err = uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	persisted, found, err := ifaceStore.GetInterfaceRecord(context.Background(), coord, application.PipelineVersion)
	if err != nil {
		t.Fatalf("GetInterfaceRecord: %v", err)
	}
	if !found {
		t.Fatal("record was not persisted")
	}
	if persisted.ContentHash == "" {
		t.Error("persisted record has empty ContentHash")
	}
}

func TestExecute_ContentHashSet(t *testing.T) {
	coord := mustCoord(t, "example.com/hash", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	ifaceStore := &fakeInterfaceStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"client.go": "package client\ntype Client struct{}\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatal(err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, ifaceStore, nil)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ContentHash == "" {
		t.Error("ContentHash not set on result")
	}
}

func TestExecute_StorePutError(t *testing.T) {
	coord := mustCoord(t, "example.com/storeerr", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	storeErr := errors.New("disk full")
	ifaceStore := &fakeInterfaceStore{putErr: storeErr}

	zipData := buildModuleZip(t, coord, map[string]string{
		"client.go": "package client\ntype Client struct{}\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatal(err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, ifaceStore, nil)
	_, err = uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if !errors.Is(err, storeErr) {
		t.Errorf("expected storeErr, got %v", err)
	}
}

func TestExecute_Idempotent(t *testing.T) {
	coord := mustCoord(t, "example.com/idem", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	ifaceStore := &fakeInterfaceStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"client.go": "package client\ntype Client struct{}\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatal(err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, ifaceStore, nil)

	r1, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	r2, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if !r2.FromCache {
		t.Error("second Execute should be a cache hit")
	}
	if r1.Record.ContentHash != r2.Record.ContentHash {
		t.Errorf("content hashes differ: %q vs %q", r1.Record.ContentHash, r2.Record.ContentHash)
	}
}

func TestStrippedFS(t *testing.T) {
	coord := mustCoord(t, "example.com/fs", "v1.0.0")
	zipData := buildModuleZip(t, coord, map[string]string{
		"a.go":     "package a",
		"sub/b.go": "package b",
	})
	archive, err := ziparchive.New(zipData)
	if err != nil {
		t.Fatal(err)
	}

	prefix := coord.Path + "@" + coord.Version + "/"
	fsys := archive.FS(prefix)

	t.Run("Open and Read", func(t *testing.T) {
		testStrippedFS_OpenRead(t, fsys)
	})

	t.Run("ReadFile", func(t *testing.T) {
		testStrippedFS_ReadFile(t, fsys)
	})

	t.Run("ReadDir root", func(t *testing.T) {
		testStrippedFS_ReadDirRoot(t, fsys)
	})

	t.Run("ReadDir sub", func(t *testing.T) {
		testStrippedFS_ReadDirSub(t, fsys)
	})

	t.Run("syntheticDir", func(t *testing.T) {
		testStrippedFS_SyntheticDir(t, fsys)
	})

	t.Run("zipFileWrapper ReadDir (unsupported)", func(t *testing.T) {
		testStrippedFS_ZipFileWrapperReadDir(t, fsys)
	})

	t.Run("syntheticDirEntry Type and Info", func(t *testing.T) {
		testStrippedFS_SyntheticDirEntry(t, fsys)
	})

	t.Run("ReadFile error", func(t *testing.T) {
		testStrippedFS_ReadFileError(t, fsys)
	})
}

func testStrippedFS_OpenRead(t *testing.T, fsys fs.FS) {
	f, err := fsys.Open("a.go")
	if err != nil {
		t.Fatalf("Open a.go: %v", err)
	}
	defer func() {
		_ = f.Close()
	}()
	info, _ := f.Stat()
	if info.Name() != "a.go" {
		t.Errorf("expected a.go, got %s", info.Name())
	}
	if _, err := f.Read(make([]byte, 10)); err != nil && !errors.Is(err, io.EOF) {
		t.Errorf("Read a.go: %v", err)
	}
}

func testStrippedFS_ReadFile(t *testing.T, fsys fs.FS) {
	data, err := fs.ReadFile(fsys, "sub/b.go")
	if err != nil {
		t.Fatalf("ReadFile sub/b.go: %v", err)
	}
	if string(data) != "package b" {
		t.Errorf("expected 'package b', got %q", string(data))
	}
}

func testStrippedFS_ReadDirRoot(t *testing.T, fsys fs.FS) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatalf("ReadDir .: %v", err)
	}
	foundA, foundSub := false, false
	for _, e := range entries {
		if e.Name() == "a.go" && !e.IsDir() {
			foundA = true
		}
		if e.Name() == "sub" && e.IsDir() {
			foundSub = true
		}
	}
	if !foundA || !foundSub {
		t.Errorf("ReadDir . failed: foundA=%v, foundSub=%v", foundA, foundSub)
	}
}

func testStrippedFS_ReadDirSub(t *testing.T, fsys fs.FS) {
	entries, err := fs.ReadDir(fsys, "sub")
	if err != nil {
		t.Fatalf("ReadDir sub: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "b.go" {
		t.Errorf("ReadDir sub failed: %+v", entries)
	}
}

func testStrippedFS_SyntheticDir(t *testing.T, fsys fs.FS) {
	d, err := fsys.Open("sub")
	if err != nil {
		t.Fatalf("Open sub: %v", err)
	}
	defer func() {
		_ = d.Close()
	}()
	dinfo, _ := d.Stat()
	if !dinfo.IsDir() {
		t.Error("expected sub to be a directory")
	}
	if dinfo.Size() != 0 {
		t.Errorf("expected size 0 for synthetic dir, got %d", dinfo.Size())
	}
	if dinfo.Mode() != fs.ModeDir|0555 {
		t.Errorf("expected mode dr-xr-xr-x (0555|ModeDir), got %v", dinfo.Mode())
	}
	if !dinfo.ModTime().IsZero() {
		t.Error("expected zero mod time for synthetic dir")
	}
	if dinfo.Sys() != nil {
		t.Error("expected nil sys for synthetic dir")
	}

	dr, ok := d.(fs.ReadDirFile)
	if !ok {
		t.Fatal("expected syntheticDir to implement fs.ReadDirFile")
	}
	entries, err := dr.ReadDir(0)
	if err != nil {
		t.Fatalf("synthetic ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "b.go" {
		t.Errorf("synthetic ReadDir failed: %+v", entries)
	}
	if entries[0].IsDir() {
		t.Error("b.go should not be a directory")
	}
	if entries[0].Type() != 0 {
		t.Errorf("expected type 0 for b.go entry, got %v", entries[0].Type())
	}
	einfo, _ := entries[0].Info()
	if einfo.Name() != "b.go" {
		t.Errorf("expected b.go, got %s", einfo.Name())
	}
}

func testStrippedFS_ZipFileWrapperReadDir(t *testing.T, fsys fs.FS) {
	zf, err := fsys.Open("a.go")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = zf.Close()
	}()
	if _, err := zf.(fs.ReadDirFile).ReadDir(0); err == nil {
		t.Error("zipFileWrapper ReadDir should fail")
	}
}

func testStrippedFS_SyntheticDirEntry(t *testing.T, fsys fs.FS) {
	entries, _ := fs.ReadDir(fsys, ".")
	var subEntry fs.DirEntry
	for _, e := range entries {
		if e.Name() == "sub" {
			subEntry = e
			break
		}
	}
	if subEntry == nil {
		t.Fatal("sub entry not found")
	}
	if subEntry.Type() != fs.ModeDir {
		t.Errorf("expected ModeDir, got %v", subEntry.Type())
	}
	sinfo, err := subEntry.Info()
	if err != nil {
		t.Errorf("Info failed: %v", err)
	}
	if !sinfo.IsDir() {
		t.Error("Info should report directory")
	}
}

func testStrippedFS_ReadFileError(t *testing.T, fsys fs.FS) {
	if _, err := fs.ReadFile(fsys, "nonexistent"); err == nil {
		t.Error("ReadFile nonexistent should fail")
	}

	d, err := fsys.Open("sub")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.Close()
	}()
	if _, err := d.Read(make([]byte, 10)); err == nil {
		t.Error("Read on directory should fail")
	}
}

// -- helpers --

func mustCoord(t *testing.T, path, version string) domain2.ModuleCoordinate {
	t.Helper()
	c, err := domain2.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return c
}

func buildUseCase(
	t *testing.T,
	facts *fakeFactStore,
	blobs *fakeBlobStore,
	store *fakeInterfaceStore,
	ext *fakeExtractor,
) *application.ExtractInterfaceUseCase {
	t.Helper()
	if facts == nil {
		facts = &fakeFactStore{}
	}
	if blobs == nil {
		blobs = &fakeBlobStore{}
	}
	if store == nil {
		store = &fakeInterfaceStore{}
	}
	clk := fakeClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	var extractor ports.InterfaceExtractor
	if ext != nil {
		extractor = ext
	} else {
		// Use the real godoc extractor so tests that pass real zip data work end-to-end.
		extractor = godocextractor.New(application.PipelineVersion, clk)
	}
	return application.NewExtractInterfaceUseCase(application.Config{
		Facts:                facts,
		Blobs:                blobs,
		Store:                store,
		Extractor:            extractor,
		Clock:                clk,
		Stopwatch:            fakeStopwatch{},
		FetchPipelineVersion: application.PipelineVersion,
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func putFact(t *testing.T, s *fakeFactStore, coord domain2.ModuleCoordinate, blobHandle string) {
	t.Helper()
	putFactWithBlob(t, s, coord, blobHandle)
}

func putFactWithBlob(t *testing.T, s *fakeFactStore, coord domain2.ModuleCoordinate, blobHandle string) {
	t.Helper()
	r := domain2.FactRecord{
		SchemaVersion:      "2",
		ModulePath:         coord.Path,
		ModuleVersion:      coord.Version,
		PipelineVersion:    application.PipelineVersion,
		ContentLocation:    blobHandle,
		ContentHash:        "sha256:placeholder",
		VerificationStatus: "Verified",
	}
	if err := s.PutFetchRecord(context.Background(), r); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
}

func buildModuleZip(t *testing.T, coord domain2.ModuleCoordinate, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	prefix := coord.Path + "@" + coord.Version + "/"
	for name, content := range files {
		f, err := w.Create(prefix + name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// Compile-time check.
var _ fetchports.FactStore = (*fakeFactStore)(nil)
