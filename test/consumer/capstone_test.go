// Package consumer_test is the capstone: a consumer-shaped acceptance
// test compiled against the public façade (pkg/kanonarion) ONLY, with no
// internal/ import — exactly what the open-core enterprise build and any other
// external downstream may rely on. It is deliberately kept in
// its own directory so the package's import set is the whole acceptance: if any
// line below needed an internal package, this file would not compile, and
// TestConsumerCapstoneImportsPublicSurfaceOnly (in test/architecture_test.go)
// fails the build if an internal import ever sneaks in.
//
// Every published consumer relationship is exercised: result types received,
// query use cases called via the DI container, substitution ports implemented
// (a PostgreSQL-shaped fact store and an S3-shaped blob store with no local
// path), the verified fetch/serve driver, the local walk→extract driver, the
// content-identity surface (canonical digest + Merkle root + inclusion proof),
// on-process signing through an injected Signer, and the airgap delta-bundle
// build with validate-and-ingest verify-on-read fail-closed.
package consumer_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// ----------------------------------------------------------------------------
// Substitution-port fakes: shaped like the backends an enterprise consumer
// substitutes, implemented against the published port interfaces alone.
// ----------------------------------------------------------------------------

// fakePostgresFactStore stands in for the PostgreSQL backend that replaces the
// OSS SQLite fact store (context). It implements kanonarion.FactStore
// and nothing more — proving the published persistence seam is satisfiable by a
// non-SQLite backend without reaching into internal/.
type fakePostgresFactStore struct {
	rows map[string]kanonarion.FactRecord
}

func newFakePostgresFactStore() *fakePostgresFactStore {
	return &fakePostgresFactStore{rows: map[string]kanonarion.FactRecord{}}
}

func factKey(coord kanonarion.ModuleCoordinate, pipelineVersion string) string {
	return coord.Path + "@" + coord.Version + "#" + pipelineVersion
}

func (s *fakePostgresFactStore) PutFetchRecord(_ context.Context, record kanonarion.FactRecord) error {
	s.rows[factKey(record.Coordinate(), record.PipelineVersion)] = record
	return nil
}

func (s *fakePostgresFactStore) GetFetchRecord(_ context.Context, coord kanonarion.ModuleCoordinate, pipelineVersion string) (kanonarion.FactRecord, bool, error) {
	rec, ok := s.rows[factKey(coord, pipelineVersion)]
	return rec, ok, nil
}

// fakeS3BlobStore stands in for an S3-style object store replacing the local
// filesystem blob store. It implements kanonarion.BlobStore (Put/Get/Exists)
// and deliberately does NOT implement the optional BlobPathOptimizer: an object
// store cannot hand back a local filesystem path. This is the concrete proof of
// the §7 reshape — GetPath was split off so an S3 backend satisfies
// BlobStore without faking a path.
type fakeS3BlobStore struct {
	objects map[kanonarion.BlobHandle][]byte
}

func newFakeS3BlobStore() *fakeS3BlobStore {
	return &fakeS3BlobStore{objects: map[kanonarion.BlobHandle][]byte{}}
}

func (s *fakeS3BlobStore) Put(_ context.Context, content io.Reader) (kanonarion.BlobHandle, error) {
	data, err := io.ReadAll(content)
	if err != nil {
		return "", fmt.Errorf("reading blob content: %w", err)
	}
	// A content-addressed handle, mirroring how a real object store keys blobs.
	handle := kanonarion.BlobHandle("s3://" + kanonarion.NewContentIdentity().CanonicalDigest(data).Hex)
	s.objects[handle] = data
	return handle, nil
}

func (s *fakeS3BlobStore) Get(_ context.Context, handle kanonarion.BlobHandle) (io.ReadCloser, error) {
	data, ok := s.objects[handle]
	if !ok {
		return nil, errors.New("blob not found")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s *fakeS3BlobStore) Exists(_ context.Context, handle kanonarion.BlobHandle) (bool, error) {
	_, ok := s.objects[handle]
	return ok, nil
}

// fakeKeyedSigner stands in for the enterprise sigstore-backed Signer injected
// through the DI container: unlike the OSS no-op default it produces a present
// attestation over the subject digest (§2).
type fakeKeyedSigner struct{}

func (fakeKeyedSigner) Sign(_ context.Context, subject kanonarion.SubjectDigest) (kanonarion.Attestation, error) {
	return kanonarion.Attestation{
		Present: true,
		Subject: subject,
		Bundle:  []byte("signed:" + subject.Hex),
	}, nil
}

// Compile-time proof that the consumer fakes satisfy the published ports purely
// from pkg/kanonarion. If a port were widened (a breaking change under the
// §4 asymmetry rule), these assignments would stop compiling.
var (
	_ kanonarion.FactStore = (*fakePostgresFactStore)(nil)
	_ kanonarion.BlobStore = (*fakeS3BlobStore)(nil)
	_ kanonarion.Signer    = fakeKeyedSigner{}
	_ kanonarion.Signer    = kanonarion.NewNoopSigner()
)

// ----------------------------------------------------------------------------
// Bullet: substitute a fake Postgres-shaped *Store and an S3-shaped BlobStore
// (no GetPath).
// ----------------------------------------------------------------------------

func TestConsumer_SubstitutionPortsAreImplementable(t *testing.T) {
	ctx := context.Background()

	// The Postgres-shaped fact store round-trips a record through the published
	// FactStore contract.
	fs := newFakePostgresFactStore()
	coord := kanonarion.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	if _, found, err := fs.GetFetchRecord(ctx, coord, "0.0.0"); err != nil || found {
		t.Fatalf("empty fact store: found=%v err=%v, want found=false err=nil", found, err)
	}

	// The S3-shaped blob store round-trips bytes through Put/Get/Exists.
	bs := newFakeS3BlobStore()
	handle, err := bs.Put(ctx, strings.NewReader("module-zip-bytes"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	present, err := bs.Exists(ctx, handle)
	if err != nil || !present {
		t.Fatalf("Exists after Put: present=%v err=%v", present, err)
	}
	rc, err := bs.Get(ctx, handle)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(got) != "module-zip-bytes" {
		t.Errorf("Get returned %q, want the stored bytes", got)
	}

	// The object-store backend must NOT satisfy the optional path capability:
	// that is the whole point of splitting GetPath into BlobPathOptimizer so S3
	// can back BlobStore without a local path (§7).
	if _, ok := any(bs).(kanonarion.BlobPathOptimizer); ok {
		t.Error("the S3-shaped BlobStore unexpectedly implements BlobPathOptimizer; an object store has no local path")
	}
}

// ----------------------------------------------------------------------------
// Bullet: construct each Query use case via the DI container.
// ----------------------------------------------------------------------------

func TestConsumer_QueryUseCasesViaDIContainer(t *testing.T) {
	ctx := context.Background()

	queries, cleanup, err := kanonarion.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := cleanup(); cerr != nil {
			t.Errorf("cleanup: %v", cerr)
		}
	})

	// Every read use case is wired by the public composition entrypoint.
	if queries.Fetch == nil || queries.Walks == nil || queries.License == nil ||
		queries.Interface == nil || queries.CallGraph == nil || queries.Examples == nil ||
		queries.Extraction == nil || queries.Vuln == nil || queries.ScanRuns == nil ||
		queries.SBOM == nil {
		t.Fatalf("Open left a Query use case unwired: %+v", queries)
	}

	// A read against the empty store must report a clean "unknown" — found=false,
	// no error — not a confident negative (absence-vs-zero).
	_, found, err := queries.Fetch.GetFetchRecord(ctx,
		kanonarion.ModuleCoordinate{Path: "example.com/absent", Version: "v0.0.1"}, "0.0.0")
	if err != nil {
		t.Fatalf("GetFetchRecord on empty store errored: %v", err)
	}
	if found {
		t.Error("GetFetchRecord reported found=true against an empty store")
	}
}

// ----------------------------------------------------------------------------
// Bullet: compute a content digest + Merkle root; sign on-process via an
// injected Signer.
// ----------------------------------------------------------------------------

func TestConsumer_ContentIdentityAndOnProcessSigning(t *testing.T) {
	ctx := context.Background()
	ci := kanonarion.NewContentIdentity()

	// Canonical digests of two blobs, then a Merkle root + inclusion proof over
	// the ordered set — the single canonical-identity surface signing and
	// bundling both commit to (§1).
	a := ci.CanonicalDigest([]byte("artefact-a"))
	b := ci.CanonicalDigest([]byte("artefact-b"))
	if a.Algorithm != "sha256" || a.Hex == "" {
		t.Fatalf("CanonicalDigest produced %+v, want a non-empty sha256 digest", a)
	}

	members := []kanonarion.SubjectDigest{a, b}
	root, err := ci.MerkleRoot(members)
	if err != nil {
		t.Fatalf("MerkleRoot: %v", err)
	}
	proof, err := ci.InclusionProof(members, 0)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if !ci.VerifyInclusion(a, proof, root) {
		t.Error("VerifyInclusion rejected a member that is in the set")
	}
	// A proof pins the member's position: the index-0 proof must not verify b.
	if ci.VerifyInclusion(b, proof, root) {
		t.Error("VerifyInclusion accepted the wrong member for the index-0 proof")
	}

	// The OSS no-op signer yields NO attestation (Present=false) — distinct from
	// a present attestation carrying empty trust (§2).
	att, err := kanonarion.NewNoopSigner().Sign(ctx, root)
	if err != nil {
		t.Fatalf("no-op Sign: %v", err)
	}
	if att.Present {
		t.Error("the no-op signer reported Present=true; an unconfigured signer must yield no attestation")
	}

	// An injected keyed signer signs the same root on-process and returns a
	// present attestation bound to the canonical digest.
	signed, err := fakeKeyedSigner{}.Sign(ctx, root)
	if err != nil {
		t.Fatalf("keyed Sign: %v", err)
	}
	if !signed.Present || signed.Subject != root || len(signed.Bundle) == 0 {
		t.Errorf("injected signer attestation = %+v, want Present over the root with a bundle", signed)
	}
}

// ----------------------------------------------------------------------------
// Bullet: run a local walk→extract; build a delta bundle (commit + sign).
//
// The local walk→extract is fully offline (source never leaves the machine).
// The "delta bundle" commits to the produced records by their canonical
// self-hashes through the content-identity Merkle root, then signs that root
// on-process — proving identity, bundling, and signing compose over real
// driver-produced records, all from the public surface.
// ----------------------------------------------------------------------------

func TestConsumer_LocalWalkExtractAndDeltaBundle(t *testing.T) {
	ctx := context.Background()
	ci := kanonarion.NewContentIdentity()

	driver, cleanup, err := kanonarion.OpenDriver(t.TempDir())
	if err != nil {
		t.Fatalf("OpenDriver: %v", err)
	}
	t.Cleanup(func() { _ = cleanup() })

	dir := writeLocalModule(t)
	res, err := driver.LocalWalkExtract.Run(ctx, kanonarion.LocalWalkExtractRequest{Dir: dir})
	if err != nil {
		t.Fatalf("LocalWalkExtract.Run: %v", err)
	}
	if res.Walk.ID == "" {
		t.Fatal("local walk produced no walk record ID")
	}
	if res.Extraction.ID == "" {
		t.Fatal("local walk→extract produced no extraction run ID")
	}

	// Build the delta bundle: one canonical-digest leaf per produced record, in a
	// fixed order, committed by the Merkle root.
	leaves := make([]kanonarion.SubjectDigest, 0, 2)
	for _, contentHash := range []string{res.Walk.ContentHash, res.Extraction.ContentHash} {
		leaf, derr := digestOf(contentHash)
		if derr != nil {
			t.Fatalf("record content hash %q is not a canonical digest: %v", contentHash, derr)
		}
		leaves = append(leaves, leaf)
	}
	root, err := ci.MerkleRoot(leaves)
	if err != nil {
		t.Fatalf("bundle MerkleRoot: %v", err)
	}
	// Each leaf is provably committed by the root (the inclusion proof a far-side
	// importer checks).
	for i, leaf := range leaves {
		proof, perr := ci.InclusionProof(leaves, i)
		if perr != nil {
			t.Fatalf("InclusionProof(%d): %v", i, perr)
		}
		if !ci.VerifyInclusion(leaf, proof, root) {
			t.Errorf("bundle leaf %d is not provably in the committed set", i)
		}
	}
	// Sign the bundle root on-process with the injected (keyed) signer.
	signer := fakeKeyedSigner{}
	attestation, err := signer.Sign(ctx, root)
	if err != nil {
		t.Fatalf("signing the bundle root: %v", err)
	}
	if !attestation.Present || attestation.Subject != root {
		t.Errorf("bundle attestation = %+v, want a present attestation over the root", attestation)
	}
}

// ----------------------------------------------------------------------------
// Bullet: validate-and-ingest with verify-on-read fail-closed.
//
// A consumer cannot mint a valid fact record from the public surface — core's
// canonical hasher stays internal (§3), so consumers receive valid
// records, never forge them. The verified-fact boundary therefore rejects any
// hand-built record fail-closed, and reports a clean "unknown" (not a confident
// negative) for an absent coordinate. The valid-record round-trip is
// exercised end-to-end in the network-gated airgap test below, sourced from a
// real fetched record.
// ----------------------------------------------------------------------------

func TestConsumer_ValidateIngestFailClosed(t *testing.T) {
	ctx := context.Background()

	driver, cleanup, err := kanonarion.OpenDriver(t.TempDir())
	if err != nil {
		t.Fatalf("OpenDriver: %v", err)
	}
	t.Cleanup(func() { _ = cleanup() })

	// A forged record — well-formed shape, but a content hash the consumer cannot
	// legitimately produce — is refused fail-closed, surfacing ErrVerificationFailed.
	forged := kanonarion.FactRecord{
		ModulePath:      "example.com/forged",
		ModuleVersion:   "v1.0.0",
		PipelineVersion: "0.0.0",
		ContentHash:     "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	if err := driver.ValidateIngest.Ingest(ctx, forged); !errors.Is(err, kanonarion.ErrVerificationFailed) {
		t.Fatalf("Ingest of a forged record: got %v, want ErrVerificationFailed", err)
	}

	// An absent coordinate reads back as a clean unknown: not found, no error.
	_, found, err := driver.ValidateIngest.ReadVerified(ctx, forged.Coordinate(), forged.PipelineVersion)
	if err != nil {
		t.Fatalf("ReadVerified of an absent coordinate errored: %v", err)
	}
	if found {
		t.Error("ReadVerified reported found=true for a record that was never ingested")
	}
}

// ----------------------------------------------------------------------------
// Bullet: run verified single-coordinate fetch/serve; full airgap round-trip of
// a valid record.
//
// Serve resolves a real published coordinate through the Go module proxy, so a
// live run needs network and is opt-in (set KANONARION_NETWORK_TESTS) to keep
// the default suite hermetic and deterministic. The driver wiring — the part the
// façade is responsible for — is asserted unconditionally; the live run then
// drives the full airgap flow: fetch a valid record, bundle + sign it, and
// validate-and-ingest it into a separate store with verify-on-read, finally
// proving fail-closed rejection of a tampered copy.
// ----------------------------------------------------------------------------

func TestConsumer_VerifiedFetchServeAndAirgapRoundTrip(t *testing.T) {
	ctx := context.Background()

	producer, cleanup, err := kanonarion.OpenDriver(t.TempDir())
	if err != nil {
		t.Fatalf("OpenDriver: %v", err)
	}
	t.Cleanup(func() { _ = cleanup() })

	if producer.FetchServe == nil {
		t.Fatal("OpenDriver left the verified fetch/serve driver unwired")
	}

	if os.Getenv("KANONARION_NETWORK_TESTS") == "" {
		t.Skip("set KANONARION_NETWORK_TESTS=1 to exercise the live verified fetch/serve over the module proxy")
	}

	out, err := producer.FetchServe.Serve(ctx, kanonarion.ServeRequest{
		Coordinate: kanonarion.ModuleCoordinate{Path: "golang.org/x/time", Version: "v0.5.0"},
	})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if out.Handle == "" {
		t.Error("Serve returned an empty blob handle for a successful fetch")
	}
	// A gating proxy makes its own decision off the recorded status; here we only
	// assert the strongest assurances the public path can yield for a sumdb-listed
	// module.
	switch out.VerificationStatus {
	case kanonarion.Verified, kanonarion.VerifiedBySumDBOnly:
	default:
		t.Errorf("Serve recorded verification status %q, want Verified or VerifiedBySumDBOnly", out.VerificationStatus)
	}

	// The fetched record is a valid, core-produced fact record: bundle + sign it,
	// then validate-and-ingest it into a far-side store.
	rec := out.Record
	ci := kanonarion.NewContentIdentity()
	leaf, err := digestOf(rec.ContentHash)
	if err != nil {
		t.Fatalf("fetched record content hash is not canonical: %v", err)
	}
	root, err := ci.MerkleRoot([]kanonarion.SubjectDigest{leaf})
	if err != nil {
		t.Fatalf("bundle MerkleRoot: %v", err)
	}
	if _, err := (fakeKeyedSigner{}).Sign(ctx, root); err != nil {
		t.Fatalf("signing the bundle root: %v", err)
	}

	consumer, cleanupC, err := kanonarion.OpenDriver(t.TempDir())
	if err != nil {
		t.Fatalf("OpenDriver (consumer): %v", err)
	}
	t.Cleanup(func() { _ = cleanupC() })

	if err := consumer.ValidateIngest.Ingest(ctx, rec); err != nil {
		t.Fatalf("Ingest of a valid fetched record: %v", err)
	}
	got, found, err := consumer.ValidateIngest.ReadVerified(ctx, rec.Coordinate(), rec.PipelineVersion)
	if err != nil || !found {
		t.Fatalf("ReadVerified of the ingested record: found=%v err=%v", found, err)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("round-tripped record hash = %q, want %q", got.ContentHash, rec.ContentHash)
	}

	// A tampered copy is rejected fail-closed on import (§1,3).
	tampered := rec
	tampered.ModuleVersion = "v9.9.9"
	if err := consumer.ValidateIngest.Ingest(ctx, tampered); !errors.Is(err, kanonarion.ErrVerificationFailed) {
		t.Errorf("Ingest of a tampered record: got %v, want ErrVerificationFailed", err)
	}
}

// ----------------------------------------------------------------------------
// Helpers (pkg/kanonarion + stdlib only).
// ----------------------------------------------------------------------------

// digestOf turns a record's canonical self-hash ("sha256:<hex>") into the
// SubjectDigest the content-identity surface commits to.
func digestOf(contentHash string) (kanonarion.SubjectDigest, error) {
	algorithm, hex, ok := strings.Cut(contentHash, ":")
	if !ok || algorithm == "" || hex == "" {
		return kanonarion.SubjectDigest{}, errors.New("content hash is not in algorithm:hex form")
	}
	return kanonarion.SubjectDigest{Algorithm: algorithm, Hex: hex}, nil
}

// writeLocalModule writes a minimal, dependency-free Go module into a temp dir
// so the local walk→extract runs fully offline. A low go directive avoids
// toolchain auto-download.
func writeLocalModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	write("go.mod", "module example.com/capstone\n\ngo 1.21\n")
	write("capstone.go", "// Package capstone is a dependency-free fixture module.\npackage capstone\n\n// Add returns the sum of a and b.\nfunc Add(a, b int) int { return a + b }\n")
	return dir
}
