package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/composition/storage"
	"code.eitanity.com/kanonarion/internal/config/domain"

	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	dirports "code.eitanity.com/kanonarion/internal/directive/ports"
	exampleports "code.eitanity.com/kanonarion/internal/example/ports"
	extractports "code.eitanity.com/kanonarion/internal/extract/ports"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
	fipsports "code.eitanity.com/kanonarion/internal/fips/ports"
	gdports "code.eitanity.com/kanonarion/internal/godebug/ports"
	ifaceports "code.eitanity.com/kanonarion/internal/iface/ports"
	licports "code.eitanity.com/kanonarion/internal/license/ports"
	nativeports "code.eitanity.com/kanonarion/internal/native/ports"
	sbomports "code.eitanity.com/kanonarion/internal/sbom/ports"
	staleports "code.eitanity.com/kanonarion/internal/staleness/ports"
	stdlibports "code.eitanity.com/kanonarion/internal/stdlib/ports"
	venports "code.eitanity.com/kanonarion/internal/vendortree/ports"
	vulnports "code.eitanity.com/kanonarion/internal/vuln/ports"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// fakeWalks is a walk store that is not SQLite and holds one walk.
type fakeWalks struct {
	walkports.WalkStore
	summary walkports.WalkSummary
}

func (f fakeWalks) ListWalks(context.Context, walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	return []walkports.WalkSummary{f.summary}, nil
}

// fakeStorage is a complete value with no file behind any of it: every store
// but Walks panics if the command touches it.
func fakeStorage(walkID string) (*storage.Storage, *int) {
	closes := new(int)
	return &storage.Storage{
		Facts:             struct{ fetchports.FactStore }{},
		Attestations:      struct{ fetchports.AttestationStore }{},
		Audit:             struct{ fetchports.AuditSink }{},
		Blobs:             struct{ fetchports.BlobStore }{},
		Walks:             fakeWalks{summary: walkports.WalkSummary{ID: walkID}},
		WalkPresence:      struct{ vulnports.WalkPresence }{},
		Licenses:          struct{ licports.LicenseStore }{},
		Interfaces:        struct{ ifaceports.InterfaceStore }{},
		CallGraphs:        struct{ cgports.CallGraphStore }{},
		CallGraphOutcomes: struct{ cgports.CallGraphOutcomeReader }{},
		Examples:          struct{ exampleports.ExampleStore }{},
		Extractions:       struct{ extractports.ExtractionStore }{},
		Vulnerabilities:   struct{ vulnports.VulnerabilityStore }{},
		SBOMs:             struct{ sbomports.SBOMStore }{},
		Directives:        struct{ dirports.DirectiveStore }{},
		GoDebug:           struct{ gdports.GoDebugStore }{},
		Vendor:            struct{ venports.VendorStore }{},
		FIPS:              struct{ fipsports.FIPSStore }{},
		Stdlib:            struct{ stdlibports.Store }{},
		Staleness:         struct{ staleports.Ledger }{},
		Native:            struct{ nativeports.NativeStore }{},
		Close:             func() error { *closes++; return nil },
	}, closes
}

// The first proof the CLI runs on a supplied backend: a read command answers
// from the fake walk store, and the store root is left as it was found.
func TestNewContainerFrom_AReadAnswersFromASuppliedBackend(t *testing.T) {
	st, closes := fakeStorage("walk-from-a-supplied-backend")
	ctr, cleanup, err := NewContainerFrom(st, t.TempDir(), "", "", false, domain.DefaultConfig(), quietLogger())
	if err != nil || ctr == nil {
		t.Fatalf("NewContainerFrom over fakes = (%v, %v), want a container", ctr, err)
	}
	if err := cleanup(); err != nil || *closes != 1 {
		t.Fatalf("cleanup = %v after %d close(s), want one close", err, *closes)
	}

	root := t.TempDir()
	st, _ = fakeStorage("walk-from-a-supplied-backend")
	orig := openStorage
	openStorage = func(storage.Request) (*storage.Storage, error) { return st, nil }
	t.Cleanup(func() { openStorage = orig })

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"walk-list", "--json", "--store-root", root}, &stdout, &stderr); err != nil {
		t.Fatalf("walk-list over a supplied backend: %v\nstderr: %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "walk-from-a-supplied-backend") {
		t.Errorf("stdout = %q, want the walk the supplied store holds", stdout.String())
	}
	if names := entries(t, root); len(names) != 0 {
		t.Errorf("walk-list over a supplied backend created %v under the store root", names)
	}
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, de := range des {
		names = append(names, de.Name())
	}
	return names
}

type fakeSchema struct{ state storage.SchemaState }

func (f fakeSchema) SchemaState(context.Context) (storage.SchemaState, error) { return f.state, nil }

// The refusal names the store as the backend reports it, not a SQLite path.
func TestNewContainerFrom_ARefusingBackendGivesTheNewerStoreRefusal(t *testing.T) {
	root := t.TempDir()
	st, closes := fakeStorage("")
	st.Writable = func(context.Context) error {
		return fmt.Errorf("%w: test backend", storage.ErrStoreSchemaNewer)
	}
	st.Schema = fakeSchema{state: storage.SchemaState{Applied: 88, Expected: 87, Unknown: []string{"vuln@v9999"}, Location: "postgres://example"}}

	ctr, cleanup, err := NewContainerFrom(st, root, "", "", false, domain.DefaultConfig(), quietLogger())
	if ctr != nil || cleanup != nil || err == nil {
		t.Fatalf("NewContainerFrom = (%v, cleanup %v, %v), want a refusal and nothing to close", ctr, cleanup != nil, err)
	}
	want := "store schema at postgres://example is newer than supported: 1 migration(s) applied that this binary does not know (vuln@v9999); upgrade kanonarion. " +
		"Run `kanonarion store info` to inspect the store without writing to it"
	if err.Error() != want {
		t.Errorf("refusal = %q, want %q", err, want)
	}
	if code, carried := ExitCodeFromError(err); !carried || code != ExitConfig {
		t.Errorf("exit code = (%d, carried %v), want ExitConfig carried", code, carried)
	}
	if *closes != 1 {
		t.Errorf("Close called %d times, want 1", *closes)
	}
}

func TestStoreInfo_ABackendWithNoSchemaStateSaysSo(t *testing.T) {
	st, _ := fakeStorage("")
	var text bytes.Buffer
	if err := writeStoreInfo(context.Background(), st, "/r", "/r/mirror.db", false, &text); err != nil {
		t.Fatalf("writeStoreInfo: %v", err)
	}
	if got, want := text.String(), "store schema: the storage backend reports no schema state\n"; got != want {
		t.Errorf("text = %q, want %q", got, want)
	}

	var js bytes.Buffer
	if err := writeStoreInfo(context.Background(), st, "/r", "/r/mirror.db", true, &js); err != nil {
		t.Fatalf("writeStoreInfo --json: %v", err)
	}
	var got storeInfoResult
	if err := json.Unmarshal(js.Bytes(), &got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.Status != storeSchemaUnreported || got.Applied != 0 || got.Expected != 0 || got.StoreRoot != "/r" {
		t.Errorf("json = %+v, want status %q and no counts", got, storeSchemaUnreported)
	}
}

// fakeBlobs is a blob store with no local paths, so the module cache cannot be
// linked into it.
type fakeBlobs struct{ fetchports.BlobStore }

func TestNewContainerFrom_FromModcacheRefusesABlobStoreWithoutLocalPaths(t *testing.T) {
	st, closes := fakeStorage("")
	st.Blobs = fakeBlobs{}
	t.Cleanup(func() { modcacheMode, modcacheDir, goSumPath = false, "", "" })
	modcacheMode, modcacheDir, goSumPath = true, t.TempDir(), filepath.Join(t.TempDir(), "go.sum")

	ctr, cleanup, err := NewContainerFrom(st, t.TempDir(), "", "", false, domain.DefaultConfig(), quietLogger())
	if ctr != nil || cleanup != nil || err == nil {
		t.Fatalf("NewContainerFrom = (%v, cleanup %v, %v), want a refusal", ctr, cleanup != nil, err)
	}
	if !strings.Contains(err.Error(), "--from-modcache") || !strings.Contains(err.Error(), "cli.fakeBlobs") {
		t.Errorf("refusal = %q, want it to name the flag and the blob store's type", err)
	}
	// Every other --from-modcache misuse exits 20 (ExitConfig); this one carries it.
	if code, carried := ExitCodeFromError(err); !carried || code != ExitConfig {
		t.Errorf("exit code = (%d, carried %v), want ExitConfig carried", code, carried)
	}
	if *closes != 1 {
		t.Errorf("Close called %d times, want 1", *closes)
	}
}
