package localfs_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// recordingSink keeps every event appended to it.
type recordingSink struct{ events []audit.Event }

func (s *recordingSink) RecordEvent(e audit.Event) error {
	s.events = append(s.events, e)
	return nil
}

type failingSink struct{}

func (failingSink) RecordEvent(audit.Event) error { return errors.New("log unwritable") }

var uuidFiles = map[string]string{
	"go.mod":  "module example.com/m\n",
	"LICENSE": "BSD-3-Clause text\n",
	"m.go":    "package m\n\nfunc F() string { return strings.Repeat(\"x\", 4096) }\n" + strings.Repeat("// padding\n", 200),
}

// zipCases are the shapes a held module zip can take after it was verified.
func zipCases(t *testing.T) (ports.BlobIdentity, map[string][]byte) {
	t.Helper()
	intact, identity := fetchtest.ModuleZip(t, "example.com/m", "v1.0.0", uuidFiles)
	altered := map[string]string{}
	for k, v := range uuidFiles {
		altered[k] = v
	}
	altered["LICENSE"] = "GPL-3.0 text\n"
	altered["backdoor.go"] = "package m\n\nfunc Backdoor() {}\n"
	rezip, _ := fetchtest.ModuleZip(t, "example.com/m", "v1.0.0", altered)

	flipped := bytes.Clone(intact)
	// Inside the first entry's compressed data: past its 30-byte local header
	// and its name.
	flipped[30+len("example.com/m@v1.0.0/LICENSE")+3] ^= 0xff

	return identity, map[string][]byte{
		"intact":    intact,
		"rezip":     rezip,
		"flipped":   flipped,
		"truncated": intact[:len(intact)/2],
	}
}

// heldAt stores intact under identity in a fresh store at dir, then replaces the
// file with held directly, the way an edit to the store's directory does. The
// store under test is opened over dir afterwards, so it holds no verdict yet.
func heldAt(ctx context.Context, t *testing.T, dir string, identity ports.BlobIdentity, intact, held []byte) string {
	t.Helper()
	seed := localfs.New(dir)
	if err := seed.Put(ctx, identity, bytes.NewReader(intact)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	path, err := seed.GetPath(ctx, identity)
	if err != nil {
		t.Fatalf("GetPath of the intact blob: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("removing held blob: %v", err)
	}
	if err := os.WriteFile(path, held, 0o600); err != nil {
		t.Fatalf("writing held blob: %v", err)
	}
	return path
}

// Get and GetPath serve only bytes that hash to the identity they are asked for:
// a valid zip of other content, a zip with a corrupted entry and a cut-short zip
// are each refused with ErrBlobTampered and nothing is handed out, and an
// absent identity is still absence.
func TestStore_ServesOnlyBytesThatHashToTheIdentity(t *testing.T) {
	ctx := context.Background()
	identity, shapes := zipCases(t)
	for name, held := range shapes {
		for _, read := range []string{"Get", "GetPath"} {
			t.Run(name+"/"+read, func(t *testing.T) {
				dir := t.TempDir()
				heldAt(ctx, t, dir, identity, shapes["intact"], held)
				sink := &recordingSink{}
				store := localfs.New(dir).WithAudit(sink, "kanonarion test")

				served, err := readOnce(ctx, t, store, identity, read, held)
				if name == "intact" {
					if err != nil || !served || len(sink.events) != 0 {
						t.Fatalf("%s(intact) = served %v, err %v, %d events; want the bytes and no event", read, served, err, len(sink.events))
					}
					return
				}
				if served {
					t.Errorf("%s(%s) handed out the refused bytes", read, name)
				}
				assertRefusal(t, name, err, identity, sink)
			})
		}
	}

	for _, read := range []string{"Get", "GetPath"} {
		_, err := readOnce(ctx, t, localfs.New(t.TempDir()), identity, read, nil)
		if !errors.Is(err, localfs.ErrBlobNotFound) {
			t.Errorf("%s(absent) = %v, want ErrBlobNotFound", read, err)
		}
	}
}

// readOnce reads identity through Get or GetPath, reporting whether anything
// was handed out; bytes Get hands out must be want.
func readOnce(ctx context.Context, t *testing.T, store *localfs.Store, identity ports.BlobIdentity, read string, want []byte) (bool, error) {
	t.Helper()
	if read == "GetPath" {
		p, err := store.GetPath(ctx, identity)
		return p != "", err
	}
	rc, err := store.Get(ctx, identity)
	if rc == nil {
		return false, err
	}
	got, rerr := io.ReadAll(rc)
	_ = rc.Close()
	if rerr != nil || !bytes.Equal(got, want) {
		t.Errorf("Get served %d bytes, err %v; want the held bytes", len(got), rerr)
	}
	return true, err
}

// assertRefusal checks a refusal names what it refused and was appended once.
func assertRefusal(t *testing.T, name string, err error, identity ports.BlobIdentity, sink *recordingSink) {
	t.Helper()
	var refused *ports.BlobTamperedError
	if !errors.Is(err, ports.ErrBlobTampered) || !errors.As(err, &refused) || refused.Identity != identity {
		t.Fatalf("%s: err = %v, want ErrBlobTampered carrying the identity", name, err)
	}
	if name == "rezip" && refused.Observed == "" {
		t.Error("a valid re-zip hashes; the refusal must name what it hashed to")
	}
	if name != "rezip" && refused.Unhashable == "" {
		t.Errorf("%s does not hash; the refusal must say why", name)
	}
	if len(sink.events) != 1 || sink.events[0].Type != audit.EventVerificationFailed {
		t.Fatalf("events = %+v, want one verification_failed", sink.events)
	}
	p := sink.events[0].Payload
	if p["artefact_identity"] != identity.String() || p["expected_hash"] != identity.Hash().String() || p["command"] != "kanonarion test" {
		t.Errorf("event payload = %v", p)
	}
}

// A go.mod is hashed as the single file go.mod, so a held go.mod whose text
// changed is refused.
func TestStore_RefusesAnAlteredGoMod(t *testing.T) {
	ctx := context.Background()
	identity := fetchtest.GoModBlob(t, "module example.com/m\n")
	dir := t.TempDir()
	heldAt(ctx, t, dir, identity, []byte("module example.com/m\n"), []byte("module example.com/m\n\nreplace x => ../x\n"))
	store := localfs.New(dir)
	if _, err := store.Get(ctx, identity); !errors.Is(err, ports.ErrBlobTampered) {
		t.Errorf("Get(altered go.mod) = %v, want ErrBlobTampered", err)
	}
	if _, err := store.GetPath(ctx, identity); !errors.Is(err, ports.ErrBlobTampered) {
		t.Errorf("GetPath(altered go.mod) = %v, want ErrBlobTampered", err)
	}
}

// One verdict per identity while the file keeps its size and modification time:
// a refusal is appended once however often it is read, a change to either
// re-hashes, and a change that keeps both is the stated limit of the rule.
func TestStore_VerdictStandsUntilSizeOrMtimeChanges(t *testing.T) {
	ctx := context.Background()
	identity, shapes := zipCases(t)
	dir := t.TempDir()
	path := heldAt(ctx, t, dir, identity, shapes["intact"], shapes["intact"])
	sink := &recordingSink{}
	store := localfs.New(dir).WithAudit(sink, "")

	if _, err := store.GetPath(ctx, identity); err != nil {
		t.Fatalf("GetPath(intact): %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Same size, same mtime: the cached verdict answers.
	same := bytes.Clone(shapes["intact"])
	same[len(same)-1] ^= 0xff
	if err := os.WriteFile(path, same, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPath(ctx, identity); err != nil {
		t.Fatalf("GetPath after a change keeping size and mtime = %v; the verdict should stand", err)
	}

	// A new mtime re-hashes.
	if err := os.Chtimes(path, info.ModTime().Add(time.Second), info.ModTime().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPath(ctx, identity); !errors.Is(err, ports.ErrBlobTampered) {
		t.Fatalf("GetPath after an mtime change = %v, want ErrBlobTampered", err)
	}
	// The refusal is itself the standing verdict: read again, nothing is appended.
	if _, err := store.Get(ctx, identity); !errors.Is(err, ports.ErrBlobTampered) {
		t.Fatalf("second read = %v, want ErrBlobTampered", err)
	}
	if len(sink.events) != 1 {
		t.Errorf("events = %d, want 1 for one refused file", len(sink.events))
	}

	// A new size re-hashes: the intact bytes verify again.
	if err := os.WriteFile(path, shapes["intact"][:len(shapes["intact"])-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, shapes["intact"], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime().Add(2*time.Second), info.ModTime().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPath(ctx, identity); err != nil {
		t.Fatalf("GetPath after restoring the bytes = %v, want them served", err)
	}
}

// Put replaces held bytes that no longer verify, which is what the re-fetch a
// refusal names relies on, and tells the observer the refusal no longer stands.
// Bytes that still verify are kept.
func TestStore_PutReplacesRefusedBytes(t *testing.T) {
	ctx := context.Background()
	identity, shapes := zipCases(t)
	dir := t.TempDir()
	heldAt(ctx, t, dir, identity, shapes["intact"], shapes["rezip"])
	var observed []*ports.BlobTamperedError
	store := localfs.New(dir).WithRefusalObserver(func(id ports.BlobIdentity, r *ports.BlobTamperedError) {
		if id != identity {
			t.Errorf("observed %s, want %s", id, identity)
		}
		observed = append(observed, r)
	})
	if _, err := store.Get(ctx, identity); !errors.Is(err, ports.ErrBlobTampered) {
		t.Fatalf("Get(rezip) = %v, want ErrBlobTampered", err)
	}
	if err := store.Put(ctx, identity, bytes.NewReader(shapes["intact"])); err != nil {
		t.Fatalf("Put over refused bytes: %v", err)
	}
	rc, err := store.Get(ctx, identity)
	if err != nil {
		t.Fatalf("Get after Put = %v, want the replaced bytes", err)
	}
	got, rerr := io.ReadAll(rc)
	_ = rc.Close()
	if rerr != nil || !bytes.Equal(got, shapes["intact"]) {
		t.Error("Put did not replace the refused bytes")
	}
	if len(observed) != 2 || observed[0] == nil || observed[1] != nil {
		t.Errorf("observer calls = %v, want a refusal then its withdrawal", observed)
	}

	if err := store.Put(ctx, identity, strings.NewReader("other bytes")); err != nil {
		t.Fatalf("Put over verified bytes: %v", err)
	}
	if _, err := store.Get(ctx, identity); err != nil {
		t.Fatalf("Get after a Put over verified bytes = %v; they must be kept", err)
	}
}

// The event that says the store's bytes changed is never lost silently: a
// failed append is returned beside the refusal.
func TestStore_RefusalReportsAFailedAppend(t *testing.T) {
	ctx := context.Background()
	identity, shapes := zipCases(t)
	dir := t.TempDir()
	heldAt(ctx, t, dir, identity, shapes["intact"], shapes["rezip"])
	store := localfs.New(dir).WithAudit(failingSink{}, "")
	_, err := store.Get(ctx, identity)
	if !errors.Is(err, ports.ErrBlobTampered) || !strings.Contains(err.Error(), "log unwritable") {
		t.Errorf("Get = %v, want the refusal and the failed append", err)
	}
}
