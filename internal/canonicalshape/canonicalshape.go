// Package canonicalshape pins the exact bytes a record domain seals over.
//
// Every record domain hashes the canonical JSON of a record to produce its
// content hash, and every record already in the store was hashed over the bytes
// the code emitted on the day it was written. So a change to a canonical struct
// is not a refactor: it retroactively changes what every stored record is
// expected to hash to, and the store finds out one read at a time.
//
// That is not hypothetical. Two fields joined canonicalFileEntry in the licence
// domain without omitempty, and 638 records — a whole pipeline generation —
// stopped reproducing. Nothing detected it for as long as the affected rows were
// only listed and never read by coordinate, because listing reads summary
// columns that no integrity check covers.
//
// A green test suite could not have caught it. Every test hashed and verified
// inside one process, where both sides of the comparison see the same shape; the
// shape is only observable against a record written by a DIFFERENT generation,
// which no unit test holds. A golden file is how a unit test can hold one.
//
// AssertGolden compares against bytes checked in beside the test. It fires on
// anything that changes the hashed encoding — a field added or removed, a JSON
// tag renamed, a struct field reordered, a type whose rendering differs — which
// is a strictly wider net than pinning the key set, because reordering and
// retyping change the bytes without changing the keys.
package canonicalshape

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// UpdateEnv is the environment variable that rewrites golden files instead of
// asserting against them: KANONARION_UPDATE_GOLDEN=1 go test ./...
//
// Rewriting is deliberately a separate, explicit act. The point of the guard is
// that changing the hashed shape requires a decision, and a guard that could be
// silenced by the same command that runs it would not require one.
const UpdateEnv = "KANONARION_UPDATE_GOLDEN"

// AssertGolden compares got against the golden file at path, which is created on
// first run and rewritten when UpdateEnv is set.
//
// When it fails, the message states the only two changes that are legitimate,
// because the failure itself does not distinguish them:
//
//   - the field is omitempty AND absent from every record already written, so
//     records that predate it marshal to the bytes they always did. This is the
//     ordinary way to extend a shape, and artefact_identity, source_content_hash
//     and role are the worked examples in-tree.
//   - the shape genuinely changed, which owes a PipelineVersion bump and a
//     migration purging the generation it leaves behind.
//
// Retrofitting omitempty to a field that is ALREADY being hashed is neither, and
// is not a repair: the records already written were hashed with that key
// present, so removing it breaks exactly the records that currently verify.
// Measured on the maintainer's store, doing that to the two licence fields
// repairs 638 records and breaks 2,187.
func AssertGolden(t testing.TB, path string, got []byte) {
	t.Helper()

	if os.Getenv(UpdateEnv) != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("creating golden directory: %v", err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("writing golden file %s: %v", path, err)
		}
		t.Logf("wrote golden file %s (%d bytes)", path, len(got))
		return
	}

	want, err := os.ReadFile(path) // #nosec G304 -- test-only, path supplied by the test itself
	if os.IsNotExist(err) {
		t.Fatalf("golden file %s does not exist; create it with %s=1 go test ./... and commit it", path, UpdateEnv)
	}
	if err != nil {
		t.Fatalf("reading golden file %s: %v", path, err)
	}
	if bytes.Equal(got, want) {
		return
	}

	t.Errorf(`the canonical hashed shape changed.

golden %s:
  %s

now:
  %s

Every record already in the store was hashed over the golden bytes, so this
change alters what those records are expected to hash to and they will stop
verifying. Exactly two changes are legitimate:

  1. a NEW field carrying omitempty, absent from every record already written,
     so pre-existing records marshal to the bytes they always did; or
  2. a genuine shape change, which owes a PipelineVersion bump and a migration
     purging the generation it leaves behind.

Retrofitting omitempty to a field that is already hashed is neither: the stored
records were hashed WITH that key, so removing it breaks the records that
currently verify rather than repairing anything.

If this change is legitimate, re-record with %s=1 go test ./...`,
		path, want, got, UpdateEnv)
}
