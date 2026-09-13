package nativefacts_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	nativeports "github.com/eitanity/kanonarion/internal/native/ports"
	"github.com/eitanity/kanonarion/internal/sbom/adapters/nativefacts"
)

type fakeStore struct {
	rec   nativedomain.Record
	found bool
	err   error
}

func (f *fakeStore) PutNativeRecord(context.Context, nativedomain.Record) error { return nil }
func (f *fakeStore) GetNativeRecord(context.Context, coordinate.ModuleCoordinate) (nativedomain.Record, bool, error) {
	return f.rec, f.found, f.err
}

func coord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate("example.com/go-sqlite3", "v1.14.12")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestNativeRecord_AnAbsentRecordIsNotAnError. A module nobody examined is an
// ordinary outcome, and the caller must keep it distinct from "ships no native
// code" — the store cannot tell them apart because only one was ever measured.
func TestNativeRecord_AnAbsentRecordIsNotAnError(t *testing.T) {
	rec, found, err := nativefacts.New(&fakeStore{}).NativeRecord(context.Background(), coord(t))
	if err != nil {
		t.Fatalf("NativeRecord = %v, want no error for a module with no record", err)
	}
	if found {
		t.Error("found = true for a store holding nothing")
	}
	if rec.Presence != "" {
		t.Errorf("an absent record carries presence %q; it must carry none", rec.Presence)
	}
}

// TestNativeRecord_ServesWhatTheStoreHolds.
func TestNativeRecord_ServesWhatTheStoreHolds(t *testing.T) {
	want := nativedomain.Record{Presence: nativedomain.PresenceIdentified, ArtefactIdentity: "zip:h1:aa="}
	rec, found, err := nativefacts.New(&fakeStore{rec: want, found: true}).NativeRecord(context.Background(), coord(t))
	if err != nil || !found {
		t.Fatalf("NativeRecord = (%v, %v), want the held record", found, err)
	}
	if rec.Presence != want.Presence || rec.ArtefactIdentity != want.ArtefactIdentity {
		t.Errorf("record = %+v, want %+v", rec, want)
	}
}

// TestNativeRecord_AConflictIsReported, never answered as an absence. Two
// records naming different artefacts for one pinned version is a contradiction
// in the evidence the inventory is assembled from.
func TestNativeRecord_AConflictIsReported(t *testing.T) {
	_, found, err := nativefacts.New(&fakeStore{err: nativeports.ErrNativeConflict}).NativeRecord(context.Background(), coord(t))
	if err == nil {
		t.Fatal("NativeRecord = nil error for a conflicting store")
	}
	if !errors.Is(err, nativeports.ErrNativeConflict) {
		t.Errorf("errors.Is(err, ErrNativeConflict) = false for %v", err)
	}
	if found {
		t.Error("found = true beside an error")
	}
}
