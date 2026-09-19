package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sbom/application"

	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
)

// fakeNativeReader serves what a test seeded, and can fail for one coordinate —
// which is the store holding records that name two different artefacts for one
// pinned version.
type fakeNativeReader struct {
	recs    map[coordinate.ModuleCoordinate]nativedomain.Record
	failFor coordinate.ModuleCoordinate
	err     error
	asked   []coordinate.ModuleCoordinate
}

func (f *fakeNativeReader) NativeRecord(
	_ context.Context, coord coordinate.ModuleCoordinate,
) (nativedomain.Record, bool, error) {
	f.asked = append(f.asked, coord)
	if f.err != nil && coord == f.failFor {
		return nativedomain.Record{}, false, f.err
	}
	rec, ok := f.recs[coord]
	return rec, ok, nil
}

// TestGenerateSBOM_NoNativeReaderAsksNothing. Nil is the default and it must
// leave the document exactly as it was: no reader, no native records, no change.
func TestGenerateSBOM_NoNativeReaderAsksNothing(t *testing.T) {
	gen := &fakeSBOMGenerator{}
	uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, &fakeSBOMStore{}, gen)

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if gen.capturedReq.NativeRecords != nil {
		t.Errorf("NativeRecords = %v, want nil when no reader is wired", gen.capturedReq.NativeRecords)
	}
}

// TestGenerateSBOM_PassesEveryRecordItFinds, keyed by coordinate, and asks about
// every node in the walk.
func TestGenerateSBOM_PassesEveryRecordItFinds(t *testing.T) {
	a := coordOf(t, "example.com/aaa", "v1.0.0")
	b := coordOf(t, "example.com/bbb", "v2.0.0")
	walk := makeMultiNodeWalk("walk-1", []coordinate.ModuleCoordinate{a, b})

	reader := &fakeNativeReader{recs: map[coordinate.ModuleCoordinate]nativedomain.Record{
		a: {Presence: nativedomain.PresenceIdentified, ArtefactIdentity: "zip:h1:aa="},
	}}
	gen := &fakeSBOMGenerator{}
	uc := makeUC(&fakeWalkStore{walk: walk}, &fakeSBOMStore{}, gen).WithNativeComponents(reader)

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(reader.asked) != 2 {
		t.Errorf("asked about %d module(s), want both nodes in the walk", len(reader.asked))
	}
	got := gen.capturedReq.NativeRecords
	if len(got) != 1 {
		t.Fatalf("NativeRecords holds %d entries, want 1", len(got))
	}
	if got[a].ArtefactIdentity != "zip:h1:aa=" {
		t.Errorf("the record reached the generator as %+v", got[a])
	}
	// A module with no record is ABSENT from the map, so the document states
	// nothing about it — which is "not examined", never "no native code".
	if _, present := got[b]; present {
		t.Error("a module with no record reached the generator with one")
	}
}

// TestGenerateSBOM_ANativeReadFailureFailsTheDocument. The store disagreeing
// with itself about which artefact a coordinate's facts describe is a
// contradiction in the evidence this document is assembled from, and a document
// that quietly drops the modules it could not read is indistinguishable from one
// where nothing was recorded.
func TestGenerateSBOM_ANativeReadFailureFailsTheDocument(t *testing.T) {
	a := coordOf(t, "example.com/aaa", "v1.0.0")
	b := coordOf(t, "example.com/bbb", "v2.0.0")
	walk := makeMultiNodeWalk("walk-1", []coordinate.ModuleCoordinate{a, b})

	boom := errors.New("conflicting embedded-native-component records")
	reader := &fakeNativeReader{failFor: b, err: boom}
	ss := &fakeSBOMStore{}
	uc := makeUC(&fakeWalkStore{walk: walk}, ss, &fakeSBOMGenerator{}).WithNativeComponents(reader)

	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err == nil {
		t.Fatal("Generate = nil error; a contradiction in the evidence must stop the document")
	}
	if !errors.Is(err, boom) {
		t.Errorf("errors.Is(err, boom) = false for %v", err)
	}
	if ss.stored != nil {
		t.Error("a document was persisted after a failed native read")
	}
}
