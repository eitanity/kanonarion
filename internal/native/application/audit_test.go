package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/native/application"
	"github.com/eitanity/kanonarion/internal/native/domain"
)

// The defect this file pins: `native` wrote a record and appended nothing to the
// append-only log. Every sibling fact has an event; this one had none, so a
// store write that appended nothing let a stable line count read as "nothing
// ran" — and the SBOM's pkg:generic component and a scan's "advisories were NOT
// searched" statement both rest on a generation the ledger could not witness.

// sqliteFiles is a module that ships an amalgamated C library and compiles it
// through cgo, so the recorded measurement has a named component and native
// sources for the payload assertions to be about.
func sqliteFiles() map[string]string {
	return map[string]string{
		"sqlite3.go":        cgoWrapper,
		"sqlite3-binding.c": sqliteAmalgamation,
		"sqlite3-binding.h": sqliteAmalgamation,
		"LICENSE":           "MIT",
	}
}

func TestExecute_PersistedMeasurementIsWitnessedExactlyOnce(t *testing.T) {
	h := newHarness(t, "github.com/mattn/go-sqlite3", "v1.14.12", sqliteFiles())

	res := h.run(t, false)
	if res.FromCache {
		t.Fatal("the first run served from cache")
	}
	events := h.sink.typed(audit.EventNativeComponentsRecorded)
	if len(events) != 1 {
		t.Fatalf("a persisted measurement appended %d event(s), want exactly 1", len(events))
	}
	if h.native.puts != 1 {
		t.Fatalf("the store took %d write(s); the event must witness one write", h.native.puts)
	}
}

// A cache hit writes nothing, so it must append nothing. An event on a re-serve
// would report a write that did not happen, and the tripwire the log exists to
// be would then fire on a run that did nothing.
func TestExecute_CacheHitWitnessesNothing(t *testing.T) {
	h := newHarness(t, "github.com/mattn/go-sqlite3", "v1.14.12", sqliteFiles())

	h.run(t, false)
	before := len(h.sink.typed(audit.EventNativeComponentsRecorded))

	res := h.run(t, false)
	if !res.FromCache {
		t.Fatal("the second run re-measured instead of serving the held record")
	}
	after := h.sink.typed(audit.EventNativeComponentsRecorded)
	if len(after) != before {
		t.Fatalf("a cache hit appended %d event(s); the ledger witnesses writes, not re-serves",
			len(after)-before)
	}
}

// --force re-measures and writes, so it appends. The pair with the case above
// is the whole contract: the log's line count moves exactly when the store's
// contents do.
func TestExecute_ForcedReMeasureAppendsAgain(t *testing.T) {
	h := newHarness(t, "github.com/mattn/go-sqlite3", "v1.14.12", sqliteFiles())

	h.run(t, false)
	h.run(t, false) // cache hit, appends nothing
	h.run(t, true)  // forced, writes and appends

	if got := len(h.sink.typed(audit.EventNativeComponentsRecorded)); got != 2 {
		t.Fatalf("two writes and one cache hit appended %d event(s), want 2", got)
	}
}

// The payload witnesses the write and states no claim the record makes. A
// component name, a version, a file or a declaration here would make the log a
// second unsealed copy of the evidence.
func TestExecute_PayloadWitnessesTheWriteWithoutRestatingTheRecord(t *testing.T) {
	h := newHarness(t, "github.com/mattn/go-sqlite3", "v1.14.12", sqliteFiles())
	h.run(t, false)

	events := h.sink.typed(audit.EventNativeComponentsRecorded)
	if len(events) != 1 {
		t.Fatalf("appended %d event(s), want 1", len(events))
	}
	payload := events[0].Payload

	rec, held, err := h.native.GetNativeRecord(context.Background(), h.coord)
	if err != nil || !held {
		t.Fatalf("reading back the record: err=%v held=%t", err, held)
	}

	wantKeys := map[string]any{
		"module":                   h.coord.Path(),
		"version":                  h.coord.Version(),
		"artefact_identity":        rec.ArtefactIdentity,
		"pipeline_version":         domain.PipelineVersion,
		"recipe_catalogue_version": domain.RecipeCatalogueVersion,
		"presence":                 string(rec.Presence),
		"component_count":          len(rec.Components),
		"source_count":             len(rec.Sources),
		"linked_library_count":     len(rec.LinkedLibraries),
		"content_hash":             rec.ContentHash,
	}
	for k, want := range wantKeys {
		got, ok := payload[k]
		if !ok {
			t.Errorf("payload carries no %q", k)
			continue
		}
		if got != want {
			t.Errorf("payload[%q] = %v, want %v", k, got, want)
		}
	}
	if len(payload) != len(wantKeys) {
		t.Errorf("payload carries %d keys, want exactly %d: %v", len(payload), len(wantKeys), payload)
	}

	// The measurement found a component and native sources, so this is the case
	// where restating them would be possible — and must not happen.
	if len(rec.Components) == 0 || len(rec.Sources) == 0 {
		t.Fatal("the fixture recorded no component or source, so this assertion proves nothing")
	}
	for _, forbidden := range []string{"components", "sources", "linked_libraries", "evidence", "statement"} {
		if _, found := payload[forbidden]; found {
			t.Errorf("payload carries %q: the record holds the claims, the event witnesses the write", forbidden)
		}
	}
	// And no value anywhere in the payload names a component or a file.
	for k, v := range payload {
		if s, ok := v.(string); ok {
			for _, leak := range []string{"SQLite", "3.38.0", "sqlite3-binding.c", "#define"} {
				if s == leak {
					t.Errorf("payload[%q] restates the record's claim %q", k, leak)
				}
			}
		}
	}
}

// The counts are emitted at zero. A module measured and found to compile
// nothing is a measurement, and a reader must not have to tell an absent key
// from a zero.
func TestExecute_CountsAreWitnessedAtZero(t *testing.T) {
	h := newHarness(t, "example.com/puregp", "v1.0.0", map[string]string{
		"go.mod": "module example.com/puregp\n",
		"a.go":   pureGo,
	})
	h.run(t, false)

	events := h.sink.typed(audit.EventNativeComponentsRecorded)
	if len(events) != 1 {
		t.Fatalf("appended %d event(s), want 1", len(events))
	}
	payload := events[0].Payload
	if payload["presence"] != string(domain.PresenceAbsent) {
		t.Fatalf("presence = %v, want %q", payload["presence"], domain.PresenceAbsent)
	}
	for _, k := range []string{"component_count", "source_count", "linked_library_count"} {
		got, ok := payload[k]
		if !ok {
			t.Errorf("payload omits %q at zero; an absent key is not a measured zero", k)
			continue
		}
		if got != 0 {
			t.Errorf("payload[%q] = %v, want 0", k, got)
		}
	}
}

// The envelope must pass the vocabulary gate, or nothing could persist it.
func TestExecute_EmittedEventIsARecognisedType(t *testing.T) {
	h := newHarness(t, "github.com/mattn/go-sqlite3", "v1.14.12", sqliteFiles())
	h.run(t, false)

	events := h.sink.typed(audit.EventNativeComponentsRecorded)
	if len(events) != 1 {
		t.Fatalf("appended %d event(s), want 1", len(events))
	}
	if err := events[0].Validate(); err != nil {
		t.Fatalf("the emitted envelope does not validate: %v", err)
	}
	if !events[0].Type.Known() {
		t.Error("the emitted type is not in the recognised vocabulary")
	}
}

// A run wired with no sink still measures and still writes. The event is an
// assurance concern; a build without a log must not lose the record, and the
// nil check must not become a nil dereference.
func TestExecute_NilSinkStillWritesTheRecord(t *testing.T) {
	h := newHarnessWithoutSink(t, "github.com/mattn/go-sqlite3", "v1.14.12", sqliteFiles())

	res, err := h.uc.Execute(context.Background(),
		application.ExtractRequest{Coordinate: h.coord, Force: false})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.ContentHash == "" {
		t.Error("no record was produced")
	}
	if h.native.puts != 1 {
		t.Errorf("store writes = %d, want 1", h.native.puts)
	}
}

// A sink that refuses is reported, not swallowed. The write already happened, so
// a silent failure would leave the store holding a generation the log does not
// witness — which is the condition this event exists to remove.
func TestExecute_SinkFailureIsSurfaced(t *testing.T) {
	boom := errors.New("log is read-only")
	h := newHarness(t, "github.com/mattn/go-sqlite3", "v1.14.12", sqliteFiles())
	h.sink.err = boom

	_, err := h.uc.Execute(context.Background(),
		application.ExtractRequest{Coordinate: h.coord, Force: false})
	if !errors.Is(err, boom) {
		t.Fatalf("Execute error = %v, want it to carry %v", err, boom)
	}
}
