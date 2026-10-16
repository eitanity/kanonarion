package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/example/adapters/parser/goast"
	"github.com/eitanity/kanonarion/internal/example/application"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

const goModUnreadableMsg = "examples: the module's stored go.mod could not be read, treating it as having no go directive"

// A cached record's go directive is read from the stored go.mod. One the run
// cannot produce is answered as no directive, as before, and stated at warn
// with the coordinate, the step and the error. A record with no go.mod hash
// gets the same answer silently.
func TestExecute_AnUnreadableStoredGoModIsStated(t *testing.T) {
	cases := []struct {
		name      string
		goModHash string
		wantStep  string
		wantErr   string
	}{
		// The control runs first: its answer is the one every case must keep.
		{name: "control: no go.mod hash recorded", goModHash: domain.ZeroString},
		{name: "go.mod hash does not parse", goModHash: "h1:", wantStep: "deriving the go.mod address", wantErr: `"h1:"`},
		{name: "go.mod blob not held", goModHash: "h1:gomod=", wantStep: "opening the go.mod blob", wantErr: "not found"},
	}
	var servedWithoutGoMod bool
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			coord := mustCoord(t, "example.com/genmeth", "v1.0.0")
			facts, blobs, store := seedHeldFailureWithGoModHash(t, coord, tc.goModHash)

			var buf bytes.Buffer
			uc := application.NewExtractExampleUseCase(application.Config{
				Facts: facts, Blobs: blobs, Examples: store, Parser: goast.New(),
				Clock:     fakeClock{t: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)},
				Stopwatch: fakeStopwatch{},
				Logger:    slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
			})
			res, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: coord})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}

			warns := jsonWarns(t, &buf, goModUnreadableMsg)
			if tc.wantStep == "" {
				if len(warns) != 0 {
					t.Errorf("warn lines = %v, want none for a record with no go.mod hash", warns)
				}
				servedWithoutGoMod = res.FromCache
				return
			}
			// The answer is unchanged: no directive, as for a record with none.
			if res.FromCache != servedWithoutGoMod {
				t.Errorf("FromCache = %v, want %v as for a record with no go.mod", res.FromCache, servedWithoutGoMod)
			}
			if len(warns) != 1 {
				t.Fatalf("warn lines = %d, want 1; logs:\n%s", len(warns), buf.String())
			}
			if w := warns[0]; w["coordinate"] != coord.String() || w["step"] != tc.wantStep || !strings.Contains(fmt.Sprint(w["error"]), tc.wantErr) {
				t.Errorf("warn coordinate=%v step=%v error=%v, want %s, %q and an error containing %q",
					w["coordinate"], w["step"], w["error"], coord, tc.wantStep, tc.wantErr)
			}
		})
	}
}

// seedHeldFailureWithGoModHash stores coord's fact record with goModHash and
// its zip, and an example record holding a parse failure, so a run consults
// the go directive.
func seedHeldFailureWithGoModHash(t *testing.T, coord coordinate.ModuleCoordinate, goModHash string) (*fakeFactStore, *fakeBlobStore, *fakeExampleStore) {
	t.Helper()
	ctx := context.Background()
	facts, blobs, store := &fakeFactStore{}, &fakeBlobStore{}, &fakeExampleStore{}
	r := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion(application.PipelineVersion),
		fetchtest.Content("zip"),
		fetchtest.Status(domain.Verified),
		func(r *domain.FactRecord) { r.GoModHash = goModHash },
	)
	zip := buildModuleZip(t, coord, map[string]string{"go.mod": goModOf("1.27.2"), "example_test.go": probeTest})
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, r), bytes.NewReader(zip)); err != nil {
		t.Fatal(err)
	}
	sealed, err := domain.Rehydrate(r)
	if err != nil {
		t.Fatal(err)
	}
	if perr := facts.PutFetchRecord(ctx, sealed); perr != nil {
		t.Fatal(perr)
	}
	if perr := store.PutExampleRecord(ctx, heldRecord(t, coord, oldWriterFailure, nil)); perr != nil {
		t.Fatal(perr)
	}
	return facts, blobs, store
}

// jsonWarns returns the JSON log lines in buf at WARN whose message is msg.
func jsonWarns(t *testing.T, buf *bytes.Buffer, msg string) []map[string]any {
	t.Helper()
	var warns []map[string]any
	for raw := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var l map[string]any
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Fatalf("log line %q: %v", raw, err)
		}
		if l["level"] == "WARN" && l["msg"] == msg {
			warns = append(warns, l)
		}
	}
	return warns
}
