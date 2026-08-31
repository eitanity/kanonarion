package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
)

// TestJSONTopLevelTypeIsFixed pins the top-level JSON type of the commands whose
// type used to be decided by the answer rather than by the command.
//
// `context --json` over several modules printed one object per line, so the
// whole output parsed only if the caller knew to split it first; then an array,
// which still differed from the object a single coordinate produced. `latest
// --json` printed a bare object for one module and an array for two, so a
// consumer that iterated the answer walked an object's KEYS on the
// single-module form and produced plausible nonsense rather than an error.
//
// The rule they now follow: the top-level type is ONE OBJECT, fixed by the
// command — not by the form invoked, and not by the number of records the answer
// holds. The per-module documents are its `modules` array. The type is asserted,
// not the content — a later change to either is then a decision somebody made
// here, not a regression nobody saw.
func TestJSONTopLevelTypeIsFixed(t *testing.T) {
	// One store, every form of `context`, one assertion. The forms are exercised
	// together because the defect is a DIFFERENCE between them: each on its own
	// passes whatever shape it happens to have.
	t.Run("context is one object at every form", func(t *testing.T) {
		fx := newJSONStdoutFixture(t)
		chdirWithGoMod(t, "")

		for _, tc := range []struct {
			name string
			args []string
			// wantModules is the number of per-module documents the form answers
			// with, at the count that used to decide the framing.
			wantModules int
		}{
			{
				name:        "a walk holding two modules",
				args:        []string{"context", "--walk-id", jsonDocWalkID},
				wantModules: 2,
			},
			{
				name:        "a manifest whose scope resolves one",
				args:        []string{"context", "--gomod", fx.populatedGoMod()},
				wantModules: 1,
			},
			{
				name:        "one coordinate named on the command line",
				args:        []string{"context", jsonDocDepCoord},
				wantModules: 1,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				if err := Run(append(tc.args, "--json", "--store-root", fx.storeRoot),
					&stdout, &stderr); err != nil {
					t.Fatalf("%v: %v\nstderr:\n%s", tc.args, err, stderr.String())
				}
				_, docs := decodeEnvelope(t, "context --json", stdout.Bytes())
				if len(docs) != tc.wantModules {
					t.Fatalf("expected %d module document(s), got %d", tc.wantModules, len(docs))
				}
				for i, doc := range docs {
					var obj map[string]any
					if err := json.Unmarshal(doc, &obj); err != nil {
						t.Fatalf("modules[%d] is not an object: %v", i, err)
					}
					// The elements are the per-module documents, unchanged: the
					// envelope reframes the answer, it does not rewrite the rows.
					if _, ok := obj["module"]; !ok {
						t.Errorf("modules[%d] has no module key: the elements are the per-module documents", i)
					}
				}
			})
		}
	})

	// latest is exercised at both counts because its type followed the count:
	// one module is where the bare row object used to be emitted.
	for _, tc := range []struct {
		name    string
		modules []string
	}{
		{name: "latest for one module is one object", modules: []string{"github.com/spf13/cobra"}},
		{name: "latest for two modules is one object", modules: []string{"github.com/spf13/cobra", "github.com/stretchr/testify"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeLatestProxy(t, map[string]string{
				"github.com/spf13/cobra":      "v1.10.2",
				"github.com/stretchr/testify": "v1.10.0",
			})
			defer srv.Close()

			prev := jsonOut
			jsonOut = true
			t.Cleanup(func() { jsonOut = prev })

			var stdout bytes.Buffer
			if err := runLatestModules(context.Background(), tc.modules,
				latestResolverFor(t, srv), &stdout, io.Discard); err != nil {
				t.Fatalf("runLatestModules: %v", err)
			}
			var rows []map[string]any
			envelopeRows(t, "latest --json", stdout.Bytes(), &rows)
			if len(rows) != len(tc.modules) {
				t.Fatalf("expected %d rows, got %d", len(tc.modules), len(rows))
			}
		})
	}
}
