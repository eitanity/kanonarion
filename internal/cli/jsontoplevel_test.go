package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
)

// TestJSONTopLevelTypeIsFixed pins the top-level JSON type of the two commands
// whose type used to be decided by the answer rather than by the command.
//
// `context --json` over several modules printed one object per line, so the
// whole output parsed only if the caller knew to split it first. `latest --json`
// printed a bare object for one module and an array for two, so a consumer that
// iterated the answer walked an object's KEYS on the single-module form and
// produced plausible nonsense rather than an error.
//
// The rule both now follow: the top-level type is fixed by the form invoked and
// never by the number of records the answer holds. The type is asserted, not
// the content — a later change to either is then a decision somebody made here,
// not a regression nobody saw.
func TestJSONTopLevelTypeIsFixed(t *testing.T) {
	t.Run("context over several modules is one array", func(t *testing.T) {
		fx := newJSONStdoutFixture(t)
		var stdout, stderr bytes.Buffer
		if err := Run([]string{"context", "--walk-id", jsonDocWalkID, "--json",
			"--store-root", fx.storeRoot}, &stdout, &stderr); err != nil {
			t.Fatalf("context --walk-id --json: %v\nstderr:\n%s", err, stderr.String())
		}
		var docs []json.RawMessage
		if err := json.Unmarshal(stdout.Bytes(), &docs); err != nil {
			t.Fatalf("context --json is not one JSON array: %v\nstdout:\n%s", err, stdout.String())
		}
		// The walk holds two modules, so this is the count that used to change
		// the framing. One record here would assert nothing.
		if len(docs) != 2 {
			t.Fatalf("expected the walk's 2 modules in the array, got %d", len(docs))
		}
		for i, doc := range docs {
			var obj map[string]any
			if err := json.Unmarshal(doc, &obj); err != nil {
				t.Fatalf("array element %d is not an object: %v", i, err)
			}
			if _, ok := obj["module"]; !ok {
				t.Errorf("array element %d has no module key: the elements are the per-module documents", i)
			}
		}
	})

	t.Run("context for one named module is one object", func(t *testing.T) {
		fx := newJSONStdoutFixture(t)
		var stdout, stderr bytes.Buffer
		if err := Run([]string{"context", jsonDocDepCoord, "--json",
			"--store-root", fx.storeRoot}, &stdout, &stderr); err != nil {
			t.Fatalf("context <module> --json: %v\nstderr:\n%s", err, stderr.String())
		}
		// A coordinate names one module, so this form answers with that module's
		// document. It is not the multi-module form with one record in it, and
		// wrapping it would be a second breaking change to a shape nothing
		// measured as varying.
		var obj map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &obj); err != nil {
			t.Fatalf("context <module> --json is not one JSON object: %v\nstdout:\n%s", err, stdout.String())
		}
		if _, ok := obj["module"]; !ok {
			t.Error("the document has no module key")
		}
	})

	// latest is exercised at both counts because its type followed the count:
	// one module is where the object used to be emitted.
	for _, tc := range []struct {
		name    string
		modules []string
	}{
		{name: "latest for one module is an array", modules: []string{"github.com/spf13/cobra"}},
		{name: "latest for two modules is an array", modules: []string{"github.com/spf13/cobra", "github.com/stretchr/testify"}},
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
			if err := json.Unmarshal(stdout.Bytes(), &rows); err != nil {
				t.Fatalf("latest --json is not a JSON array: %v\nstdout:\n%s", err, stdout.String())
			}
			if len(rows) != len(tc.modules) {
				t.Fatalf("expected %d rows, got %d", len(tc.modules), len(rows))
			}
		})
	}
}
