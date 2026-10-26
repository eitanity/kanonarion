package modulecache_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/modulecache"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
)

const goModUnreadableMsg = "callgraph: a requirement's stored go.mod could not be read, treating it as pre-pruning"

// A requirement whose recorded go.mod cannot be produced is still treated as
// pre-pruning, and that is stated at warn with the coordinate, the step and
// the error. A requirement with a readable go.mod, or none servable, is silent.
func TestMaterialise_ARequirementsUnreadableGoModIsStated(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(t *testing.T, facts *factStore, blobs *blobStore, key string)
		aside    bool
		wantStep string
		wantErr  string
	}{
		{
			name:     "go.mod hash does not parse",
			mutate:   malformGoModHash,
			wantStep: "deriving the go.mod address",
			wantErr:  `"h1:"`,
		},
		{
			name:     "go.mod does not parse",
			mutate:   garbleGoMod,
			wantStep: "parsing the go.mod",
			wantErr:  "go.mod",
		},
		{name: "control: readable go.mod"},
		{name: "control: nothing servable", aside: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts, blobs, f := newFixture(t)
			dep := coord(t, "example.com/dep", "v1.2.3")
			if !tc.aside {
				store(t, facts, blobs, dep, "", true)
			}
			if tc.mutate != nil {
				tc.mutate(t, facts, blobs, dep.String())
			}
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			var fs fetchports.FactStore = facts
			if tc.aside {
				fs = asideStore{facts}
			}
			c := modulecache.New(fs, blobs, logger)
			if !tc.aside {
				// Without a fetcher a set-aside requirement stays unservable, so
				// the go.mod read meets it rather than a fresh record.
				c = c.WithFetcher(f)
			}
			c.Materialise(context.Background(), t.TempDir(), pruned(dep))

			warns := jsonWarns(t, &buf, goModUnreadableMsg)
			if tc.wantStep == "" {
				if len(warns) != 0 {
					t.Fatalf("warn lines = %v, want none", warns)
				}
				return
			}
			assertOneStepWarn(t, warns, dep.String(), tc.wantStep, tc.wantErr)
		})
	}
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

// assertOneStepWarn checks there is exactly one warn line, naming coord and
// step, with an error containing wantErr.
func assertOneStepWarn(t *testing.T, warns []map[string]any, coord, wantStep, wantErr string) {
	t.Helper()
	if len(warns) != 1 {
		t.Fatalf("warn lines = %d, want 1: %v", len(warns), warns)
	}
	w := warns[0]
	if w["coordinate"] != coord || w["step"] != wantStep {
		t.Errorf("warn coordinate=%v step=%v, want %s and %q", w["coordinate"], w["step"], coord, wantStep)
	}
	if e := fmt.Sprint(w["error"]); !strings.Contains(e, wantErr) {
		t.Errorf("warn error = %q, want it to contain %q", e, wantErr)
	}
}

// malformGoModHash re-seals the record under key with a go.mod hash that does
// not parse.
func malformGoModHash(t *testing.T, facts *factStore, _ *blobStore, key string) {
	t.Helper()
	r := facts.records[key]
	r.GoModHash = "h1:"
	resealed, err := fetchdomain.CanonicalHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatal(err)
	}
	facts.records[key] = resealed
}

// garbleGoMod replaces the go.mod held for the record under key with bytes
// that do not parse.
func garbleGoMod(t *testing.T, facts *factStore, blobs *blobStore, key string) {
	t.Helper()
	id, _, err := fetchports.GoModIdentity(facts.records[key])
	if err != nil {
		t.Fatal(err)
	}
	blobs.blobs[id.String()] = []byte("module (\n")
}
