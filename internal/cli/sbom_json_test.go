package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"

	sbomsqlite "github.com/eitanity/kanonarion/internal/sbom/adapters/store/sqlite"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
)

// sbomJSONFixture is a store holding two SBOM records that differ in the one
// field a caller has to be able to read per record: whether the document's
// licences are complete. One record is enough to show a field is emitted; two
// that disagree are what shows the value follows the record rather than a
// constant.
type sbomJSONFixture struct {
	storeRoot string
	// incomplete and complete are the ids of the two records, named by what
	// their LicensesIncomplete says.
	incomplete string
	complete   string
	// docs holds each record's stored document bytes, keyed by id, so a test can
	// assert what the command printed IS the record rather than merely parses.
	docs map[string][]byte
}

func newSBOMJSONFixture(t *testing.T) sbomJSONFixture {
	t.Helper()
	fx := sbomJSONFixture{
		storeRoot:  t.TempDir(),
		incomplete: "sbom-0000000000000000000000i1",
		complete:   "sbom-0000000000000000000000c1",
		docs:       map[string][]byte{},
	}

	db, err := sqlitestore.Open(filepath.Join(fx.storeRoot, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the fixture store: %v", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("closing the fixture store: %v", cerr)
		}
	}()
	if err := sqlitestore.Apply(db, allMigrations()); err != nil {
		t.Fatalf("migrating the fixture store: %v", err)
	}

	at := time.Date(2026, 1, 31, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()
	store := sbomsqlite.New(db)
	for _, r := range []sbomdomain.SBOMRecord{
		{
			ID:        fx.incomplete,
			Ecosystem: sbomdomain.EcosystemGo,
			WalkID:    "01JS0NGARD0000000000000WK1",
			Format:    sbomdomain.CycloneDX16,
			// A document, not a stub: the point of the command is that these
			// bytes reach stdout unaltered on both invocations.
			Content:            []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":"example.com/dep","version":"v1.0.0"}]}`),
			ContentHash:        "sha256:incomplete",
			GeneratedAt:        at,
			PipelineVersion:    "0.9.0",
			Operator:           "release-bot",
			LicensesIncomplete: true,
		},
		{
			ID:                 fx.complete,
			Ecosystem:          sbomdomain.EcosystemGo,
			WalkID:             "01JS0NGARD0000000000000WK2",
			Format:             sbomdomain.CycloneDX16,
			Content:            []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`),
			ContentHash:        "sha256:complete",
			GeneratedAt:        at.Add(time.Hour),
			PipelineVersion:    "0.9.0",
			Operator:           "",
			LicensesIncomplete: false,
		},
	} {
		if err := store.PutSBOMRecord(ctx, r); err != nil {
			t.Fatalf("seeding SBOM record %s: %v", r.ID, err)
		}
		fx.docs[r.ID] = r.Content
	}
	return fx
}

// TestSBOMShowJSONIsANoOp pins the decision that --json changes nothing here.
//
// It guards a real regression, not a hypothetical one: the flag used to replace
// the CycloneDX document with a 345-byte metadata descriptor of it, so the one
// flag documented as "machine-readable output" returned strictly LESS
// machine-readable content than omitting it, and said nothing about the
// document it had withheld. An agent told to always pass --json asked for an
// SBOM and got a descriptor.
//
// Byte-identity is asserted rather than "both parse as JSON": a second
// rendering that happened to be valid JSON is exactly what this forbids.
func TestSBOMShowJSONIsANoOp(t *testing.T) {
	fx := newSBOMJSONFixture(t)

	for _, id := range []string{fx.incomplete, fx.complete} {
		t.Run(id, func(t *testing.T) {
			var plain, plainErr bytes.Buffer
			if err := Run([]string{"sbom-show", id, "--store-root", fx.storeRoot}, &plain, &plainErr); err != nil {
				t.Fatalf("sbom-show: %v\nstderr:\n%s", err, plainErr.String())
			}
			var withJSON, jsonErr bytes.Buffer
			if err := Run([]string{"sbom-show", id, "--json", "--store-root", fx.storeRoot}, &withJSON, &jsonErr); err != nil {
				t.Fatalf("sbom-show --json: %v\nstderr:\n%s", err, jsonErr.String())
			}

			if !bytes.Equal(plain.Bytes(), withJSON.Bytes()) {
				t.Fatalf("--json changed the output: %d bytes without it, %d bytes with it.\n"+
					"without:\n%s\nwith:\n%s",
					plain.Len(), withJSON.Len(), plain.String(), withJSON.String())
			}
			if !bytes.Equal(plain.Bytes(), fx.docs[id]) {
				t.Errorf("stdout is not the stored document:\ngot:\n%s\nwant:\n%s", plain.String(), fx.docs[id])
			}
		})
	}
}

// TestSBOMListJSONCarriesOperatorAndLicenceCompleteness asserts the two record
// fields that no other listing serves.
//
// They are here because sbom-show's metadata rendering is gone, and a fact that
// could only be read one record at a time was the defect that rendering existed
// to work around. licenses_incomplete is the condition behind the non-zero exit
// an SBOM with undetermined licences carries, so a caller that cannot read it
// across records cannot tell a complete stored artefact from an incomplete one
// without opening every document.
//
// Both values are asserted at both records, and the records disagree: a field
// wired to a constant, or dropped at its zero value, fails here.
func TestSBOMListJSONCarriesOperatorAndLicenceCompleteness(t *testing.T) {
	fx := newSBOMJSONFixture(t)

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"sbom-list", "--json", "--store-root", fx.storeRoot}, &stdout, &stderr); err != nil {
		t.Fatalf("sbom-list --json: %v\nstderr:\n%s", err, stderr.String())
	}

	var rows []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &rows); err != nil {
		t.Fatalf("sbom-list --json is not an array of objects: %v\nstdout:\n%s", err, stdout.String())
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d:\n%s", len(rows), stdout.String())
	}

	byID := make(map[string]map[string]any, len(rows))
	for _, r := range rows {
		id, _ := r["id"].(string)
		byID[id] = r
	}

	for _, want := range []struct {
		id                 string
		operator           string
		licensesIncomplete bool
	}{
		{fx.incomplete, "release-bot", true},
		{fx.complete, "", false},
	} {
		row, ok := byID[want.id]
		if !ok {
			t.Fatalf("no row for %s:\n%s", want.id, stdout.String())
		}
		op, ok := row["operator"]
		if !ok {
			t.Errorf("%s: no operator key — a row that omits it at the empty string reads as "+
				"'not recorded' rather than as 'no operator'", want.id)
		} else if op != want.operator {
			t.Errorf("%s: operator = %v, want %q", want.id, op, want.operator)
		}
		inc, ok := row["licenses_incomplete"]
		if !ok {
			t.Errorf("%s: no licenses_incomplete key — the condition behind the undetermined-licence "+
				"exit is then readable only one record at a time", want.id)
		} else if inc != want.licensesIncomplete {
			t.Errorf("%s: licenses_incomplete = %v, want %v", want.id, inc, want.licensesIncomplete)
		}
	}
}

// TestSBOMListTextIsUnchangedByTheNewFields keeps the new facts to the JSON
// path. The text listing is a fixed-width line per record that operators read
// and scripts have been written against; adding a column there would be a
// second change riding on this one.
func TestSBOMListTextIsUnchangedByTheNewFields(t *testing.T) {
	fx := newSBOMJSONFixture(t)

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"sbom-list", "--store-root", fx.storeRoot}, &stdout, &stderr); err != nil {
		t.Fatalf("sbom-list: %v\nstderr:\n%s", err, stderr.String())
	}
	const want = "sbom-0000000000000000000000c1  walk=01JS0NGARD0000000000000WK2  format=cyclonedx-1.6   2026-01-31T10:00:00Z\n" +
		"sbom-0000000000000000000000i1  walk=01JS0NGARD0000000000000WK1  format=cyclonedx-1.6   2026-01-31T09:00:00Z\n"
	if stdout.String() != want {
		t.Errorf("sbom-list text changed:\ngot:\n%s\nwant:\n%s", stdout.String(), want)
	}
}
