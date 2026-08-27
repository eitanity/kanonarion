package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/sqlitestore"
	stalesqlite "github.com/eitanity/kanonarion/internal/staleness/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/staleness/domain"
)

func newStore(t *testing.T) *stalesqlite.Store {
	t.Helper()
	db, err := sqlitestore.Open(":memory:", stalesqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})
	return stalesqlite.New(db)
}

func TestPutGet_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	want := domain.Record{
		ModulePath:        "github.com/minio/minio-go/v6",
		LatestVersion:     "v6.0.57",
		LatestPublishedAt: time.Date(2020, 12, 21, 10, 0, 0, 0, time.UTC),
		NewerMajor: domain.NewerMajor{
			Probed:      true,
			FromMajor:   7,
			Path:        "github.com/minio/minio-go/v7",
			Version:     "v7.2.1",
			PublishedAt: time.Date(2026, 1, 19, 8, 0, 0, 0, time.UTC),
		},
		LookedUpAt: time.Date(2026, 7, 31, 9, 14, 0, 0, time.UTC),
	}
	if err := s.PutStaleness(ctx, want); err != nil {
		t.Fatalf("PutStaleness: %v", err)
	}

	got, found, err := s.GetStaleness(ctx, want.ModulePath)
	if err != nil {
		t.Fatalf("GetStaleness: %v", err)
	}
	if !found {
		t.Fatal("expected the row to be found")
	}
	if got.LatestVersion != want.LatestVersion || !got.LatestPublishedAt.Equal(want.LatestPublishedAt) {
		t.Errorf("latest = %s/%v, want %s/%v", got.LatestVersion, got.LatestPublishedAt, want.LatestVersion, want.LatestPublishedAt)
	}
	if got.NewerMajor != want.NewerMajor {
		t.Errorf("NewerMajor = %+v, want %+v", got.NewerMajor, want.NewerMajor)
	}
	if !got.LookedUpAt.Equal(want.LookedUpAt) {
		t.Errorf("LookedUpAt = %v, want %v", got.LookedUpAt, want.LookedUpAt)
	}
}

func TestGet_MissIsNotAnError(t *testing.T) {
	_, found, err := newStore(t).GetStaleness(context.Background(), "example.com/never/stored")
	if err != nil {
		t.Fatalf("GetStaleness: %v", err)
	}
	if found {
		t.Error("expected no row")
	}
}

// "Probed, none found" and "not probed" must survive the round trip as
// different answers; collapsing them would let an unasked question read as a
// clean one.
func TestRoundTrip_DistinguishesUnprobedFromNegative(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Date(2026, 7, 31, 9, 0, 0, 0, time.UTC)

	negative := domain.Record{
		ModulePath:    "example.com/negative",
		LatestVersion: "v1.0.0",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    now,
	}
	unprobed := domain.Record{
		ModulePath:    "example.com/unprobed",
		LatestVersion: "v1.0.0",
		LookedUpAt:    now,
	}
	for _, rec := range []domain.Record{negative, unprobed} {
		if err := s.PutStaleness(ctx, rec); err != nil {
			t.Fatalf("PutStaleness(%s): %v", rec.ModulePath, err)
		}
	}

	got, _, err := s.GetStaleness(ctx, "example.com/negative")
	if err != nil {
		t.Fatalf("GetStaleness: %v", err)
	}
	if !got.NewerMajor.Probed || got.NewerMajor.FromMajor != 2 || got.NewerMajor.Path != "" {
		t.Errorf("negative round-tripped as %+v", got.NewerMajor)
	}

	got, _, err = s.GetStaleness(ctx, "example.com/unprobed")
	if err != nil {
		t.Fatalf("GetStaleness: %v", err)
	}
	if got.NewerMajor.Probed {
		t.Errorf("unprobed round-tripped as probed: %+v", got.NewerMajor)
	}
}

// A module whose publication date the proxy did not supply must not acquire a
// fabricated 0001-01-01 on the way through the store.
func TestRoundTrip_AbsentPublicationDateStaysAbsent(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if err := s.PutStaleness(ctx, domain.Record{
		ModulePath:    "example.com/nodate",
		LatestVersion: "v1.0.0",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    time.Date(2026, 7, 31, 9, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("PutStaleness: %v", err)
	}
	got, _, err := s.GetStaleness(ctx, "example.com/nodate")
	if err != nil {
		t.Fatalf("GetStaleness: %v", err)
	}
	if !got.LatestPublishedAt.IsZero() {
		t.Errorf("LatestPublishedAt = %v, want the zero time", got.LatestPublishedAt)
	}
}

func TestPut_OverwritesInPlace(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := domain.Record{
		ModulePath:    "example.com/mod",
		LatestVersion: "v1.0.0",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    time.Date(2026, 7, 31, 9, 0, 0, 0, time.UTC),
	}
	if err := s.PutStaleness(ctx, base); err != nil {
		t.Fatalf("PutStaleness: %v", err)
	}
	base.LatestVersion = "v1.1.0"
	base.LookedUpAt = base.LookedUpAt.Add(time.Hour)
	if err := s.PutStaleness(ctx, base); err != nil {
		t.Fatalf("PutStaleness (overwrite): %v", err)
	}
	got, found, err := s.GetStaleness(ctx, "example.com/mod")
	if err != nil || !found {
		t.Fatalf("GetStaleness: %v found=%v", err, found)
	}
	if got.LatestVersion != "v1.1.0" {
		t.Errorf("LatestVersion = %q, want the overwritten v1.1.0", got.LatestVersion)
	}
}

func TestPut_RefusesAnIncompleteRow(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Date(2026, 7, 31, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		rec  domain.Record
	}{
		{"no module path", domain.Record{LatestVersion: "v1.0.0", LookedUpAt: now}},
		{"no latest version", domain.Record{ModulePath: "example.com/mod", LookedUpAt: now}},
		{"no lookup time", domain.Record{ModulePath: "example.com/mod", LatestVersion: "v1.0.0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.PutStaleness(ctx, tc.rec); err == nil {
				t.Error("expected the incomplete row to be refused")
			}
		})
	}
}

// The republication is a separate fact in its own columns, and a row carrying
// both must return both. One set of columns could only hold one of them.
func TestRoundTrip_CarriesBothMajorFactsSeparately(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	want := domain.Record{
		ModulePath:    "github.com/go-chi/chi",
		LatestVersion: "v1.5.5",
		NewerMajor: domain.NewerMajor{
			Probed:      true,
			FromMajor:   4,
			Path:        "github.com/go-chi/chi/v5",
			Version:     "v5.3.1",
			PublishedAt: time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC),
		},
		Republication: domain.Republication{
			Asked:       true,
			Path:        "github.com/go-chi/chi/v3",
			Version:     "v3.3.5",
			PublishedAt: time.Date(2019, 4, 1, 0, 0, 0, 0, time.UTC),
		},
		LookedUpAt: time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC),
	}
	if err := s.PutStaleness(ctx, want); err != nil {
		t.Fatalf("PutStaleness: %v", err)
	}
	got, found, err := s.GetStaleness(ctx, want.ModulePath)
	if err != nil {
		t.Fatalf("GetStaleness: %v", err)
	}
	if !found {
		t.Fatal("expected the row to be found")
	}
	if got.NewerMajor != want.NewerMajor {
		t.Errorf("NewerMajor = %+v, want %+v", got.NewerMajor, want.NewerMajor)
	}
	if got.Republication != want.Republication {
		t.Errorf("Republication = %+v, want %+v", got.Republication, want.Republication)
	}
}

// "Asked, and this major is not republished" is a real answer and must survive
// the round trip distinct from "not asked". They are the pair major_probe_from
// draws for the walk, and collapsing them would report an unasked question as a
// negative.
func TestRoundTrip_DistinguishesUnaskedRepublicationFromNegative(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	cases := []struct {
		name string
		rep  domain.Republication
	}{
		{name: "not asked", rep: domain.Republication{}},
		{name: "asked, absent", rep: domain.Republication{Asked: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := domain.Record{
				ModulePath:    "example.com/mod-" + tc.name,
				LatestVersion: "v1.0.0",
				NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
				Republication: tc.rep,
				LookedUpAt:    time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC),
			}
			if err := s.PutStaleness(ctx, rec); err != nil {
				t.Fatalf("PutStaleness: %v", err)
			}
			got, _, err := s.GetStaleness(ctx, rec.ModulePath)
			if err != nil {
				t.Fatalf("GetStaleness: %v", err)
			}
			if got.Republication.Asked != tc.rep.Asked {
				t.Errorf("Republication.Asked = %v, want %v", got.Republication.Asked, tc.rep.Asked)
			}
			if got.Republication.Exists() {
				t.Errorf("Republication.Path = %q, want empty", got.Republication.Path)
			}
		})
	}
}

// Migration 2 moves a same-major answer written by the previous shape out of the
// newer_major_* columns, where it rendered as a major-number change that had not
// happened. The move is keyed on the walk's start: only the same-major question
// can have written the major BELOW it.
func TestMigration2_MovesASameMajorAnswerOutOfTheNewerMajorColumns(t *testing.T) {
	ctx := context.Background()

	// Open at version 1 only, write the rows the way that shape wrote them, then
	// apply version 2 over the top.
	v1 := stalesqlite.Migrations()[:1]
	db, err := sqlitestore.Open(":memory:", v1, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})

	const insert = `INSERT INTO staleness_records
        (module_path, latest_version, latest_published_at, major_probe_from,
         newer_major_path, newer_major_version, newer_major_published_at, looked_up_at)
        VALUES (?, ?, '', ?, ?, ?, '', '2026-08-15T09:00:00Z')`
	rows := []struct {
		path      string
		probeFrom int
		nmPath    string
		nmVersion string
	}{
		// Mislabelled: the walk started at 3, so /v2 is the pin's own major.
		{"github.com/gavv/httpexpect", 3, "github.com/gavv/httpexpect/v2", "v2.17.0"},
		// gopkg.in encodes the major with ".v", and the same reading applies.
		{"gopkg.in/thing", 3, "gopkg.in/thing.v2", "v2.4.0"},
		// Non-zero controls: genuine newer majors, at or above the walk's start.
		{"github.com/Masterminds/sprig", 3, "github.com/Masterminds/sprig/v3", "v3.3.0"},
		{"github.com/go-chi/chi", 4, "github.com/go-chi/chi/v5", "v5.3.1"},
		// A double-digit major must not be matched by the single-digit pattern.
		{"example.com/wide", 3, "example.com/wide/v12", "v12.0.0"},
	}
	for _, r := range rows {
		if _, err := db.DB().ExecContext(ctx, insert, r.path, "v1.0.0", r.probeFrom, r.nmPath, r.nmVersion); err != nil {
			t.Fatalf("seeding %s: %v", r.path, err)
		}
	}

	if err := sqlitestore.Apply(db, stalesqlite.Migrations()); err != nil {
		t.Fatalf("applying migration 2: %v", err)
	}
	s := stalesqlite.New(db)

	moved := []struct{ path, wantRepPath, wantRepVersion string }{
		{"github.com/gavv/httpexpect", "github.com/gavv/httpexpect/v2", "v2.17.0"},
		{"gopkg.in/thing", "gopkg.in/thing.v2", "v2.4.0"},
	}
	for _, m := range moved {
		got, found, gerr := s.GetStaleness(ctx, m.path)
		if gerr != nil || !found {
			t.Fatalf("GetStaleness(%s): %v found=%v", m.path, gerr, found)
		}
		if got.NewerMajor.Exists() {
			t.Errorf("%s: NewerMajor.Path = %q, want empty — the pin's own major is not a newer one", m.path, got.NewerMajor.Path)
		}
		if got.Republication.Path != m.wantRepPath || got.Republication.Version != m.wantRepVersion {
			t.Errorf("%s: Republication = %s@%s, want %s@%s", m.path,
				got.Republication.Path, got.Republication.Version, m.wantRepPath, m.wantRepVersion)
		}
		if !got.Republication.Asked {
			t.Errorf("%s: the moved answer proves the question was asked", m.path)
		}
	}

	kept := []struct{ path, wantNMPath string }{
		{"github.com/Masterminds/sprig", "github.com/Masterminds/sprig/v3"},
		{"github.com/go-chi/chi", "github.com/go-chi/chi/v5"},
		{"example.com/wide", "example.com/wide/v12"},
	}
	for _, k := range kept {
		got, found, gerr := s.GetStaleness(ctx, k.path)
		if gerr != nil || !found {
			t.Fatalf("GetStaleness(%s): %v found=%v", k.path, gerr, found)
		}
		if got.NewerMajor.Path != k.wantNMPath {
			t.Errorf("%s: NewerMajor.Path = %q, want %q — a genuine newer major is untouched", k.path, got.NewerMajor.Path, k.wantNMPath)
		}
		if got.Republication.Asked {
			t.Errorf("%s: nothing was moved, so the question stays unasked rather than answered no", k.path)
		}
	}
}

// The deprecation notice is three states in the ledger and the row must keep
// them apart: never asked, asked and none declared, and the notice itself. An
// empty notice alone cannot say which of the first two a row is in, which is
// exactly the absence-as-answer this ledger exists to prevent.
func TestRoundTrip_DistinguishesUncheckedDeprecationFromNoNotice(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	const notice = "aws-sdk-go is deprecated. Use aws-sdk-go-v2.\nSee https://example.com/eol."
	cases := []struct {
		name string
		dep  domain.Deprecation
	}{
		{name: "not established", dep: domain.Deprecation{}},
		{name: "checked, none declared", dep: domain.Deprecation{Checked: true}},
		{name: "checked, deprecated", dep: domain.Deprecation{Checked: true, Notice: notice}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := domain.Record{
				ModulePath:    "example.com/mod-" + tc.name,
				LatestVersion: "v1.0.0",
				Deprecation:   tc.dep,
				LookedUpAt:    time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC),
			}
			if err := s.PutStaleness(ctx, rec); err != nil {
				t.Fatalf("PutStaleness: %v", err)
			}
			got, _, err := s.GetStaleness(ctx, rec.ModulePath)
			if err != nil {
				t.Fatalf("GetStaleness: %v", err)
			}
			if got.Deprecation.Checked != tc.dep.Checked {
				t.Errorf("Deprecation.Checked = %v, want %v", got.Deprecation.Checked, tc.dep.Checked)
			}
			// The notice is stored verbatim, newline and all: it is reproduced,
			// not interpreted, and the store is not where that starts changing.
			if got.Deprecation.Notice != tc.dep.Notice {
				t.Errorf("Deprecation.Notice = %q, want %q", got.Deprecation.Notice, tc.dep.Notice)
			}
			if got.Deprecation.Deprecated() != tc.dep.Deprecated() {
				t.Errorf("Deprecated() = %v, want %v", got.Deprecation.Deprecated(), tc.dep.Deprecated())
			}
		})
	}
}

// Migration 3 adds the deprecation columns. Existing rows keep
// deprecation_checked = 0 — "not established", which is the truth about a row
// written before anything asked — and they never read back as "not deprecated".
func TestMigration3_ExistingRowsAreUncheckedNotUndeprecated(t *testing.T) {
	ctx := context.Background()

	all := stalesqlite.Migrations()
	if len(all) < 3 {
		t.Fatalf("expected at least 3 staleness migrations, got %d", len(all))
	}
	db, err := sqlitestore.Open(":memory:", all[:2], sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})
	if _, err := db.DB().ExecContext(ctx,
		`INSERT INTO staleness_records (module_path, latest_version, looked_up_at) VALUES (?, ?, ?)`,
		"example.com/legacy", "v1.0.0", "2026-08-17T09:00:00Z"); err != nil {
		t.Fatalf("seeding the pre-migration row: %v", err)
	}
	if err := sqlitestore.Apply(db, all); err != nil {
		t.Fatalf("applying migration 3: %v", err)
	}

	got, found, err := stalesqlite.New(db).GetStaleness(ctx, "example.com/legacy")
	if err != nil || !found {
		t.Fatalf("GetStaleness: found=%v err=%v", found, err)
	}
	if got.Deprecation.Checked {
		t.Error("a row written before the question existed reads as having been asked")
	}
	if got.Deprecation.Deprecated() {
		t.Error("a row nothing asked about reads as deprecated")
	}
}
