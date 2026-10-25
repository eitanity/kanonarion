// Package sqlite is the SQLite and local-filesystem storage backend: mirror.db
// for every record store, a content-addressed blob directory, and audit.jsonl,
// all under one store root.
package sqlite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	noopsigner "github.com/eitanity/kanonarion/internal/adapters/signer/noop"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/composition/storage"
	dirsqlite "github.com/eitanity/kanonarion/internal/directive/adapters/store/sqlite"
	exsqlite "github.com/eitanity/kanonarion/internal/example/adapters/store/sqlite"
	extstore "github.com/eitanity/kanonarion/internal/extract/adapters/store/sqlite"
	fipssqlite "github.com/eitanity/kanonarion/internal/fips/adapters/store/sqlite"
	gdsqlite "github.com/eitanity/kanonarion/internal/godebug/adapters/store/sqlite"
	ifacesqlite "github.com/eitanity/kanonarion/internal/iface/adapters/store/sqlite"
	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	nativesqlite "github.com/eitanity/kanonarion/internal/native/adapters/store/sqlite"
	sbomstore "github.com/eitanity/kanonarion/internal/sbom/adapters/store/sqlite"
	stalesqlite "github.com/eitanity/kanonarion/internal/staleness/adapters/store/sqlite"
	stdlibsqlite "github.com/eitanity/kanonarion/internal/stdlib/adapters/store/sqlite"
	tinygosqlite "github.com/eitanity/kanonarion/internal/tinygo/adapters/store/sqlite"
	vensqlite "github.com/eitanity/kanonarion/internal/vendortree/adapters/store/sqlite"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
)

// Migrations returns every migration the binary knows about, in apply order.
// Its length is the binary's expected schema version, so the CLI and the public
// façade open mirror.db against an identical schema.
func Migrations() []sqlitestore.Migration {
	var m []sqlitestore.Migration
	m = append(m, fetchsqlite.Migrations()...)
	m = append(m, walksqlite.Migrations()...)
	m = append(m, extstore.Migrations()...)
	m = append(m, licsqlite.Migrations()...)
	m = append(m, ifacesqlite.Migrations()...)
	m = append(m, cgsqlite.Migrations()...)
	m = append(m, exsqlite.Migrations()...)
	m = append(m, sbomstore.Migrations()...)
	m = append(m, vulnsqlite.Migrations()...)
	m = append(m, dirsqlite.Migrations()...)
	m = append(m, gdsqlite.Migrations()...)
	m = append(m, vensqlite.Migrations()...)
	m = append(m, fipssqlite.Migrations()...)
	m = append(m, stdlibsqlite.Migrations()...)
	m = append(m, stalesqlite.Migrations()...)
	m = append(m, nativesqlite.Migrations()...)
	m = append(m, tinygosqlite.Migrations()...)
	return m
}

// DatabasePath is the database file of the store under root.
func DatabasePath(root string) string { return filepath.Join(root, "mirror.db") }

// BlobsDir is the directory the store under root keeps artefact bytes in.
func BlobsDir(root string) string { return filepath.Join(root, "blobs") }

// LedgerPath is the append-only assurance log of the store under root; the
// log's own reader names it, so the writer and the reader cannot disagree.
func LedgerPath(root string) string { return fetchsqlite.AuditLogPath(root) }

// Exists reports whether a store has been initialised under root. Only an
// absent database reads as false; any other stat failure is left for the open
// to report.
func Exists(root string) bool {
	_, err := os.Stat(DatabasePath(root))
	return !os.IsNotExist(err)
}

// Name is the storage.backend value that selects this backend.
const Name = "sqlite"

// Settings is the sqlite section of config.yaml. It has no keys: every path
// the backend uses derives from the store root.
type Settings struct{}

// ConfigComment is the explanation `config init` writes under the section.
func (Settings) ConfigComment() string {
	return "The SQLite backend keeps mirror.db, blobs/ and audit.jsonl under the\n" +
		"store root. Its paths derive from the store root; it has no settings."
}

// Backend is the SQLite backend as a registered value.
func Backend() storage.Backend {
	return storage.Backend{
		Name:     Name,
		Section:  Name,
		Defaults: Settings{},
		Open: func(_ context.Context, req storage.Request) (*storage.Storage, error) {
			if err := parseSettings(req.Section); err != nil {
				return nil, err
			}
			return Open(req)
		},
	}
}

// parseSettings refuses a sqlite section that sets anything, so a key meant
// for another backend is not silently ignored.
func parseSettings(section []byte) error {
	if len(section) == 0 {
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(section))
	dec.KnownFields(true)
	var s Settings
	if err := dec.Decode(&s); err != nil {
		return fmt.Errorf("config.yaml section %s: %w", Name, err)
	}
	return nil
}

// Open opens the store under req.StoreRoot and returns every store over it.
//
// The database is opened without migrations, judged, then migrated, because
// schema_migrations is keyed on (module, version): a store from a newer build
// reads as fully applied, so its unknown rows are the only signal. A write
// intent applies nothing to such a store and Writable refuses it; a read
// intent still opens it, so an operator can diagnose the refusal.
//
// IntentInspect applies no migration, creates no ledger and runs no
// maintenance, so the schema state it reports is the store as found; it
// refuses a root with no database.
func Open(req storage.Request) (*storage.Storage, error) {
	if req.Intent == storage.IntentInspect {
		if !Exists(req.StoreRoot) {
			return nil, &storage.NotFoundError{Location: DatabasePath(req.StoreRoot)}
		}
		return open(req, true)
	}
	return open(req, false)
}

func open(req storage.Request, inspect bool) (*storage.Storage, error) {
	db, maintain, needLedger, err := openDatabase(req, inspect)
	if err != nil {
		return nil, err
	}
	facts := fetchsqlite.New(db)
	facts.ReportSetAside(req.SetAside)
	auditing := fetchsqlite.NewAuditingStore(facts, LedgerPath(req.StoreRoot))
	blobs := localfs.New(req.StoreRoot).WithAudit(auditing, req.Command).WithRefusalObserver(req.OnBlobRefused)
	if maintain {
		if err := maintainStore(db, auditing, blobs, req, needLedger); err != nil {
			return nil, errors.Join(err, db.Close())
		}
	}

	walks, licences, callGraphs := walksqlite.New(db), licsqlite.New(db), cgsqlite.New(db)
	examples, extractions, stdlib := exsqlite.New(db), extstore.New(db), stdlibsqlite.New(db)
	walks.ReportSetAside(req.SetAside)
	licences.ReportSetAside(req.SetAside)
	callGraphs.ReportSetAside(req.SetAside)
	examples.ReportSetAside(req.SetAside)
	extractions.ReportSetAside(req.SetAside)
	stdlib.ReportSetAside(req.SetAside)
	// Records derived from a directory read under a published coordinate, before
	// local code had its own identity, are left out of that coordinate's reads.
	superseded := facts.SupersededLocalArtefacts
	licences.WithSupersededArtefacts(superseded)
	callGraphs.WithSupersededArtefacts(superseded)
	examples.WithSupersededArtefacts(superseded)

	schema := schemaReporter{db: db, location: DatabasePath(req.StoreRoot)}
	return &storage.Storage{
		Facts:             auditing,
		Attestations:      auditing,
		Audit:             auditing,
		Blobs:             blobs,
		Walks:             walks,
		WalkPresence:      walks,
		Licenses:          licences,
		Interfaces:        ifacesqlite.New(db).WithSupersededArtefacts(superseded),
		CallGraphs:        callGraphs,
		CallGraphOutcomes: callGraphs,
		Examples:          examples,
		Extractions:       extractions,
		Vulnerabilities:   vulnsqlite.New(db),
		SBOMs:             sbomstore.New(db),
		Directives:        dirsqlite.New(db),
		GoDebug:           gdsqlite.New(db),
		Vendor:            vensqlite.New(db),
		FIPS:              fipssqlite.New(db),
		Stdlib:            stdlib,
		Staleness:         stalesqlite.New(db),
		Native:            nativesqlite.New(db).WithSupersededArtefacts(superseded),
		TinyGoReleases:    tinygosqlite.New(db),
		ConfigHashes:      fetchsqlite.NewConfigHashMarker(req.StoreRoot),
		Signer:            noopsigner.New(),
		Schema:            schema,
		Writable: func(ctx context.Context) error {
			st, err := schema.SchemaState(ctx)
			if err != nil {
				return err
			}
			if len(st.Unknown) > 0 {
				return fmt.Errorf(
					"%w: %s carries %d migration(s) this build does not know (%s); upgrade kanonarion",
					storage.ErrStoreSchemaNewer, st.Location, len(st.Unknown), strings.Join(st.Unknown, ", "),
				)
			}
			return nil
		},
		Close: func() error { return closeError(db.Close()) },
	}, nil
}

// openDatabase opens and, unless inspecting, migrates mirror.db. maintain
// says whether this open may write maintenance; needLedger, whether the store
// was created by it or opened to write.
func openDatabase(req storage.Request, inspect bool) (db sqlitestore.DB, maintain, needLedger bool, err error) {
	intent := sqlitestore.IntentRead
	if req.Intent == storage.IntentCreate && !inspect {
		intent = sqlitestore.IntentCreate
		if merr := os.MkdirAll(req.StoreRoot, 0o750); merr != nil {
			return nil, false, false, fmt.Errorf("creating store root %s: %w", req.StoreRoot, merr)
		}
	}
	dbPath := DatabasePath(req.StoreRoot)
	_, statErr := os.Stat(dbPath)
	storeCreated := os.IsNotExist(statErr)
	db, err = sqlitestore.Open(dbPath, nil, intent)
	if err != nil {
		return nil, false, false, fmt.Errorf("opening database: %w", err)
	}
	state, err := sqlitestore.ReadMigrationState(db, Migrations())
	if err != nil {
		return nil, false, false, errors.Join(err, db.Close())
	}
	// Maintenance, migration and the ledger all write, so none of them runs for
	// an inspection or on a store this build refuses to write.
	maintain = !inspect && len(state.Unknown) == 0
	if !inspect && (intent == sqlitestore.IntentRead || maintain) {
		if aerr := sqlitestore.Apply(db, Migrations()); aerr != nil {
			return nil, false, false, errors.Join(fmt.Errorf("opening database: %w", aerr), db.Close())
		}
	}
	return db, maintain, storeCreated || intent == sqlitestore.IntentCreate, nil
}

// maintainStore gives a store this open created, or one opened to write, its
// ledger, so "a store that exists has a ledger" holds. The blob maintenance
// runs at every such open whatever the intent, as the CLI container did;
// adoption is a no-op once its marker exists.
func maintainStore(db sqlitestore.DB, auditing *fetchsqlite.AuditingStore, blobs *localfs.Store, req storage.Request, needLedger bool) error {
	if needLedger {
		if err := auditing.EnsureAuditLog(); err != nil {
			return fmt.Errorf("creating audit log: %w", err)
		}
	}
	logger := req.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	cleanOrphanedBlobTemps(blobs, logger)
	if err := adoptLegacyBlobs(db, blobs, req.StoreRoot, logger); err != nil {
		logger.Warn("could not re-address existing blobs by artefact identity", "error", err)
	}
	return nil
}

// closeError names a failed close; it is split out because no test can make
// SQLite's own close fail.
func closeError(err error) error {
	if err != nil {
		return fmt.Errorf("closing database: %w", err)
	}
	return nil
}

// schemaReporter reads schema_migrations on every call, so a refusal or a
// report describes the store as it is now rather than as it was at open.
type schemaReporter struct {
	db       sqlitestore.DB
	location string
}

func (r schemaReporter) SchemaState(context.Context) (storage.SchemaState, error) {
	known := Migrations()
	st, err := sqlitestore.ReadMigrationState(r.db, known)
	if err != nil {
		return storage.SchemaState{}, fmt.Errorf("reading schema state: %w", err)
	}
	return storage.SchemaState{Applied: st.Applied, Expected: len(known), Unknown: st.Unknown, Location: r.location}, nil
}
