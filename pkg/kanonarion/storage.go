package kanonarion

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/composition/storage"
)

// Storage is everything kanonarion persists through, supplied as one value:
// every record store, the blob store, the audit sink, the attestation store and
// the signer. A consumer builds one against the ports in this package and hands
// it to OpenFrom or OpenDriverFrom; Validate names every required field left
// nil. Signer, Schema, Writable and Close are optional: a nil Signer is the
// no-op signer, a nil Writable is always writable, a nil Close closes nothing.
//
// Stability: storage value (filled by consumers); unstable pre-v1. It is a
// struct that may gain fields within a major version, so a consumer sets
// fields by name, never positionally (§4).
type Storage = storage.Storage

// StorageRequest is what a storage backend is asked to open: the store root,
// whether it may create the store, where set-aside records are reported, and
// the backend's logger.
//
// Stability: request struct (passed to backends); unstable pre-v1. Fields may
// be added within a major version (§4).
type StorageRequest = storage.Request

// StorageIntent says whether a backend may bring a store into existence.
//
// Stability: request enumeration (passed to backends); unstable pre-v1. Values
// may be added within a major version (§4).
type StorageIntent = storage.Intent

// StorageIntentRead never creates anything: an absent store is refused.
// StorageIntentCreate may create the store, for a caller about to write.
//
// Stability: request-enumeration constants; unstable pre-v1 (§4).
const (
	StorageIntentRead   = storage.IntentRead
	StorageIntentCreate = storage.IntentCreate
)

// SchemaState is what a backend's schema bookkeeping reports: applied and
// expected migration counts and the applied migrations this build does not
// know.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version (§4).
type SchemaState = storage.SchemaState

// SchemaReporter is the optional capability a backend offers when it keeps a
// schema version; Storage.Schema holds it.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type SchemaReporter = storage.SchemaReporter

// ErrStoreSchemaNewer matches the refusal to write a store whose schema was
// written by a newer kanonarion. A backend's Storage.Writable wraps it.
//
// Stability: error sentinel (matched by consumers); unstable pre-v1 (§4).
var ErrStoreSchemaNewer = storage.ErrStoreSchemaNewer

// OpenFrom builds the read-consumption surface over a Storage value instead of
// the SQLite store Open opens. It takes ownership of st: the returned cleanup
// calls st.Close, and a refusal calls it before returning. It takes no
// options: the set-aside reporter travels in the backend's StorageRequest.
//
// Stability: public composition entrypoint; unstable pre-v1 (§4).
func OpenFrom(st *Storage) (*Queries, func() error, error) {
	queries, cleanup, err := composition.NewQueriesFrom(st)
	if err != nil {
		return nil, nil, fmt.Errorf("opening kanonarion store: %w", err)
	}
	return queries, cleanup, nil
}

// OpenDriverFrom builds the write/serving surface over a Storage value instead
// of the SQLite store OpenDriver opens. It takes ownership of st as OpenFrom
// does and refuses a store whose Writable refuses. storeRoot is the local
// directory where the checksum-database cache and the call-graph child's
// configuration live, not where records are stored.
//
// Stability: public driver composition entrypoint; unstable pre-v1 (§4).
func OpenDriverFrom(st *Storage, storeRoot string) (*Driver, func() error, error) {
	driver, cleanup, err := composition.NewDriverFrom(st, storeRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("opening kanonarion driver: %w", err)
	}
	return driver, cleanup, nil
}
