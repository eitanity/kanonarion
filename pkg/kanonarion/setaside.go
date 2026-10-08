package kanonarion

import (
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/composition"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// Stored records this build cannot reproduce. A record whose bytes hash to
// their own seal but which this build cannot re-derive was written by another
// build in a different canonical shape; reads leave it out and name it rather
// than report it as tampering. A record whose bytes do not hash to their seal
// still fails with the store's integrity sentinel.

// SetAside reports the stored records a read or write left out because this
// build cannot reproduce them. The vulnerability store returns it BESIDE the
// answer, as it returns UnreadableRows; match it with errors.As.
//
// Stability: error type (matched by consumers); unstable pre-v1 (§4).
type SetAside = recordseal.SetAside

// SetAsideRow names one set-aside stored record: its kind, identity,
// generation, content hash and the classification that set it aside.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version (§4).
type SetAsideRow = recordseal.SetAsideRow

// NothingServable is the answer when every stored record for what was asked
// was set aside: records are held, none this build can serve. It is an absence,
// not an integrity failure, and unwraps to the SetAside that says why.
//
// Stability: error type (matched by consumers); unstable pre-v1 (§4).
type NothingServable = recordseal.NothingServable

// UnreadableRows reports that a vulnerability store listing returned every row
// it could verify and names the ones it could not. It unwraps to the store's
// integrity sentinel.
//
// Stability: error type (matched by consumers); unstable pre-v1 (§4).
type UnreadableRows = vulnports.UnreadableRows

// UnreadableRow names one row an UnreadableRows report could not verify.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version (§4).
type UnreadableRow = vulnports.UnreadableRow

// ErrGenerationDrift matches a record whose bytes hash to their own seal but
// which this build cannot reproduce; every SetAsideRow's reason wraps it.
//
// Stability: error sentinel (matched by consumers); unstable pre-v1 (§4).
var ErrGenerationDrift = recordseal.ErrGenerationDrift

// Option configures Open and OpenDriver.
//
// Stability: composition option; unstable pre-v1. Options may be added within
// a major version (§4).
type Option = composition.Option

// WithSetAsideReporter receives the records the licence, example, call-graph,
// walk, extraction-run, stdlib and fetch stores set aside. Those stores answer from
// the records they can serve and keep the answer's signature, so the rows come
// here rather than as an error; without a reporter each is logged at warn level
// through the default logger. The vulnerability store returns its rows as
// SetAside beside the answer instead.
//
// Stability: composition option; unstable pre-v1 (§4).
func WithSetAsideReporter(r func([]SetAsideRow)) Option {
	return composition.WithSetAsideReporter(r)
}
