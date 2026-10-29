// Package exitcode is the process exit-code taxonomy and the classification
// of an error onto it, shared by the kanonarion binary and the call-graph child
// an importing application serves, so the two exit alike.
package exitcode

import (
	"errors"

	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	exampleports "code.eitanity.com/kanonarion/internal/example/ports"
	extractports "code.eitanity.com/kanonarion/internal/extract/ports"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
	ifaceports "code.eitanity.com/kanonarion/internal/iface/ports"
	licenceports "code.eitanity.com/kanonarion/internal/license/ports"
	nativeports "code.eitanity.com/kanonarion/internal/native/ports"
	stdlibports "code.eitanity.com/kanonarion/internal/stdlib/ports"
	vulnports "code.eitanity.com/kanonarion/internal/vuln/ports"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// Exit codes.
//
// The taxonomy exists so an automation caller can branch on the process exit
// code alone, without parsing stderr prose. Four questions a script actually
// asks get four different answers: did the work complete (0/1/2/3), does the
// record you named exist (4), did a policy gate fire on real findings (5), is
// the recorded evidence in doubt (10), or did you invoke it wrongly (20).
// Collapsing any of those onto Config makes "you typed it wrong"
// indistinguishable from "the gate you asked for did its job".
const (
	OK        = 0
	Partial   = 1
	Failed    = 2
	Cancelled = 3
	// NotFound signals that a record requested by ID or coordinate (walk,
	// scan run, extraction, directive scan, licence, vulnerability, call
	// graph,...) does not exist. Distinct from Config so scripts can tell
	// 'no such record' — which the remedy named in the message fixes — from
	// 'the request itself was malformed'.
	NotFound = 4
	// Policy signals that a governance or publication gate fired on real
	// findings: the command ran to completion, measured the artefact, and the
	// policy it was asked to enforce says the result is not publishable. That is
	// the gate working, not a configuration error, and a CI step must be able to
	// route it to a human rather than to whoever fixes broken invocations.
	Policy    = 5
	Integrity = 10
	// Config is the invocation/precondition catch-all: a malformed argument,
	// an unparseable coordinate, a missing toolchain, a policy FILE that is not
	// there, or a store whose schema is newer than this binary. It says the
	// command never got as far as producing an answer.
	Config = 20
)

// Error is an error that carries its exit code.
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// EvidenceInDoubt is every sentinel meaning the recorded evidence cannot be
// trusted: a stored record whose content hash does not verify, or two records
// for one coordinate that disagree. The table gives both to Integrity and
// does not qualify either by which domain raised it.
//
// Only the walk sentinel was mapped, so the other twelve reached Config by
// the fallback — which says the invocation itself was wrong, and routes a
// store-integrity problem to whoever fixes broken command lines. A sentinel
// added to a ports package must be added here; the contract test reads the
// ports packages and fails if one is missing.
var EvidenceInDoubt = []error{
	walkports.ErrWalkIntegrity,
	cgports.ErrCallGraphIntegrity, cgports.ErrCallGraphConflict,
	ifaceports.ErrInterfaceIntegrity, ifaceports.ErrInterfaceConflict,
	licenceports.ErrLicenceIntegrity, licenceports.ErrLicenceConflict,
	exampleports.ErrExampleIntegrity, exampleports.ErrExampleConflict,
	extractports.ErrExtractionRunIntegrity,
	vulnports.ErrVulnIntegrity, vulnports.ErrVulnConflict, vulnports.ErrSnapshotIntegrity,
	stdlibports.ErrFactsIntegrity, stdlibports.ErrFactsConflict,
	fetchports.ErrFetchRecordIntegrity,
	nativeports.ErrNativeConflict,
}

// ModuleNotFetched is every producer's refusal for a module whose bytes the
// store does not hold. The printed 'kanonarion fetch' runs as given and supplies
// them, so it is an absent record (4), not a malformed invocation (20).
var ModuleNotFetched = []error{
	cgports.ErrModuleNotFetched, ifaceports.ErrModuleNotFetched, licenceports.ErrModuleNotFetched,
	exampleports.ErrModuleNotFetched, nativeports.ErrModuleNotFetched,
}

// Of maps err onto the exit code a run ending in it exits with: a refused
// stored artefact first, then a code err carries, then the absences and the
// evidence in doubt by sentinel, and otherwise Config. coded reads a carrier
// the caller defines; nil reads only Error.
func Of(err error, coded func(error) (int, bool)) int {
	if err == nil {
		return OK
	}
	// A stored artefact refused as altered outranks whatever the command made of
	// the gap it left: every answer the run gave stands on the store's bytes.
	if errors.Is(err, fetchports.ErrBlobTampered) {
		return Integrity
	}
	if coded != nil {
		if code, ok := coded(err); ok {
			return code
		}
	}
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code
	}
	for _, sentinel := range EvidenceInDoubt {
		if errors.Is(err, sentinel) {
			return Integrity
		}
	}
	// A genuine record filed under a key its seal does not carry, raised by a
	// store with no integrity sentinel of its own.
	if recordseal.IsMisfiled(err) {
		return Integrity
	}
	for _, sentinel := range ModuleNotFetched {
		if errors.Is(err, sentinel) {
			return NotFound
		}
	}
	// A walk id that reached a use case without the up-front lookup is still an
	// absent record, not a malformed invocation; so is a walk never scanned.
	if errors.Is(err, walkports.ErrWalkNotFound) || errors.Is(err, vulnports.ErrWalkNotScanned) {
		return NotFound
	}
	// Every stored generation was set aside, or a refusal was decided without
	// one: nothing this build can serve to answer, which is an absence. A
	// set-aside reaches here only as a failure, since reads return it beside an
	// answer; checked after the sentinels so an altered row still wins.
	if errors.As(err, new(*recordseal.SetAside)) {
		return NotFound
	}
	// A divergence — two records for one coordinate disagreeing on a hash they
	// both carry — is an integrity failure, not a configuration error. A
	// consuming command fails closed on it; a store-inspection command reports
	// it and exits 0, so the tool used to diagnose the problem is not the one
	// that refuses to run.
	if errors.As(err, new(*fetchdomain.Divergence)) {
		return Integrity
	}
	return Config
}
