package cli

// Exit codes.
//
// The taxonomy exists so an automation caller can branch on the process exit
// code alone, without parsing stderr prose. Four questions a script actually
// asks get four different answers: did the work complete (0/1/2/3), does the
// record you named exist (4), did a policy gate fire on real findings (5), is
// the recorded evidence in doubt (10), or did you invoke it wrongly (20).
// Collapsing any of those onto ExitConfig makes "you typed it wrong"
// indistinguishable from "the gate you asked for did its job".
const (
	ExitOK        = 0
	ExitPartial   = 1
	ExitFailed    = 2
	ExitCancelled = 3
	// ExitNotFound signals that a record requested by ID or coordinate (walk,
	// scan run, extraction, directive scan, licence, vulnerability, call
	// graph,...) does not exist. Distinct from ExitConfig so scripts can tell
	// 'no such record' — which the remedy named in the message fixes — from
	// 'the request itself was malformed'.
	ExitNotFound = 4
	// ExitPolicy signals that a governance or publication gate fired on real
	// findings: the command ran to completion, measured the artefact, and the
	// policy it was asked to enforce says the result is not publishable. That is
	// the gate working, not a configuration error, and a CI step must be able to
	// route it to a human rather than to whoever fixes broken invocations.
	ExitPolicy    = 5
	ExitIntegrity = 10
	// ExitConfig is the invocation/precondition catch-all: a malformed argument,
	// an unparseable coordinate, a missing toolchain, a policy FILE that is not
	// there, or a store whose schema is newer than this binary. It says the
	// command never got as far as producing an answer.
	ExitConfig = 20
)
