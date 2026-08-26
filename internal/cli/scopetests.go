package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// testScope names what a resolved go.mod dependency scope did about test-scope
// dependencies.
//
// It is stated on every go.mod-scoped answer for the same reason the build frame
// is. The axis moves the module count by about as much as the platform does — on
// this project the code scope resolves 20 modules with test imports and 18
// without, while linux and windows differ by two — and only the platform was
// named. A count published without the scope it was computed over is the defect,
// whichever axis decided it.
type testScope string

const (
	// testScopeIncluded: the scope was resolved with `go list -deps -test`, so a
	// module reached only from the root set's _test.go files is in the set.
	testScopeIncluded testScope = "included"
	// testScopeExcluded: the resolution covers only what the root set's non-test
	// packages import. On the code scope --exclude-tests asks for this; on the
	// tool scope it is the scope's own definition.
	testScopeExcluded testScope = "excluded"
	// testScopeUnavailable: the scope resolves through `go list -m all`, which
	// reports one build list and partitions it by nothing. The axis is stated as
	// absent rather than as "included", which would claim a decision the module
	// graph never offered and would read as a narrowing having been honoured.
	testScopeUnavailable testScope = "unavailable"
)

// testScopeFor is the single mapping from a dependency scope and the caller's
// --exclude-tests to the axis actually applied.
//
// The two -deps scopes default differently and that is not an inconsistency:
// `-test` means "include the test dependencies OF THE ROOT SET", and the two
// scopes have different root sets. On the code scope it adds this project's own
// test infrastructure — go-internal and goleak here — which we compile and
// execute, so a vulnerability in either runs on our machines and belongs in the
// answer. On the tool scope it adds the test frameworks the TOOL AUTHORS use to
// test their own tools — ginkgo and gomega, via golangci-lint — which nothing we
// run ever links. A CVE there is a fact about golangci-lint's development, not
// about our tooling supply chain.
//
// So the defaults answer two different questions correctly, and one flag cannot
// govern both. What was missing was never a shared axis; it was that neither
// answer said which question it had answered.
func testScopeFor(scope depScope, excludeTests bool) testScope {
	switch scope {
	case scopeComplete:
		return testScopeUnavailable
	case scopeTool:
		// By construction, not by request: the tool closure is the import closure
		// of the tool binaries, which never reaches their authors' test packages.
		return testScopeExcluded
	case scopeCode:
		if excludeTests {
			return testScopeExcluded
		}
		return testScopeIncluded
	default:
		return testScopeIncluded
	}
}

// withTests reports whether the resolution passes -test to `go list`. Only
// testScopeIncluded does; an unavailable axis never reaches a -deps resolution.
func (t testScope) withTests() bool { return t == testScopeIncluded }

// scopeResolution is what a scope resolved to: the scope, the test axis it
// applied, and whether the caller asked for a narrowing.
//
// The three travel together because the statement must be able to say that
// --exclude-tests changed nothing without a surface deciding that for itself. It
// is produced by resolveScopeModules beside the module set, so an answer cannot
// state one axis and have resolved another.
type scopeResolution struct {
	Scope depScope
	Tests testScope
	// Requested records that --exclude-tests was passed. It differs from what the
	// axis says only on the tool scope, where the exclusion was already in force:
	// there the statement says the flag narrowed nothing rather than crediting it
	// with a narrowing it did not cause.
	Requested bool
}

// newScopeResolution derives the resolution from the scope and the caller's flag.
func newScopeResolution(scope depScope, excludeTests bool) scopeResolution {
	return scopeResolution{Scope: scope, Tests: testScopeFor(scope, excludeTests), Requested: excludeTests}
}

// statement renders the axis as the clause an answer carries. It names what was
// measured and what decided it, so an answer with no test-only dependency in it
// still says which set it looked at, and an answer whose exclusion predates the
// flag does not credit the flag with it.
func (r scopeResolution) statement() string {
	switch {
	case r.Tests == testScopeUnavailable:
		return "no test axis: `go list -m all` reports one build list with no test partition"
	case r.Tests == testScopeExcluded && r.Scope == scopeTool && r.Requested:
		return "test-scope dependencies excluded by the scope itself — the tool closure is the tool binaries' imports, which never reach their authors' test packages; --" +
			testScopeFlagName + " narrowed nothing"
	case r.Tests == testScopeExcluded && r.Scope == scopeTool:
		return "test-scope dependencies excluded by the scope itself — the tool closure is the tool binaries' imports, which never reach their authors' test packages"
	case r.Tests == testScopeExcluded:
		return "test-scope dependencies excluded (--" + testScopeFlagName + " was given)"
	default:
		return "test-scope dependencies included"
	}
}

// narrowable reports whether offering --exclude-tests would tell the reader
// anything. Only a test-inclusive resolution can be narrowed by it.
func (r scopeResolution) narrowable() bool { return r.Tests == testScopeIncluded }

// writeDepScopeNotice states, on stderr, which dependency scope resolved the
// answer and which test axis that scope applied, with the count it resolved.
//
// stderr, beside the build-frame and derivation lines, and for the reason given
// there: on these commands stdout is either a documented array of rows, a
// content-hashed walk record, or an NDJSON stream, and a statement about the run
// is not one of the run's rows. The machine-readable half of the disclosure is a
// field on the documents that have one, not a line on this channel.
//
// offerFlag is set by the surfaces that honour --exclude-tests, so the hint is
// only shown where the flag would be accepted and would change something.
func writeDepScopeNotice(w io.Writer, r scopeResolution, modules int, offerFlag bool) error {
	return writeDepScopeLine(w, fmt.Sprintf("%s scope resolved %d module(s)", r.Scope, modules), r, offerFlag)
}

// writeDepScopeAxisNotice states the scope and its axis where the run resolved no
// count to state: a complete-scope walk restricts the build list by nothing, so
// it never enumerates the set, and reporting "0 module(s)" there would name an
// empty scope rather than an unrestricted one.
func writeDepScopeAxisNotice(w io.Writer, r scopeResolution) error {
	return writeDepScopeLine(w, fmt.Sprintf("%s scope", r.Scope), r, false)
}

func writeDepScopeLine(w io.Writer, subject string, r scopeResolution, offerFlag bool) error {
	hint := ""
	if offerFlag && r.narrowable() {
		hint = " (narrow with --" + testScopeFlagName + ")"
	}
	if _, err := fmt.Fprintf(w, "notice: %s; %s%s\n", subject, r.statement(), hint); err != nil {
		return fmt.Errorf("writing dependency scope notice: %w", err)
	}
	return nil
}

// scopeJSON is the machine-readable half of the same disclosure, carried by
// every go.mod-scoped document that has somewhere to put it.
//
// test_scope is a three-valued string, not a bool. A bool cannot hold
// "unavailable", and flattening the complete scope's absent axis into false
// would publish it as a narrowing that was honoured — the exact silence this
// field exists to end. The local working-tree form's tests_excluded stays a bool
// because there the axis is always available and false is exactly the default.
//
// It carries what the answer IS, never what the request was: an axis excluded by
// the tool scope and one excluded by --exclude-tests describe the same set, and
// a consumer comparing two answers must not see them differ. That the flag
// narrowed nothing is a message about the invocation, and it goes in the text.
type scopeJSON struct {
	Scope     string `json:"scope"`
	TestScope string `json:"test_scope"`
}

// newScopeJSON builds the field. Both members are always populated: a reader
// cannot tell an unstated axis from a missing one.
func newScopeJSON(r scopeResolution) *scopeJSON {
	return &scopeJSON{Scope: string(r.Scope), TestScope: string(r.Tests)}
}

// refuseTestScopeOnCompleteScope refuses --exclude-tests against --project.
//
// An unavailable axis is stated, never silently ignored. The tool scope accepts
// the flag and says it narrowed nothing, because there the caller's question —
// answer over production code only — is already answered by the set they get.
// Here it is not: the build list holds the test dependencies of everything and
// cannot be partitioned, so returning it under a flag that asked for production
// code would answer a different question than the one put.
func refuseTestScopeOnCompleteScope(path string) error {
	return fmt.Errorf("%s --project does not act on --%s: the complete scope resolves through `go list -m all`, which reports one build list with no test partition, so there is no test axis to narrow",
		path, testScopeFlagName)
}

// testScopeNoScopeFlag returns --exclude-tests when it was set on a path that
// projects no go.mod scope: a positional module and a pinned walk each name
// their own set, fixed elsewhere, with no test axis of their own to narrow.
func testScopeNoScopeFlag(set bool) []inapplicableFlag {
	if !set {
		return nil
	}
	return []inapplicableFlag{{
		flag:  "--" + testScopeFlagName,
		where: "context --gomod or latest --gomod",
	}}
}

// registerRecordedTestScopeFlag registers --exclude-tests on a command that
// records a walk, so the refusal below can say why rather than leaving cobra to
// report an unknown flag.
//
// Hidden: the flag is registered to be explained, not to be offered, and listing
// it in --help beside flags that work would advertise a narrowing this command
// cannot take.
func registerRecordedTestScopeFlag(cmd *cobra.Command, p *bool) {
	cmd.Flags().BoolVar(p, testScopeFlagName, false,
		"not accepted here: a walk record names its scope but not its test axis")
	_ = cmd.Flags().MarkHidden(testScopeFlagName)
}

// refuseTestScopeOnRecordingCommand refuses --exclude-tests on the commands that
// record a walk.
//
// `walks.scope` is a stored column and Scope is inside the walk identity hash,
// so today the scope string fully describes the module set that was walked.
// Narrowing a walk by a flag the record cannot name would break that: two walks
// both stored `code` would hold different module sets and nothing would tell
// them apart. Recording the axis is a walk pipeline bump and a migration, which
// this change does not take, so the flag is refused here and honoured on the
// commands that only read.
func refuseTestScopeOnRecordingCommand(path string, set bool) error {
	if !set {
		return nil
	}
	return fmt.Errorf("%s does not act on --%s: it records a walk, and a walk record names its scope but not its test axis, so a narrowed walk would be stored as one indistinguishable from a full one (applies to context --gomod and latest --gomod)",
		path, testScopeFlagName)
}
