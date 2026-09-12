// Package failurecause names what a failed or incomplete measurement is a
// statement about: the thing under analysis, or the run that tried to analyse
// it.
//
// The distinction is the difference between a finding and a measurement that
// never happened. A module whose source does not type-check is a real, stable
// property of that module — re-analysing it tomorrow rediscovers it at full
// analysis cost. A run that could not find a usable Go toolchain, that was
// stopped for making no progress, or whose write lost the store lock has
// measured nothing at all, and the same module analysed a minute later on a
// repaired box may well come back complete.
//
// The fetch ledger draws the same line for the same reason, and states it as
// "a failure is a statement about the lookup, not about the module, and a later
// attempt may well succeed. Collapsing the two lets one network flake be
// recorded — and cached — as a property of a dependency." The flake may be a
// toolchain, a deadline or a lock, and the record may be a call graph, a scan or
// a stage result, but the failure mode is identical: without the axis, one bad
// run is filed as a fact about a dependency and served on every subsequent run.
//
// The cause is classified where the failure is still a value — at the boundary
// that met it, from what that boundary knows about the environment — and never
// by re-reading the prose of a stored detail, on the same terms x/mod/sumdb's
// errors are classified at ClientOps rather than recovered from a flattened
// string.
//
// It lives at the root of internal/ rather than inside one bounded context
// because three of them ask the same question of the same run — the call-graph
// ledger, the vulnerability scan and the extraction stage — and a vocabulary
// each of them spelled for itself is one that holds in whichever copy was
// edited last. Only one word ever has to mean "repair the box and run again".
//
// It is not a ladder and nothing composes over it: it qualifies a failure or an
// incompleteness, and a record carrying an answer outranks any failure whatever
// caused it. What it decides is whether a later run may be served this one.
package failurecause

// Cause is the axis: unrecorded, the module, or this environment.
type Cause string

const (
	// Unrecorded is the zero value. It is carried by every measurement that came
	// back complete, and by the failed and partial records written before the axis
	// reached them. It states no cause, and must never be read as one: an
	// extraction that does not say what limited it is not evidence that the module
	// is at fault.
	Unrecorded Cause = ""

	// Module means the thing under analysis is what limited it: its published
	// bytes carry no Go packages, its source does not type-check, its module graph
	// cannot be resolved from what it ships. It qualifies a partial measurement as
	// well as a failed one. The finding is about the module and is stable across
	// runs, so it is served from cache exactly as a successful analysis is.
	Module Cause = "module"

	// Environment means the analysis environment is what limited the run: no
	// usable go on PATH, a tool built against an older Go than the project
	// requires, a toolchain that is absent or unresolvable, a cancelled context, a
	// subprocess stopped for making no progress, a memory cap, a module cache too cold
	// to resolve a dependency the load needed, a write that could not take the
	// store lock. What the run reached says as much about this host as about the
	// module, so the record is kept as evidence that this run ran the way it did —
	// the ledger never goes silent — but it is not eligible as a cache hit. That
	// holds whether the run produced no answer at all or an incomplete one: a
	// repaired environment must get its chance to measure the rest.
	Environment Cause = "environment"
)

// IsEnvironmentLimit reports whether the cause says this HOST, rather than the
// module, is what the analysis stopped short of.
//
// It is a predicate rather than a comparison written out at each site because
// several rules read it, and a rule spelled twice is one that holds in whichever
// copy was edited last. A store reads it off a column and composition off a
// record; both ask this.
func (c Cause) IsEnvironmentLimit() bool { return c == Environment }

// String renders the cause, showing the zero value as "not recorded" rather than
// as an empty field a reader would take for an absence of cause.
func (c Cause) String() string {
	if c == Unrecorded {
		return "not recorded"
	}
	return string(c)
}
