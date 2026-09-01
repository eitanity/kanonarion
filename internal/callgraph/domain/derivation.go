package domain

// ReuseGate names the check a run consults before appending a generation:
// whether the ledger already holds this analysis.
//
// Both routes ask it and they ask different questions, so a reader has to be
// told which one answered. A tree-scoped digest match is not the same evidence
// as an identical-measurement comparison against a held generation.
type ReuseGate string

const (
	// ReuseGateUnrecorded is the zero value: the generation predates the field
	// and says nothing about why it was appended. It is not a gate of its own and
	// never matches another unrecorded value.
	ReuseGateUnrecorded ReuseGate = ""
	// ReuseGateWorktree is the tree-scoped gate the local route consults before
	// analysing: the generation the ledger holds of this root at this scan digest.
	// See WorktreeRecordAnswersFor.
	ReuseGateWorktree ReuseGate = "worktree"
	// ReuseGateLedger is the identical-generation check the artefact route makes
	// after analysing: whether a generation already restates this measurement.
	// See RestatesAnalysis.
	ReuseGateLedger ReuseGate = "ledger"
)

// GateOutcome says what the reuse gate did for the run that appended this
// generation.
type GateOutcome string

const (
	// GateOutcomeUnrecorded is the zero value, on the same terms as
	// ReuseGateUnrecorded: the generation predates the field.
	GateOutcomeUnrecorded GateOutcome = ""
	// GateOutcomeConsulted means the gate was asked. A gate that answered appends
	// nothing, so on a stored generation this always means it held nothing
	// restating the analysis and the measurement is genuinely new.
	GateOutcomeConsulted GateOutcome = "consulted"
	// GateOutcomeBypassed means --force, so the gate was never asked. This is the
	// value that tells a demanded re-measurement from a gate that failed to fire.
	GateOutcomeBypassed GateOutcome = "bypassed"
)

// GenerationDerivation states why a generation exists, as distinct from what it
// measured.
//
// Two generations of one identical analysis are otherwise indistinguishable: a
// deliberate --force re-measurement and a reuse gate that did not fire leave the
// same row, and the only thing left to read intent out of is the directory the
// run happened to stand in, which is not evidence. Measured on the maintainer's
// store, one coordinate held thirteen generations of one analysis — same
// worktree digest, same node and edge counts — that nothing in the ledger could
// separate.
//
// It is inside the seal, so it is as tamper-evident as the measurement it
// qualifies. It is stripped from every comparison and every digest — see
// withoutRunCircumstance and forGraphComparison — because why a measurement was
// taken is no part of what the measurement says, and because a generation that
// predates the field must still be recognised as restating one that carries it.
type GenerationDerivation struct {
	// Gate is which reuse gate governed this append.
	Gate ReuseGate `json:"gate,omitzero"`
	// Outcome is whether that gate was asked or bypassed.
	Outcome GateOutcome `json:"outcome,omitzero"`
}

// IsRecorded reports whether the derivation says anything at all.
func (d GenerationDerivation) IsRecorded() bool { return d != GenerationDerivation{} }

// String renders the derivation for a report: which gate, and what it did.
func (d GenerationDerivation) String() string {
	if !d.IsRecorded() {
		return "derivation not recorded"
	}
	gate := string(d.Gate)
	if d.Gate == ReuseGateUnrecorded {
		gate = "unnamed"
	}
	switch d.Outcome {
	case GateOutcomeBypassed:
		return gate + " reuse gate bypassed (--force)"
	case GateOutcomeConsulted:
		return gate + " reuse gate consulted, held nothing restating this analysis"
	case GateOutcomeUnrecorded:
		return gate + " reuse gate, outcome not recorded"
	default:
		return gate + " reuse gate: " + string(d.Outcome)
	}
}

// DerivationFor states the gate a route consults and whether this run asked it.
// A forcing run never asks, which is the whole distinction the field records.
func DerivationFor(gate ReuseGate, forced bool) GenerationDerivation {
	outcome := GateOutcomeConsulted
	if forced {
		outcome = GateOutcomeBypassed
	}
	return GenerationDerivation{Gate: gate, Outcome: outcome}
}
