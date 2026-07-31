package domain

// SynthesisedGoMod records that the tree an analysis read is NOT the tree that
// was published: the module zip shipped no go.mod, so kanonarion wrote one into
// the extraction directory before loading.
//
// It exists because the alternative is a record that quietly claims more than it
// measured. A module published before Go modules carries no go.mod in its zip, so
// the loader runs outside any module: no package carries the module's import
// path, nothing is recognised as the target, and the module is recorded with an
// empty graph. Writing a go.mod fixes that — and makes the analysis one of the
// published bytes PLUS a file kanonarion invented. A record sealed against an
// artefact identity while describing a tree that artefact does not contain is
// making a claim about bytes it did not read, which is precisely the kind of
// silent divergence the ledger exists to prevent.
//
// The zero value means no file was synthesised. That is unambiguous rather than
// merely absent: no record written before this field existed could have been
// synthesised, because nothing synthesised anything. So there is no "unrecorded"
// third state to ladder against here, and the field is omitted from the sealed
// shape when zero — which keeps every stored record's content hash verifiable.
type SynthesisedGoMod struct {
	// ModulePath is the module path written into the synthesised file. It is the
	// coordinate's path VERBATIM, with no major-version suffix added.
	//
	// That rule comes from a measured hazard. A +incompatible version — v2 or
	// above published without a /vN path — names a module whose path carries no
	// suffix at all. Synthesising "github.com/Masterminds/sprig/v2" for
	// sprig@v2.22.0+incompatible would load and build cleanly, and every node ID
	// in the resulting graph would name a module that does not exist. Such a graph
	// joins nothing else in the ledger and says so nowhere: worse than the empty
	// graph it replaces.
	ModulePath string
	// GoDirective is the language version written into the file, pinned and
	// recorded rather than defaulted.
	//
	// It is on the record because it decides the graph. A go directive of 1.22 or
	// later changes loop-variable scoping, which changes the SSA, which changes the
	// call graph — so a graph built under an unstated directive is not reproducible
	// across tool versions. Reading it back is how a consumer knows which language
	// semantics the graph describes.
	GoDirective string
	// VendorTreePresent reports that the extracted module also ships a vendor
	// directory.
	//
	// A go.mod beside a vendor tree makes the toolchain auto-select -mod=vendor,
	// at which point the analysis silently describes vendored copies of
	// dependencies rather than the module graph — and, with a synthesised file
	// that requires nothing, fails consistency checking against vendor/modules.txt
	// instead. The load explicitly disables vendor mode when this is set, and the
	// field is what makes that decision readable off the record rather than
	// inferable from the analyser's source.
	VendorTreePresent bool
}

// IsZero reports whether no go.mod was synthesised for this analysis.
func (s SynthesisedGoMod) IsZero() bool { return s == SynthesisedGoMod{} }

// String renders the synthesis for a human reading a record's provenance,
// returning the empty string when nothing was synthesised so a caller can append
// it unconditionally.
func (s SynthesisedGoMod) String() string {
	if s.IsZero() {
		return ""
	}
	out := "synthesised go.mod (module " + s.ModulePath + ", go " + s.GoDirective + ")"
	if s.VendorTreePresent {
		out += " [vendor tree present, vendor mode disabled]"
	}
	return out
}
