package domain

import (
	"encoding/json"
	"strings"

	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// ToolchainIdentity is what a record says about the toolchain that built it,
// together with how it came to say it.
//
// Two strengths, because the two are not the same claim. A RECORDED version is
// the toolchain naming itself. A DERIVED one is read back out of the record's
// own stdlib positions, which is all a record written before the field existed
// can offer — and which, for a GOROOT that is a plain directory, is a location
// rather than a version.
type ToolchainIdentity struct {
	// Version is the toolchain version, when one is established.
	Version gotoolchain.Version
	// Root is the GOROOT the stdlib was read from, when that is all the record
	// shows. Empty once Version is known.
	Root string
	// Derived is true when this was read out of the graph rather than recorded by
	// the analysis.
	Derived bool
}

// Key is the toolchain this record ESTABLISHES, and it is empty unless a version
// is known.
//
// A GOROOT that names no version is not a value. "The stdlib came from
// /usr/local/go" says where it was read, not which toolchain read it — the
// toolchain installed there is upgraded in place — so it is an absence of an
// established value in exactly the way "no stdlib path at all" is. Treating it as
// a value made it collide with a named toolchain and refused reads whose two
// generations held a byte-identical graph: measured on the live store, 25 of 30
// refusals were a named toolchain against an unnamed GOROOT, and 18 of the 30 had
// one graph digest across every generation. "I could not tell" is not a toolchain.
//
// The root still matters as EVIDENCE, and Root is where that lives: it explains a
// graph difference without ever asserting a version. See rootEvidence.
func (t ToolchainIdentity) Key() string {
	if t.Version.Recorded() {
		return string(t.Version)
	}
	return ""
}

// rootEvidence is where this record's stdlib was read from, as the strongest
// statement the record supports: a version when one is established, the GOROOT
// when only a location is, empty when neither.
//
// It is not a dimension value and never raises a conflict on its own. It is what
// lets a graph difference be ATTRIBUTED to the toolchain — two records built from
// different stdlib trees that describe different graphs have a cause, and naming
// it is better evidence than reporting the analyser as non-deterministic.
func (t ToolchainIdentity) rootEvidence() string {
	switch {
	case t.Version.Recorded():
		return string(t.Version)
	case t.Root != "":
		return "GOROOT " + t.Root
	default:
		return ""
	}
}

// String renders the identity for a human, and says plainly when a GOROOT names
// no version — a reader who is told "GOROOT /usr/local/go" must not read it as a
// version, because the toolchain installed there is upgraded in place.
func (t ToolchainIdentity) String() string {
	switch {
	case t.Version.Recorded() && t.Derived:
		return string(t.Version) + " (from the recorded stdlib path)"
	case t.Version.Recorded():
		return string(t.Version)
	case t.Root != "":
		return "unnamed version at GOROOT " + t.Root
	default:
		return gotoolchain.Unrecorded.String()
	}
}

// RecordToolchain projects a record onto the toolchain that built it.
//
// AN EMPTY KEY IS A DELIBERATE EXCEPTION to the rule that an absent value is not
// a dimension value. Every other retrofitted dimension had a knowable predecessor
// to ladder pre-field rows to; this one does not, so a record that establishes
// nothing takes no part in the toolchain comparison rather than being laddered to
// a value or read as a toolchain of its own. Assigning the reading host's would
// be fabrication, and the next reader must not "repair" it into a guess.
//
// The recorded field answers whenever it is set. Otherwise the record's own
// stdlib node positions are read: every graph built with bodies carries the
// stdlib it linked against, and the GOROOT those files sat under is a fact the
// record already states. That is recovery of recorded evidence, not attribution
// — nothing here consults the reading host, and a graph that carries no stdlib
// path at all establishes nothing and says so.
func RecordToolchain(r CallGraphRecord) ToolchainIdentity {
	if r.Toolchain.Recorded() {
		return ToolchainIdentity{Version: r.Toolchain}
	}
	root := stdlibRoot(r)
	if root == "" {
		return ToolchainIdentity{}
	}
	if v, ok := gotoolchain.FromGOROOT(root); ok {
		return ToolchainIdentity{Version: v, Derived: true}
	}
	return ToolchainIdentity{Root: root, Derived: true}
}

// stdlibRoot returns the GOROOT this graph's stdlib nodes were read from, or
// empty when it holds none.
//
// A stdlib node is recognised from the record alone: its package is an import
// path with no dot in the first element, and its position sits at
// "<goroot>/src/<package>/". Matching the package against its own file path is
// what makes this host-agnostic — nothing here knows what a GOROOT looks like,
// only that the stdlib lives under one.
func stdlibRoot(r CallGraphRecord) string {
	for i := range r.Nodes {
		n := &r.Nodes[i]
		if n.Module != "" || n.Package == "" || strings.Contains(firstPathElement(n.Package), ".") {
			continue
		}
		marker := "/src/" + n.Package + "/"
		if idx := strings.Index(n.Position.File, marker); idx > 0 {
			return n.Position.File[:idx]
		}
	}
	return ""
}

// firstPathElement returns the leading element of a slash-separated path.
func firstPathElement(p string) string {
	if i := strings.Index(p, "/"); i >= 0 {
		return p[:i]
	}
	return p
}

// withToolchain keeps the records built by one toolchain, as named by a reader.
func withToolchain(records []CallGraphRecord, want gotoolchain.Version) []CallGraphRecord {
	out := make([]CallGraphRecord, 0, len(records))
	for _, r := range records {
		if RecordToolchain(r).Version == want {
			out = append(out, r)
		}
	}
	return out
}

// selectableToolchain returns the first conflicting identity a reader can
// actually pass to --toolchain, or empty when none of them can be.
//
// Only a version is selectable. A "GOROOT ..." identity names a directory whose
// toolchain was never recorded, so offering it as a selector would print a
// command with no version in it — advice the CLI would then reject.
func selectableToolchain(values []string) string {
	for _, v := range values {
		if !strings.HasPrefix(v, "GOROOT ") && v != "" {
			return v
		}
	}
	return ""
}

// toolchainExplainedGraphDifference reports a graph difference the toolchain
// accounts for, or nil.
//
// It is checked ahead of the per-build-list graph comparison because the two axes
// are independent: two generations offered different build lists are not compared
// with each other at all, and a toolchain difference between them would otherwise
// go unreported — which is exactly how the flagship coordinate came to serve one
// toolchain's graph silently.
//
// AN IDENTICAL GRAPH CLAIM IS NEVER A DISAGREEMENT, whatever the labels say. That
// short-circuit is the deliberate choice here: where two records describe the
// same nodes, edges, interfaces and implementations there is nothing for a
// toolchain to disagree about, and refusing on the strength of a label alone is
// what made 18 of 30 refusals byte-identical graphs and partially undid the
// property that analysing a module twice leaves it readable.
//
// What remains is a real difference with a cause. Two records that describe
// different graphs and read their stdlib from different trees have one, and
// naming it is better evidence than reporting the analyser as non-deterministic.
// The comparison is pairwise so that a difference BETWEEN two runs of one
// toolchain is not mislabelled because some third record happens to name another.
func toolchainExplainedGraphDifference(records []CallGraphRecord) *CallGraphConflict {
	if len(records) < 2 {
		return nil
	}
	stated := make([]map[string]json.RawMessage, len(records))
	for i, r := range records {
		fields, err := graphFields(r)
		if err != nil {
			// Which fields each record states could not be read, so whether they agree
			// was never measured. The per-build-list comparison reports that as its own
			// refusal — see unmeasurableGraphs — and attributing an unmeasured
			// difference to the toolchain here would be a cause invented for an effect
			// nothing observed. Standing aside is deliberate, not a swallowed error.
			return nil //nolint:nilerr // the failure is reported by graphDisagreement, which runs next
		}
		stated[i] = fields
	}
	shared := sharedFieldsAmong(stated, GraphClaimFields())
	digests := make([]string, len(records))
	evidence := make([]string, len(records))
	for i := range records {
		digests[i] = digestOfFields(stated[i], shared)
		evidence[i] = RecordToolchain(records[i]).rootEvidence()
	}

	for i := range records {
		for j := i + 1; j < len(records); j++ {
			if digests[i] == digests[j] {
				continue
			}
			a, b := evidence[i], evidence[j]
			if a == "" || b == "" || a == b {
				continue
			}
			values := []string{a, b}
			hashes := []string{records[i].ContentHash, records[j].ContentHash}
			if b < a {
				values = []string{b, a}
				hashes = []string{records[j].ContentHash, records[i].ContentHash}
			}
			c := &CallGraphConflict{
				Coordinate:      records[0].Coordinate,
				PipelineVersion: records[0].PipelineVersion,
				AnalysisRoot:    agreedAnalysisRoot(records),
				Field:           ConflictFieldToolchain,
				Completeness:    records[i].Completeness,
				Values:          values,
				ContentHashes:   hashes,
			}
			return describingTheDifference(c, records)
		}
	}
	return nil
}
