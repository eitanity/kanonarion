package domain

// AnalysisSource names what an analysis read to build a call graph.
//
// It is a DIMENSION, not a ladder. A graph built from a published module zip and
// one built from a working tree are both correct and neither supersedes the
// other; they answer different questions about different bytes. Composition
// therefore never picks between values of it — a reader asks for the one it
// wants, and the record carries which one it is.
//
// The field exists because the distinction was previously smuggled into the
// VERSION component of the coordinate: a working-tree ingest was stored at a
// synthetic "v0.0.0" that no published module ever resolves to. That is a
// version column stating something untrue, invisible to every query that filters
// on version, and unusable as an identity — two checkouts of the same module
// path collide on one key. Naming the source directly is what lets the two be
// told apart without reading a convention out of a version string.
type AnalysisSource string

const (
	// AnalysisSourceUnrecorded is the zero value: the record predates the field
	// and says nothing about what was analysed. It is a distinct value from all
	// the others and is never fidelity-comparable with them — a record that does
	// not say what it read cannot be shown to have read the same thing as one that
	// does.
	//
	// That holds for grouping and for reporting. It does NOT extend to comparing
	// what two records say about the graph: an absent value there is not a third
	// answer, it is the absence of a field, and hashing it as an answer made two
	// records with an identical graph contradict each other. analysedFrom resolves
	// it for that one purpose.
	AnalysisSourceUnrecorded AnalysisSource = ""
	// AnalysisSourceModuleZip is a graph built from a fetched module zip. The
	// bytes are pinned, the artefact identity names them, and re-analysing the
	// same coordinate reads the same bytes.
	AnalysisSourceModuleZip AnalysisSource = "zip"
	// AnalysisSourceWorktree is a graph built from a directory on disk. Nothing
	// was fetched, so there is no artefact identity — not missing, inapplicable —
	// and the tree mutates between runs, so two analyses of "the same" coordinate
	// may legitimately describe different code. WorktreeDigest is what tells them
	// apart.
	AnalysisSourceWorktree AnalysisSource = "worktree"
)

// String renders the source, showing the zero value as "not recorded" rather
// than as an empty field a reader would take for an absence of source.
func (s AnalysisSource) String() string {
	if s == AnalysisSourceUnrecorded {
		return "not recorded"
	}
	return string(s)
}

// AnalysisSources is every source this type defines. Consumers that must cover
// the dimension range over it rather than restating the list.
func AnalysisSources() []AnalysisSource {
	return []AnalysisSource{
		AnalysisSourceModuleZip,
		AnalysisSourceWorktree,
		AnalysisSourceUnrecorded,
	}
}

// analysedFrom names the source a record was built from, resolving a record that
// predates the field to the one source that was in use when it was written.
//
// It exists for the comparison site and nowhere else. An unrecorded source is not
// a third kind of source and must not be reported as one, so nothing here invents
// a value: it resolves to a source this type already defines, on the same evidence
// isWorktreeSequence already reads. A pinned version was fetched, so a graph built
// for it before the field existed was built from a module zip; the synthetic local
// version is never fetched, so a graph built for it was built from a working tree.
//
// Grouping and reporting deliberately keep using the raw field. A record that did
// not say what it read is still not evidence that it read the same bytes as one
// that did — that judgement belongs to identifiedOrAll and defaultSourceGroup, and
// resolving the value for them would assert provenance no record states.
func analysedFrom(r CallGraphRecord) AnalysisSource {
	if r.AnalysisSource != AnalysisSourceUnrecorded {
		return r.AnalysisSource
	}
	if r.Coordinate.IsLocal() {
		return AnalysisSourceWorktree
	}
	return AnalysisSourceModuleZip
}

// RecordAnalysisSource projects a record onto the source it was analysed from,
// together with what distinguishes that source from another of the same kind.
//
// For a zip the discriminator is the artefact identity — which bytes were read.
// For a working tree it is the tree digest. A record naming no source has
// neither, and the empty discriminator is what stops it being grouped with any
// record that does name one.
//
// It is a free function rather than a method so CallGraphRecord stays a
// read-shaped result type with no behaviour.
func RecordAnalysisSource(r CallGraphRecord) (AnalysisSource, string) {
	switch r.AnalysisSource {
	case AnalysisSourceWorktree:
		return AnalysisSourceWorktree, r.WorktreeDigest
	case AnalysisSourceModuleZip:
		return AnalysisSourceModuleZip, r.ArtefactIdentity
	case AnalysisSourceUnrecorded:
		return AnalysisSourceUnrecorded, ""
	default:
		return r.AnalysisSource, ""
	}
}
