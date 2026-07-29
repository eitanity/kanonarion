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
