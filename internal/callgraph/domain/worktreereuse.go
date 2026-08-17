package domain

// WorktreeIdentity is what a run can learn about a working tree WITHOUT
// analysing it: where the tree is, and a digest of what it currently contains.
//
// It is the input identity of a local analysis. The record produced from that
// analysis states both, so a later run holding the same pair knows it would be
// asking the same question again.
type WorktreeIdentity struct {
	// Root is the absolute, symlink-free directory the analysis would run in.
	Root string
	// ScanDigest identifies the tree's current contents. It carries the scheme
	// prefix that says how it was taken — see CallGraphRecord.WorktreeScanDigest,
	// which is where it is stored and which explains why it is never compared
	// against the digest of what was analysed.
	ScanDigest string
}

// IsZero reports whether nothing about the tree was established.
func (i WorktreeIdentity) IsZero() bool { return i.Root == "" || i.ScanDigest == "" }

// WorktreeRecordAnswersFor reports whether a stored record already answers what
// an analysis of this tree would ask, so the analysis need not be run again.
//
// Four things must hold, and each of them is a way the answer could otherwise be
// about something else:
//
//   - The record was produced from a working tree. A graph built from a
//     published zip of the same module path describes different bytes.
//   - It was produced from THIS tree, at this root. Two checkouts of one module
//     path are two trees, and a reader standing in one asked about that one.
//   - It states the same scan digest, so the tree has not changed since. An
//     empty digest on the record is not a match: every record written before the
//     field existed carries none, and absence cannot show that two runs were
//     handed the same tree. The first run after this field lands therefore
//     re-derives, and every run after that reuses.
//   - It is servable at all. A record the analysis environment cut short — one
//     that failed for want of a toolchain, or came back incomplete because a
//     dependency was absent from this host's module cache — describes the run and
//     not just this tree, and serving it back would make one bad run permanent.
//     The tree's digest cannot see any of that: it moves when the source moves
//     and nothing else, so a repaired environment leaves it identical and the
//     cause axis is the only thing that says the answer is worth taking again.
//     The same rule the published path applies, applied here for the same
//     reason.
//
// The pipeline version is not checked here because it is not this function's to
// check: a store read is scoped to one pipeline version, so a record from
// another one is never handed to it.
func WorktreeRecordAnswersFor(existing CallGraphRecord, identity WorktreeIdentity) bool {
	if identity.IsZero() {
		return false
	}
	if existing.AnalysisSource != AnalysisSourceWorktree {
		return false
	}
	if existing.AnalysisRoot != identity.Root {
		return false
	}
	if existing.WorktreeScanDigest == "" || existing.WorktreeScanDigest != identity.ScanDigest {
		return false
	}
	return RecordIsCacheable(existing)
}
