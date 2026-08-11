package domain

import "github.com/eitanity/kanonarion/internal/coordinate"

// LocalDirPlaceholder stands in for the working tree's directory in a remedy
// built somewhere the directory is not known.
//
// It is a placeholder and reads as one. The alternative — omitting the argument
// and printing a bare "kanonarion local" — is worse: that form is a valid
// invocation which analyses whatever directory the reader happens to be in, so a
// remedy that meant "the project's tree" would silently analyse the wrong one.
const LocalDirPlaceholder = "<dir>"

// ReanalysisCommand names the one command that re-derives coord's call graph.
//
// The answer is a property of the COORDINATE, not of the site asking. A
// published module is fetched and analysed by 'callgraph <module>@<version>'. A
// project's own module carries the synthetic 'local' version, which names no
// published artefact: 'callgraph' cannot fetch it and refuses, and 'fetch'
// cannot satisfy it either, so a remedy built by concatenating the coordinate
// onto "kanonarion callgraph " is an instruction that exits non-zero for every
// project coordinate it is handed. 'local <dir>' is the command that re-derives
// that graph.
//
// Every refusal that tells a reader to re-derive a graph goes through here, so
// the decision is made once and a new refusal cannot get it wrong on its own.
//
// dir is the working tree behind a local coordinate, when the caller knows it;
// empty yields LocalDirPlaceholder. It is ignored for a published coordinate,
// which has no working tree.
func ReanalysisCommand(coord coordinate.ModuleCoordinate, dir string) string {
	if !coord.IsLocal() {
		return "kanonarion callgraph " + coord.String()
	}
	if dir == "" {
		dir = LocalDirPlaceholder
	}
	return "kanonarion local " + dir
}

// ForcedReanalysisCommand names the command that re-derives coord's call graph
// even though the store already holds one, for a refusal raised BY a stored
// record: without bypassing the cache the run is served the very record the
// refusal was about, and reads as the remedy having been tried and failed.
//
// 'local' takes no --force because it holds no analysis cache to bypass — it
// analyses the tree it is pointed at every time — so the forced form of a
// project coordinate is the plain one. Appending a flag the command does not
// declare would produce an invocation cobra rejects outright.
func ForcedReanalysisCommand(coord coordinate.ModuleCoordinate, dir string) string {
	cmd := ReanalysisCommand(coord, dir)
	if coord.IsLocal() {
		return cmd
	}
	return cmd + " --force"
}

// IsReFetchable reports whether coord names bytes 'kanonarion fetch' can go and
// get. A project coordinate names a working tree, never a published artefact,
// so a remedy that tells its reader to fetch it names a command that cannot
// succeed however often it is run.
func IsReFetchable(coord coordinate.ModuleCoordinate) bool {
	return !coord.IsLocal() && !coord.IsZero()
}
