package domain

import (
	"errors"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// NativeSchemaVersion is the version of the Record JSON schema. Bump it on a
// backwards-incompatible serialisation change. It is independent of
// PipelineVersion and of RecipeCatalogueVersion: the on-disk shape, the
// detection logic and the recognised-library knowledge evolve apart.
const NativeSchemaVersion = "1"

// EcosystemGo is the only ecosystem kanonarion records describe. The field
// declares the schema's scope — kanonarion is fitted for Go — rather than
// enabling polyglot mode.
const EcosystemGo = "go"

// PipelineVersion tracks the detection logic: which files are held to be
// compiled into a binary, which linked libraries are read out of the cgo
// directives, and how a recipe is matched against them. Bump it when a
// re-measurement of an unchanged artefact would differ from a stored record.
// The recipe catalogue is versioned separately and folded in by
// PipelineFingerprint, so adding a recipe re-measures without pretending the
// detection logic changed.
//
// 0.2.0 added the LinkedLibraries collection and the linked_not_shipped
// presence. 0.3.0 added `#cgo pkg-config` as a fourth operand form, which moves
// a module linking only through pkg-config off absent. Neither older record
// describes the same measurement, and neither is ever served for one taken now.
const PipelineVersion = "0.3.0"

// ErrUnsupportedEcosystem is returned when a stored record's ecosystem is
// absent or holds a value other than EcosystemGo.
var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem: kanonarion records are Go-only")

// PipelineFingerprint is the generation key a record is stored under: the
// detection logic and the recipe catalogue that produced it. A catalogue
// revision must re-measure an unchanged artefact rather than serve a cached
// answer taken before the recipe existed, which is precisely the "present,
// unidentified" case turning into an identification.
func PipelineFingerprint() string {
	return PipelineVersion + "+recipes." + RecipeCatalogueVersion
}

// Presence is what the artefact was found to carry. It is four-valued on
// purpose: an artefact carrying native source no recipe matches is a coverage
// gap a reader can act on, an artefact that links a library it never ships is
// a scoping limit rather than an absence, and recording either as absent — or
// as nothing at all — would be the same silence this context exists to remove.
type Presence string

const (
	// PresenceAbsent means the artefact carries no native source the Go build
	// would compile and its cgo directives name no library from outside the
	// module. It is a measured answer, not a missing one.
	PresenceAbsent Presence = "absent"

	// PresenceLinkedNotShipped means the artefact compiles no native source of
	// its own but its cgo directives link at least one external native library.
	// Something native reaches the binary; it is not in these bytes, so no
	// version can be read from them.
	//
	// It does not take the present_ prefix, because it is not a statement about
	// what the artefact contains. Calling it absent would put a coverage gap
	// under the word reserved for an absence.
	PresenceLinkedNotShipped Presence = "linked_not_shipped"

	// PresenceIdentified means native source is compiled in and at least one
	// recipe named the library it belongs to.
	PresenceIdentified Presence = "present_identified"

	// PresenceUnidentified means native source is compiled in and no recipe
	// matched. The record still carries every file, so the gap is legible.
	PresenceUnidentified Presence = "present_unidentified"
)

// Confidence states how a component's version was established. Only a version
// read out of a named declaration in the compiled source is produced today; a
// weaker basis would earn a lower rung rather than being reported as this one.
type Confidence string

// ConfidenceDeclared means the version was read verbatim from the declaration a
// recipe names, inside a source file the build compiles. Nothing was inferred
// from a file name, a path or a version heuristic.
const ConfidenceDeclared Confidence = "declared"

// Evidence is one declaration a recipe matched, and where it was read.
type Evidence struct {
	// File is the path inside the artefact, relative to the module root.
	File string `json:"file"`
	// Declaration is the matched text, verbatim, so a reader can check the
	// claim against the artefact without re-running the tool.
	Declaration string `json:"declaration"`
}

// Component is one third-party native library compiled into the host module.
type Component struct {
	// Name is the library a recipe named — "SQLite", not a module path.
	Name string `json:"name"`
	// Version is what the matched declaration said. Two components with one
	// name and different versions mean the artefact's own sources disagree;
	// both are recorded rather than one being chosen.
	Version    string     `json:"version"`
	Confidence Confidence `json:"confidence"`
	// Evidence holds every declaration that established this name and version.
	Evidence []Evidence `json:"evidence"`
}

// Source is one native file the build compiles, recorded whether or not a
// recipe matched it. It is the file evidence behind PresenceUnidentified and
// the audit trail behind PresenceIdentified.
type Source struct {
	// File is the path inside the artefact, relative to the module root.
	File string `json:"file"`
	// Bytes is the file's uncompressed size.
	Bytes int64 `json:"bytes"`
	// SHA256 is the hex digest of the file's bytes, bare, so the exact source
	// a claim rests on can be re-identified in any copy of the artefact.
	SHA256 string `json:"sha256"`
}

// Record is the persisted result of examining one module artefact for embedded
// native components.
//
// It names the artefact it read, so it inherits that artefact's verification
// status and needs no trust story of its own: the bytes were extracted from a
// zip the fetch ledger already verified.
type Record struct {
	SchemaVersion string `json:"schema_version"`
	// Ecosystem declares the schema's scope; always EcosystemGo.
	Ecosystem  string                      `json:"ecosystem"`
	Coordinate coordinate.ModuleCoordinate `json:"coordinate"`
	// ArtefactIdentity is the blob identity of the module zip these facts were
	// read from. A record that cannot say which bytes it describes is
	// unfalsifiable, so the store refuses one.
	ArtefactIdentity       string `json:"artefact_identity"`
	PipelineVersion        string `json:"pipeline_version"`
	RecipeCatalogueVersion string `json:"recipe_catalogue_version"`

	Presence Presence `json:"presence"`
	// Components is empty for every presence but PresenceIdentified.
	Components []Component `json:"components"`
	// Sources is every native file the build compiles, in canonical order. It
	// is empty exactly when Presence is PresenceAbsent or
	// PresenceLinkedNotShipped.
	Sources []Source `json:"sources"`
	// LinkedLibraries is every library the artefact's cgo directives name as
	// linked, in canonical order, recorded whatever the presence. A module that
	// ships its own sources AND links something else states both, so neither
	// hides the other.
	LinkedLibraries []LinkedLibrary `json:"linked_libraries"`

	ExtractedAt time.Time `json:"extracted_at"`
	ContentHash string    `json:"content_hash"`
}
