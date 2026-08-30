package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	nativeapp "github.com/eitanity/kanonarion/internal/native/application"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/spf13/cobra"
)

// nativeEvidenceResult is one declaration a recipe matched, and the file it was
// read from.
type nativeEvidenceResult struct {
	File        string `json:"file"`
	Declaration string `json:"declaration"`
}

// nativeComponentResult is one third-party native library compiled into the
// host module from source the module itself ships.
type nativeComponentResult struct {
	Name       string                 `json:"name"`
	Version    string                 `json:"version"`
	Confidence string                 `json:"confidence"`
	Evidence   []nativeEvidenceResult `json:"evidence"`
}

// nativeSourceResult is one native file the build compiles, recorded whether or
// not a recipe named what it belongs to.
type nativeSourceResult struct {
	File   string `json:"file"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// nativeLinkedLibraryResult is one native library a cgo directive names as
// linked into the binary, whether or not the artefact ships its source.
type nativeLinkedLibraryResult struct {
	Name string `json:"name"`
	// Kind is "external" or "system". The C runtime every cgo binary links is
	// "system"; everything else, frameworks included, is "external".
	Kind string `json:"kind"`
	// Directive is the verbatim `#cgo` line, so a reader sees the build
	// constraint that governs it without the tool having evaluated one.
	Directive string `json:"directive"`
	File      string `json:"file"`
}

// nativeSection is the machine-readable `native` section. Deterministic: every
// collection is in the record's canonical order and no wall-clock field beyond
// the record's own extracted_at is emitted.
type nativeSection struct {
	SchemaVersion          string `json:"schema_version"`
	Ecosystem              string `json:"ecosystem"`
	PipelineVersion        string `json:"pipeline_version"`
	RecipeCatalogueVersion string `json:"recipe_catalogue_version"`
	Module                 string `json:"module"`
	Version                string `json:"version"`
	ArtefactIdentity       string `json:"artefact_identity"`
	// Presence is "absent", "linked_not_shipped", "present_identified" or
	// "present_unidentified". Only the first is an absence; the other three are
	// spelled differently for that reason.
	Presence        string                      `json:"presence"`
	Statement       string                      `json:"statement"`
	Components      []nativeComponentResult     `json:"components"`
	Sources         []nativeSourceResult        `json:"sources"`
	LinkedLibraries []nativeLinkedLibraryResult `json:"linked_libraries"`
	ExtractedAt     string                      `json:"extracted_at"`
	ContentHash     string                      `json:"content_hash"`
	FromCache       bool                        `json:"from_cache"`
}

// nativeExternalLinks counts the DISTINCT libraries a record names as linked
// from outside the module. Distinct names rather than directives, because one
// library named by five per-platform directives is one library, and the C
// runtime is excluded because every cgo binary links it.
func nativeExternalLinks(rec nativedomain.Record) int {
	seen := map[string]bool{}
	for _, l := range rec.LinkedLibraries {
		if l.Kind == nativedomain.LinkedLibraryExternal {
			seen[l.Name] = true
		}
	}
	return len(seen)
}

// nativeStatement is the one-line answer, stated the same way in both output
// modes so a reader of either sees the same claim — and so "present, and we
// cannot say what it is" can never be read as "nothing is there".
func nativeStatement(rec nativedomain.Record) string {
	switch rec.Presence {
	case nativedomain.PresenceAbsent:
		return "no native source is compiled into a binary from this module's own artefact"
	case nativedomain.PresenceLinkedNotShipped:
		n := nativeExternalLinks(rec)
		noun := "libraries"
		if n == 1 {
			noun = "library"
		}
		return fmt.Sprintf(
			"no native source is compiled in from this artefact; it names %d external native %s it links but does not ship, so no version could be read",
			n, noun)
	case nativedomain.PresenceIdentified:
		return fmt.Sprintf("%d native source file(s) compiled in; %d component(s) identified by declaration",
			len(rec.Sources), len(rec.Components))
	case nativedomain.PresenceUnidentified:
		return fmt.Sprintf("%d native source file(s) compiled in; no recipe names the library they belong to",
			len(rec.Sources))
	default:
		return fmt.Sprintf("unrecognised presence %q", rec.Presence)
	}
}

func toNativeSection(rec nativedomain.Record, fromCache bool) nativeSection {
	out := nativeSection{
		SchemaVersion:          rec.SchemaVersion,
		Ecosystem:              rec.Ecosystem,
		PipelineVersion:        rec.PipelineVersion,
		RecipeCatalogueVersion: rec.RecipeCatalogueVersion,
		Module:                 rec.Coordinate.Path(),
		Version:                rec.Coordinate.Version(),
		ArtefactIdentity:       rec.ArtefactIdentity,
		Presence:               string(rec.Presence),
		Statement:              nativeStatement(rec),
		// Empty (non-nil) slices serialise as [] rather than null, so a
		// consumer iterates uniformly whatever the answer was.
		Components:      []nativeComponentResult{},
		Sources:         []nativeSourceResult{},
		LinkedLibraries: []nativeLinkedLibraryResult{},
		ExtractedAt:     rec.ExtractedAt.UTC().Format(time.RFC3339),
		ContentHash:     rec.ContentHash,
		FromCache:       fromCache,
	}
	for _, c := range rec.Components {
		comp := nativeComponentResult{
			Name:       c.Name,
			Version:    c.Version,
			Confidence: string(c.Confidence),
			Evidence:   []nativeEvidenceResult{},
		}
		for _, e := range c.Evidence {
			comp.Evidence = append(comp.Evidence, nativeEvidenceResult{File: e.File, Declaration: e.Declaration})
		}
		out.Components = append(out.Components, comp)
	}
	for _, s := range rec.Sources {
		out.Sources = append(out.Sources, nativeSourceResult{File: s.File, Bytes: s.Bytes, SHA256: s.SHA256})
	}
	for _, l := range rec.LinkedLibraries {
		out.LinkedLibraries = append(out.LinkedLibraries, nativeLinkedLibraryResult{
			Name: l.Name, Kind: string(l.Kind), Directive: l.Directive, File: l.File,
		})
	}
	return out
}

func newNativeCmd(stdout, stderr io.Writer) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use: "native <module>@<version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentCreate,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Record the third-party native component a cgo module compiles into the binary",
		Long: `native reports the third-party C, C++, Objective-C or Fortran library a Go
module ships in its own published zip and compiles into the binary through cgo.

The facts are read out of the module zip the fetch ledger already verified, so
they inherit that artefact's verification status. Nothing is built and no C
toolchain is invoked.

Four answers are possible, and only the first is an absence:

  absent                 no native source is compiled in and nothing external is linked
  linked_not_shipped     no native source is compiled in, and a cgo directive links an
                         external native library the artefact does not carry
  present_identified     native source is compiled in and a recipe named the library
  present_unidentified   native source is compiled in and no recipe names it

The last two carry the file evidence, and linked_not_shipped names what is
linked. Shipping a .c file is not enough on its own — a module can carry C it
never builds — so a file counts only when it sits in a package directory that
declares cgo with ` + "`import \"C\"`" + `.

Whatever the answer, every library the module's ` + "`#cgo LDFLAGS`" + ` directives name is
listed. A library the host provides cannot be resolved from an artefact, so no
version is read for it and none is invented; the C runtime every cgo binary
links is marked "system" so it never inflates the external count.

A version is read from the declaration a per-library recipe names, verbatim.
Nothing is inferred from a file name, a path or a version heuristic.`,
		Example: `  kanonarion native github.com/mattn/go-sqlite3@v1.14.12
  kanonarion native github.com/mattn/go-sqlite3@v1.14.12 --json
  kanonarion native github.com/mattn/go-sqlite3@v1.14.12 --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			return runNative(cmd.Context(), args[0], force, stdout, stderr)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "re-measure even if a record for this generation is held")
	return cmd
}

func runNative(ctx context.Context, arg string, force bool, stdout, stderr io.Writer) error {
	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	result, err := ctr.ExtractNative.Execute(ctx, nativeapp.ExtractRequest{Coordinate: coord, Force: force})
	if err != nil {
		return fmt.Errorf("measuring native components: %w", err)
	}

	section := toNativeSection(result.Record, result.FromCache)
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(section); err != nil {
			return fmt.Errorf("encoding native section: %w", err)
		}
		return nil
	}
	return printNativeTable(stdout, section)
}

// printNativeLinkedLibraries lists what the cgo directives name as linked. It
// prints for every presence, so a module that ships its own sources AND links
// something else states both.
func printNativeLinkedLibraries(stdout io.Writer, s nativeSection) error {
	if len(s.LinkedLibraries) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "\nLinked libraries named by cgo directives (%d)\n", len(s.LinkedLibraries)); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "LIBRARY\tKIND\tFILE\tDIRECTIVE"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	for _, l := range s.LinkedLibraries {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", l.Name, l.Kind, l.File, l.Directive); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flushing output: %w", err)
	}
	return nil
}

func printNativeTable(stdout io.Writer, s nativeSection) error {
	if _, err := fmt.Fprintf(stdout,
		"Module:     %s@%s\nArtefact:   %s\nGeneration: %s+recipes.%s\nPresence:   %s\nStatement:  %s\n",
		s.Module, s.Version, s.ArtefactIdentity,
		s.PipelineVersion, s.RecipeCatalogueVersion, s.Presence, s.Statement); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if len(s.Sources) == 0 {
		return printNativeLinkedLibraries(stdout, s)
	}

	if len(s.Components) > 0 {
		if _, err := fmt.Fprintln(stdout, "\nComponents"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "COMPONENT\tVERSION\tCONFIDENCE\tEVIDENCE"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		for _, c := range s.Components {
			for i, e := range c.Evidence {
				name, version, confidence := c.Name, c.Version, c.Confidence
				if i > 0 {
					name, version, confidence = "", "", ""
				}
				if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s: %s\n",
					name, version, confidence, e.File, e.Declaration); err != nil {
					return fmt.Errorf("writing output: %w", err)
				}
			}
		}
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("flushing output: %w", err)
		}
	}

	if _, err := fmt.Fprintf(stdout, "\nNative sources compiled into the binary (%d)\n", len(s.Sources)); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "FILE\tBYTES\tSHA256"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	for _, src := range s.Sources {
		if _, err := fmt.Fprintf(tw, "%s\t%d\t%s\n", src.File, src.Bytes, src.SHA256); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flushing output: %w", err)
	}
	return printNativeLinkedLibraries(stdout, s)
}
