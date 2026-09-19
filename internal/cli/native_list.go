package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	nativeports "github.com/eitanity/kanonarion/internal/native/ports"
	"github.com/spf13/cobra"
)

// This file is the bulk read of the native fact: which of a store's modules
// ship or link native code, answered once instead of once per module.
//
// A "native record" is what `kanonarion native <module>@<version>` writes: the
// third-party C, C++, Objective-C or Fortran library a Go module compiles into
// the binary from source it ships, and the libraries its cgo directives name as
// linked. The fact is four-valued and only one of the four is an absence, so a
// store of a few hundred records holds a handful that report something. Finding
// them meant invoking the single-module command once per module and collating.

// nativeRecordLister is the survey this listing needs. It is an interface so
// the paging, the filter and the zero-result notice are exercisable without a
// live store.
type nativeRecordLister interface {
	List(ctx context.Context, filter nativeports.NativeFilter) ([]nativeports.NativeSummary, error)
}

// nativeListComponent is one identified native library on a listed row.
type nativeListComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Confidence is how the version was established; "declared" means it was
	// read verbatim from a named declaration in compiled source.
	Confidence string `json:"confidence"`
}

// nativeListEntry is one row of `native-list --json`.
//
// Presence is the field the listing exists to filter on, so it is on the row
// rather than implied by which rows came back. Components and LinkedLibraries
// are named rather than counted, because "which of my dependencies ship or link
// native code" is not answered by a number.
type nativeListEntry struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	// Presence is "absent", "linked_not_shipped", "present_identified" or
	// "present_unidentified". Only the first is an absence.
	Presence string `json:"presence"`
	// Generation is the detection generation the record was taken at, and
	// Superseded says this build does not serve it. Both halves are emitted on
	// every row, including the rows where Superseded is false: a consumer
	// reading only the true ones could not tell a servable record from one the
	// pair was never computed for.
	Generation string `json:"generation"`
	Superseded bool   `json:"superseded"`
	// ArtefactIdentity is the verified module zip the measurement read.
	ArtefactIdentity string `json:"artefact_identity"`
	// Components is empty at every presence but present_identified, and
	// LinkedLibraries is the distinct external libraries the cgo directives
	// name. Both are arrays at every count, never null.
	Components      []nativeListComponent `json:"components"`
	LinkedLibraries []string              `json:"linked_libraries"`
	// SourceCount is how many native files the build compiles from this
	// artefact. Zero at absent and at linked_not_shipped, where it is a measured
	// zero rather than a missing figure.
	SourceCount int    `json:"source_count"`
	ExtractedAt string `json:"extracted_at"`
	ContentHash string `json:"content_hash"`
	// Conflict is set only when the store holds another record describing a
	// different artefact for this coordinate at this generation. The two
	// disagree about what the version's bytes are, and the single-module command
	// refuses to answer for it.
	Conflict string `json:"conflict,omitempty"`
}

func newNativeListCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		limit, offset  int
		presence       []string
		allGenerations bool
	)

	cmd := &cobra.Command{
		Use: "native-list",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "List the modules examined for native code, filterable by what was found",
		Long: `native-list reads back the records 'kanonarion native' writes, so the question
the fact exists to answer can be asked of a whole store at once: which of my
dependencies ship or link a third-party C library.

Four presences are possible and only the first is an absence:

  absent                 no native source is compiled in and nothing external is linked
  linked_not_shipped     no native source is compiled in, and a cgo directive links an
                         external native library the artefact does not carry
  present_identified     native source is compiled in and a recipe named the library
  present_unidentified   native source is compiled in and no recipe names it

--presence takes one or more of those four, comma-separated or repeated, and a
record matching any of them is listed. The three that are not "absent" are the
answer to "which of my dependencies ship or link native code":

  kanonarion native-list --presence linked_not_shipped,present_identified,present_unidentified

A value outside the four is refused rather than matched, because in a list it
would otherwise narrow the answer in silence.

By default only records taken at the generation this build serves are listed. A
record from an earlier detection generation answers no query — it was measured
by logic this build has replaced — so listing it beside the others would pad the
count of what is known with rows that cannot answer. --all-generations includes
them and marks each one.`,
		Example: `  kanonarion native-list
  kanonarion native-list --presence present_identified
  kanonarion native-list --presence linked_not_shipped,present_identified,present_unidentified
  kanonarion native-list --presence linked_not_shipped --json
  kanonarion native-list --limit 0
  kanonarion native-list --all-generations`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			values, verr := nativePresenceFilter(presence)
			if verr != nil {
				return verr
			}
			return runNativeList(cmd.Context(), nativeListFlags{
				limit: limit, offset: offset,
				presence: values, allGenerations: allGenerations,
			}, stdout, stderr)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of records to return (0 = unlimited)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many records")
	cmd.Flags().StringSliceVar(&presence, "presence", nil,
		"list only records with one of these presences (comma-separated): absent, linked_not_shipped, present_identified, present_unidentified")
	cmd.Flags().BoolVar(&allGenerations, "all-generations", false,
		"also list records taken at a superseded detection generation, which this build does not serve")

	return cmd
}

// nativeListFlags is one invocation's request.
type nativeListFlags struct {
	limit, offset  int
	presence       []string
	allGenerations bool
}

// filter renders the request as the store's filter, over-fetching one row so
// the listing can say whether the limit bit without a second read.
func (f nativeListFlags) filter() nativeports.NativeFilter {
	return nativeports.NativeFilter{
		Presence:       f.presence,
		AllGenerations: f.allGenerations,
		Limit:          truncationFetchLimit(f.limit),
		Offset:         f.offset,
	}
}

// subject names the listing's rows in the reader's terms, and states which
// generation they were drawn from.
//
// The generation is in the subject rather than in a field of its own so the
// listing document keeps exactly the key set every other listing on this store
// emits, and a reader of the truncation line is told the scope of the rows it
// is describing in the same sentence.
func (f nativeListFlags) subject() string {
	if f.allGenerations {
		return "native records at every generation"
	}
	return "native records at generation " + nativedomain.PipelineFingerprint()
}

func runNativeList(ctx context.Context, f nativeListFlags, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return nativeListWith(ctx, f, ctr.QueryNative, stdout, stderr)
}

// nativeListWith holds the listing over an injected use case.
func nativeListWith(ctx context.Context, f nativeListFlags, uc nativeRecordLister, stdout, stderr io.Writer) error {
	sums, err := uc.List(ctx, f.filter())
	if err != nil {
		return fmt.Errorf("listing native records: %w", err)
	}
	// The corpus is measured only when the page came back empty: it is the read
	// the notice is built from, and a listing that returned rows never pays it.
	var zero listZeroScope
	if len(sums) == 0 {
		zero, err = nativeListZeroScope(ctx, f, uc)
		if err != nil {
			return err
		}
	}
	return printNativeList(sums, f, zero, stdout, stderr)
}

// nativeListZeroScope lifts the filter and re-asks the store, so a zero says
// which of three things happened: the store holds no native record at this
// generation, the presence filter matched none of the records it does hold, or
// the page simply starts past the last one.
func nativeListZeroScope(ctx context.Context, f nativeListFlags, uc nativeRecordLister) (listZeroScope, error) {
	all, err := uc.List(ctx, nativeports.NativeFilter{AllGenerations: f.allGenerations})
	if err != nil {
		return listZeroScope{}, fmt.Errorf("counting native records for the zero-result notice: %w", err)
	}
	scope := listZeroScope{
		subject:    "native record",
		considered: len(all),
		produce:    "kanonarion native <module>@<version>",
		listAll:    "kanonarion native-list",
	}
	if len(f.presence) > 0 {
		scope.filterName = "presence"
		scope.filterValue = strings.Join(f.presence, ",")
		scope.field = "presence"
		scope.matchKind = matchExact
		// The example is every presence the corpus actually holds, not one of
		// them: the filter's whole vocabulary is four values, and a reader who
		// mistyped one learns more from the set than from a single sample.
		scope.example = strings.Join(nativePresencesHeld(all), ", ")
	}
	// An offset past the end empties the page while records are there to be
	// listed, and the two are the same zero rows from the caller's side. An
	// empty corpus is not something a page can start past, so a zero over it
	// keeps the store-empty statement and its produce-a-record remedy.
	//
	// The count the offset is measured against is the count the FILTER matched,
	// not the corpus. A filter that matched two rows and a page starting at the
	// fifth is a paging zero, and reporting it as "no record matched" would be
	// false about a filter that matched twice.
	matched := nativeMatching(all, f.presence)
	if len(matched) > 0 && f.offset > 0 && f.offset >= len(matched) {
		scope.pagedPast = fmt.Sprintf("--offset %d starts past the last one", f.offset)
		if len(f.presence) > 0 {
			scope.pagedPast = fmt.Sprintf("--offset %d starts past the last of the %d matching presence %q",
				f.offset, len(matched), strings.Join(f.presence, ","))
		}
	}
	return scope, nil
}

// nativeMatching returns the records a presence filter would keep. It filters
// the corpus already in hand rather than asking the store again: the corpus is
// the same rows the filter would have been applied to, so a second read could
// only differ by being taken at a different moment.
func nativeMatching(sums []nativeports.NativeSummary, presence []string) []nativeports.NativeSummary {
	if len(presence) == 0 {
		return sums
	}
	want := map[string]bool{}
	for _, p := range presence {
		want[p] = true
	}
	out := make([]nativeports.NativeSummary, 0, len(sums))
	for _, s := range sums {
		if want[string(s.Presence)] {
			out = append(out, s)
		}
	}
	return out
}

// nativePresences is the vocabulary --presence accepts, in the order the
// command's own help and docs/cli/native.md already list the four: the one
// absence first, then the three that are not.
var nativePresences = []nativedomain.Presence{
	nativedomain.PresenceAbsent,
	nativedomain.PresenceLinkedNotShipped,
	nativedomain.PresenceIdentified,
	nativedomain.PresenceUnidentified,
}

// nativePresenceFilter validates the values a caller gave --presence.
//
// An unrecognised value is refused rather than passed through to match nothing.
// On a single-value filter a zero result would at least be visible; in a list
// it would not — two good values and one typo returns rows, and the rows the
// typo should have added are missing with nothing in the output to say so.
func nativePresenceFilter(values []string) ([]string, error) {
	known := map[string]bool{}
	names := make([]string, 0, len(nativePresences))
	for _, p := range nativePresences {
		known[string(p)] = true
		names = append(names, string(p))
	}
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !known[v] {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf(
				"--presence %q is not a presence a native record can hold; it accepts one or more of: %s",
				v, strings.Join(names, ", "))}
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}

// nativePresencesHeld returns the distinct presence values in a corpus, in the
// order the four are defined rather than alphabetically, so the reader sees
// them from absence to identified component.
func nativePresencesHeld(sums []nativeports.NativeSummary) []string {
	held := map[nativedomain.Presence]bool{}
	for _, s := range sums {
		held[s.Presence] = true
	}
	out := []string{}
	for _, p := range nativePresences {
		if held[p] {
			out = append(out, string(p))
		}
		delete(held, p)
	}
	// A presence this build does not recognise is still listed, at the end. It
	// is a value the store holds, and omitting it would teach a vocabulary the
	// store contradicts.
	for p := range held {
		out = append(out, string(p))
	}
	return out
}

// toNativeListEntry projects one summary into the row both output modes carry.
func toNativeListEntry(s nativeports.NativeSummary) nativeListEntry {
	entry := nativeListEntry{
		Module:           s.Coordinate.Path(),
		Version:          s.Coordinate.Version(),
		Presence:         string(s.Presence),
		Generation:       s.Generation,
		Superseded:       s.Generation != nativedomain.PipelineFingerprint(),
		ArtefactIdentity: s.ArtefactIdentity,
		Components:       []nativeListComponent{},
		LinkedLibraries:  []string{},
		SourceCount:      s.SourceCount,
		ExtractedAt:      s.ExtractedAt.UTC().Format(time.RFC3339),
		ContentHash:      s.ContentHash,
	}
	for _, c := range s.Components {
		entry.Components = append(entry.Components, nativeListComponent{
			Name: c.Name, Version: c.Version, Confidence: string(c.Confidence),
		})
	}
	entry.LinkedLibraries = append(entry.LinkedLibraries, s.LinkedExternal...)
	if s.Conflict != nil {
		entry.Conflict = s.Conflict.Error()
	}
	return entry
}

// nativeListDetail is the row's right-hand column on the text path: what was
// found, in the fewest words that still name it.
//
// A row with nothing to report prints the em dash rather than an empty cell, so
// a measured absence is visibly an answer.
func nativeListDetail(e nativeListEntry) string {
	var parts []string
	if e.SourceCount > 0 {
		parts = append(parts, fmt.Sprintf("%d native source file(s)", e.SourceCount))
	}
	for _, c := range e.Components {
		parts = append(parts, c.Name+" "+c.Version)
	}
	if len(e.LinkedLibraries) > 0 {
		parts = append(parts, "links "+strings.Join(e.LinkedLibraries, ", "))
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "; ")
}

// printNativeList renders the page in whichever mode was asked for.
//
// A disputed coordinate is printed on its own row and the command fails
// afterwards: every record is listed first, so one coordinate in dispute does
// not delete the answers for all the others, and the run still does not read as
// clean.
func printNativeList(sums []nativeports.NativeSummary, f nativeListFlags, zero listZeroScope, stdout, stderr io.Writer) error {
	sums, truncated := truncateList(sums, f.limit)
	trunc := listTruncation{limit: f.limit, subject: f.subject(), truncated: truncated, offset: f.offset}

	entries := make([]nativeListEntry, 0, len(sums))
	var conflicts []error
	for _, s := range sums {
		entries = append(entries, toNativeListEntry(s))
		if s.Conflict != nil {
			conflicts = append(conflicts, s.Conflict)
		}
	}

	if jsonOut {
		var empty *listZeroScope
		if len(entries) == 0 {
			empty = &zero
		}
		if derr := writeListDocument(stdout, entries, trunc, empty); derr != nil {
			return derr
		}
		return nativeListConflictErr(conflicts)
	}

	if len(entries) == 0 {
		return writeListZeroNotice(stdout, zero)
	}
	if perr := printNativeListRows(stdout, entries); perr != nil {
		return perr
	}
	if gerr := writeNativeListGenerationNotice(stdout, f, entries); gerr != nil {
		return gerr
	}
	if terr := writeListTruncationNotice(stdout, trunc); terr != nil {
		return terr
	}
	return nativeListConflictErr(conflicts)
}

// printNativeListRows writes the rows themselves.
func printNativeListRows(stdout io.Writer, entries []nativeListEntry) error {
	for _, e := range entries {
		mark := ""
		if e.Superseded {
			mark = "  [superseded generation " + e.Generation + "]"
		}
		if e.Conflict != "" {
			mark = "  [CONFLICT: " + e.Conflict + "]"
		}
		if _, err := fmt.Fprintf(stdout, "%-55s %-22s %s%s\n",
			e.Module+"@"+e.Version, e.Presence, nativeListDetail(e), mark); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}

// writeNativeListGenerationNotice states which generation the rows were drawn
// from.
//
// It prints on every listing, not only when something was excluded. A count of
// native records is read as a count of what is known about a build, and a
// reader who is not told the rows were restricted to one generation has no way
// to tell a restricted count from a whole one.
func writeNativeListGenerationNotice(stdout io.Writer, f nativeListFlags, entries []nativeListEntry) error {
	if !f.allGenerations {
		_, err := fmt.Fprintf(stdout,
			"listing native records at generation %s, the generation this build serves; "+
				"records from a superseded generation are not shown (--all-generations)\n",
			nativedomain.PipelineFingerprint())
		if err != nil {
			return fmt.Errorf("writing generation notice: %w", err)
		}
		return nil
	}
	superseded := 0
	for _, e := range entries {
		if e.Superseded {
			superseded++
		}
	}
	if superseded == 0 {
		return nil
	}
	_, err := fmt.Fprintf(stdout,
		"%d of %d listed record(s) were taken at a superseded detection generation; this build serves %s "+
			"and answers no query from them. Re-measure one:\n  kanonarion native <module>@<version>\n",
		superseded, len(entries), nativedomain.PipelineFingerprint())
	if err != nil {
		return fmt.Errorf("writing superseded notice: %w", err)
	}
	return nil
}

// nativeListConflictErr fails the run when the page held a disputed coordinate.
// The rows are already out; a store that holds two measurements of one pinned
// version must not be reported as a clean read.
func nativeListConflictErr(conflicts []error) error {
	if len(conflicts) == 0 {
		return nil
	}
	return fmt.Errorf("%d listed native record(s) describe a coordinate the store holds two measurements of: %w",
		len(conflicts), errors.Join(conflicts...))
}
