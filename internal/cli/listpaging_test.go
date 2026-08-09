package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The defect this file pins: every listing took --limit and only one took
// --offset, so a caller told "more exist" could ask for the first N or for all
// of them and nothing in between. Reading records 51-100 of 635 meant fetching
// all 635 and slicing client-side — the second read the truncation statement
// was designed not to pay.
//
// Paging is only meaningful over a total, deterministic ordering: page 2 is the
// rows page 1 did not show only if two calls order the population the same way.
// Every listing paged here orders on a timestamp with the row's primary key as
// tiebreak, so the ordering is total; the disjoint-pages test below is what
// asserts it rather than assuming it.

// jsonRows returns the listing payload's rows as raw JSON, so two invocations
// can be compared row for row rather than by a count that would pass on the
// wrong rows.
func jsonRows(t *testing.T, stdout string) []string {
	t.Helper()
	var rows []json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("decoding listing payload: %v\npayload: %s", err, stdout)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, string(r))
	}
	return out
}

// --limit N --offset M returns rows M+1..M+N of the ordering the unpaged
// listing produces, verified against a slice of the --limit 0 output rather
// than against the paged call's own idea of what it returned.
func TestListings_OffsetReturnsTheSameRowsTheFullListingHoldsThere(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			full := jsonRows(t, mustStdout(t, s, 0, 0))
			if len(full) != s.population {
				t.Fatalf("--limit 0 returned %d rows, want the whole population %d", len(full), s.population)
			}
			const limit, offset = 2, 2
			page := jsonRows(t, mustStdout(t, s, limit, offset))
			want := full[offset : offset+limit]
			if len(page) != len(want) {
				t.Fatalf("page holds %d rows, want %d", len(page), len(want))
			}
			for i := range want {
				if page[i] != want[i] {
					t.Errorf("row %d of --limit %d --offset %d is not row %d of the full listing\n got: %s\nwant: %s",
						i, limit, offset, offset+i, page[i], want[i])
				}
			}
		})
	}
}

// Paging to the end and one page past it. The last partial page has withheld
// nothing and must not claim to; the page past the population is empty rather
// than an error, and says nothing about truncation either.
func TestListings_LastPageAndPastItClaimNoTruncation(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			// population 5, limit 3: the second page holds the remaining 2.
			last, _ := s.run(t, 3, 3, false)
			if strings.Contains(last, "more exist") {
				t.Errorf("the last partial page claimed more rows exist:\n%s", last)
			}
			lastJSON, _ := s.run(t, 3, 3, true)
			if got := len(jsonRows(t, lastJSON)); got != s.population-3 {
				t.Errorf("last page holds %d rows, want %d", got, s.population-3)
			}

			past, _ := s.run(t, 3, s.population+5, false)
			if strings.Contains(past, "more exist") {
				t.Errorf("a page past the population claimed more rows exist:\n%s", past)
			}
			pastJSON, _ := s.run(t, 3, s.population+5, true)
			if got := len(jsonRows(t, pastJSON)); got != 0 {
				t.Errorf("a page past the population returned %d rows, want none", got)
			}
		})
	}
}

// Consecutive pages are disjoint and together are the whole population. This is
// the property an offset over a non-total ordering silently breaks: a page
// boundary falling inside a group of rows that compare equal can repeat one row
// and drop another, and the row counts still look right.
func TestListings_ConsecutivePagesArePartitions(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			seen := make(map[string]int, s.population)
			var order []string
			const pageSize = 2
			for offset := 0; offset < s.population; offset += pageSize {
				for _, row := range jsonRows(t, mustStdout(t, s, pageSize, offset)) {
					seen[row]++
					order = append(order, row)
				}
			}
			if len(order) != s.population {
				t.Fatalf("paging the whole population returned %d rows, want %d", len(order), s.population)
			}
			for row, n := range seen {
				if n != 1 {
					t.Errorf("row appeared on %d pages, want exactly 1: %s", n, row)
				}
			}
			full := jsonRows(t, mustStdout(t, s, 0, 0))
			for i := range full {
				if order[i] != full[i] {
					t.Errorf("paged row %d differs from the unpaged listing\n got: %s\nwant: %s", i, order[i], full[i])
				}
			}
		})
	}
}

// The truncation statement is a remedy a caller can act on: it names the next
// page as well as the whole population, and a page that did not start at the
// beginning says which rows it is showing rather than calling them the first N.
func TestListings_TruncationLineOffersTheNextPage(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			first, _ := s.run(t, 2, 0, false)
			if want := "--offset 2 for the next page"; !strings.Contains(first, want) {
				t.Errorf("the first page does not name the next one (%q):\n%s", want, first)
			}
			second, _ := s.run(t, 2, 2, false)
			if want := fmt.Sprintf("showing %s 3-4", s.subject); !strings.Contains(second, want) {
				t.Errorf("a mid-population page does not name its range (%q):\n%s", want, second)
			}
			if strings.Contains(second, "showing first") {
				t.Errorf("a page starting at offset 2 described itself as the first rows:\n%s", second)
			}
			_, stderr := s.run(t, 2, 2, true)
			var marker listTruncationJSON
			if err := json.Unmarshal([]byte(stderr), &marker); err != nil {
				t.Fatalf("no truncation marker on stderr: %v\nstderr: %q", err, stderr)
			}
			if marker.Offset != 2 || marker.NextOffset != 4 {
				t.Errorf("marker offset/next = %d/%d, want 2/4: %+v", marker.Offset, marker.NextOffset, marker)
			}
		})
	}
}

// The zero-paired control. --offset 0 is the flag's own default, so an
// invocation that passes it must be byte-identical to one that does not — on
// both output paths, rows and scope statement alike. A paging implementation
// that reordered, re-fetched or re-worded anything at offset zero would change
// the output of every existing caller, none of whom asked for paging.
func TestListings_OffsetZeroIsByteIdenticalToNoOffset(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			for _, asJSON := range []bool{false, true} {
				noOffsetOut, noOffsetErr := s.run(t, 3, offsetFlagDefault(t, s.name), asJSON)
				zeroOut, zeroErr := s.run(t, 3, 0, asJSON)
				if noOffsetOut != zeroOut || noOffsetErr != zeroErr {
					t.Errorf("--offset 0 differs from the flag default (json=%v)\nstdout: %q vs %q\nstderr: %q vs %q",
						asJSON, zeroOut, noOffsetOut, zeroErr, noOffsetErr)
				}
			}
		})
	}
}

// mustStdout runs a listing on the JSON path and returns stdout alone.
func mustStdout(t *testing.T, s listingSurface, limit, offset int) string {
	t.Helper()
	stdout, _ := s.run(t, limit, offset, true)
	return stdout
}

// offsetFlagDefault reads the default the command's own --offset flag carries,
// so "no --offset given" is taken from the CLI rather than assumed to be zero.
func offsetFlagDefault(t *testing.T, command string) int {
	t.Helper()
	cmd, ok := findListingCommand(t, command)
	if !ok {
		t.Fatalf("no command named %q in the CLI", command)
	}
	f := cmd.Flags().Lookup("offset")
	if f == nil {
		t.Fatalf("%s registers no --offset flag", command)
	}
	var n int
	if _, err := fmt.Sscanf(f.DefValue, "%d", &n); err != nil {
		t.Fatalf("--offset default %q on %s is not a number: %v", f.DefValue, command, err)
	}
	return n
}

// findListingCommand locates a command by the space-separated path the listing
// surfaces name it with ("extract list", "directives list").
func findListingCommand(t *testing.T, path string) (*cobra.Command, bool) {
	t.Helper()
	cmd := newRootCmd(io.Discard, io.Discard)
	for _, name := range strings.Fields(path) {
		next, ok := childCommand(cmd, name)
		if !ok {
			return nil, false
		}
		cmd = next
	}
	return cmd, true
}

func childCommand(parent *cobra.Command, name string) (*cobra.Command, bool) {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c, true
		}
	}
	return nil, false
}

// The adjacent-fuzz sweep: every command in the CLI that caps its rows also
// lets a caller step past the cap. It walks the whole command tree rather than
// a list of the commands that were measured, so a listing added later cannot
// ship with one flag and not the other.
func TestCLI_EveryLimitBearingCommandAlsoTakesOffset(t *testing.T) {
	var walk func(cmd *cobra.Command)
	checked := 0
	walk = func(cmd *cobra.Command) {
		if cmd.Flags().Lookup("limit") != nil {
			checked++
			path := strings.TrimPrefix(cmd.CommandPath(), "kanonarion ")
			off := cmd.Flags().Lookup("offset")
			switch {
			case off == nil:
				t.Errorf("%s caps its rows with --limit and offers no --offset, so a caller can only re-fetch from the top", path)
			case off.DefValue != "0":
				t.Errorf("%s has --offset default %q, want 0: paging must be off unless it is asked for", path, off.DefValue)
			case off.Value.Type() != "int":
				t.Errorf("%s has --offset of type %s, want int", path, off.Value.Type())
			}
		}
		for _, c := range cmd.Commands() {
			walk(c)
		}
	}
	walk(newRootCmd(io.Discard, io.Discard))
	// The count is asserted so the sweep cannot pass by finding nothing: nine
	// commands cap their rows — eight record listings and `store ledger`.
	if checked < 9 {
		t.Errorf("the sweep found %d commands taking --limit, want at least the 9 measured", checked)
	}
}
