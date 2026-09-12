package cmd_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// widenedStampColumns are the ledger timestamp columns that hold two
// generations of encoding: a whole second on rows written before the stamp was
// widened, a fixed-width nine-digit fraction after. Both live in the column —
// append-only evidence is not rewritten.
//
// SQLite compares TEXT lexicographically, and inside a shared second the
// fractional spelling sorts FIRST: '.' is 0x2E and 'Z' is 0x5A. So over these
// columns a bare MAX returns the EARLIER instant and a bare MIN the LATER one.
//
// Columns on ledgers that were NOT widened are deliberately absent. Their rows
// stay uniform, so text order is still chronological order there and wrapping
// them would be cost with no correction behind it.
var widenedStampColumns = map[string]string{
	"extracted_at":     "callgraph and licence records",
	"scanned_at":       "vulnerability records",
	"first_scanned_at": "the vulnerability record first-seen anchor",
	"started_at":       "walks and walk scan runs",
	"completed_at":     "walks and walk scan runs",
	"fetched_at":       "fetch records",
}

// TestNoBareAggregateOverAWidenedStamp guards the half of the timestamp defect
// family that lives in the SELECT list rather than in ORDER BY.
//
// Converting the orderings and leaving the aggregates is the shape this exists
// to catch: one query ordered on the parsed time while still SELECTING
// MAX(scanned_at), so the value a generation reported as its latest scan
// disagreed with the order the rows came back in. MIN and MAX collapse the rows
// and have no rowid beneath them to fall back on, so the comparison has to be
// right in the aggregate itself — sqlitestore.SortableStamp.
//
// It reads string literals only. The rule is discussed at length in the store
// adapters, and a text search would report the discussion as the defect.
func TestNoBareAggregateOverAWidenedStamp(t *testing.T) {
	files, literals := 0, 0
	seen := map[string]bool{}
	err := filepath.Walk("../internal", func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return fmt.Errorf("walk %s: %w", path, werr)
		}
		if info.IsDir() {
			if info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parsing %s: %w", path, perr)
		}
		files++
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			literals++
			for col := range widenedStampColumns {
				if mentionsColumn(value, col) {
					seen[col] = true
				}
			}
			for _, defect := range bareStampAggregates(value) {
				pos := fset.Position(lit.Pos())
				t.Errorf("%s:%d aggregates a widened timestamp as text (%s, %s) — the column holds a "+
					"whole second and a fixed-width fraction, and \"…53.9Z\" sorts BEFORE \"…53Z\", so "+
					"MAX returns the earlier instant and MIN the later one. Wrap the column in "+
					"sqlitestore.SortableStamp",
					strings.TrimPrefix(filepath.ToSlash(path), "../"), pos.Line,
					defect.expr, widenedStampColumns[defect.column])
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking ../internal: %v", err)
	}
	if files == 0 || literals == 0 {
		t.Fatalf("read %d files and %d string literals: the guard would pass vacuously", files, literals)
	}
	// The column list drains as the tree moves: an entry naming a column no SQL
	// mentions any more exempts nothing while reading as a live decision.
	var stale []string
	for col := range widenedStampColumns {
		if !seen[col] {
			stale = append(stale, col)
		}
	}
	sort.Strings(stale)
	for _, col := range stale {
		t.Errorf("widenedStampColumns names %q (%s), which no SQL in the tree mentions any more — remove the entry",
			col, widenedStampColumns[col])
	}
}

// TestStampAggregateGuardCatchesAPlantedAggregate is the control: without it the
// guard above could pass because it detects nothing at all.
func TestStampAggregateGuardCatchesAPlantedAggregate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		want  bool
	}{
		{"the census oversight", "SELECT pipeline_version, MAX(scanned_at) FROM t GROUP BY 1", true},
		{"lower case", "select max(scanned_at) from t", true},
		{"the anchor", "SELECT MIN(first_scanned_at) FROM t", true},
		{"whitespace padded", "SELECT MAX( extracted_at ) FROM t", true},
		{"table qualified", "SELECT MAX(vr.scanned_at) FROM vulnerability_records vr", true},
		{"in an ORDER BY", "SELECT a FROM t GROUP BY b ORDER BY MAX(started_at) DESC", true},
		{"in a correlated subquery", "WHERE x = (SELECT MAX(completed_at) FROM walks w2)", true},

		{"wrapped in julianday", "SELECT a FROM t ORDER BY MAX(julianday(scanned_at)) DESC", false},
		{"wrapped in the fixed-width case", "SELECT MAX(CASE WHEN length(scanned_at) > 20 THEN scanned_at ELSE substr(scanned_at, 1, 19) || '.000000000Z' END) FROM t", false},
		{"a column on a ledger that was not widened", "SELECT MAX(acquired_at) FROM stdlib_facts", false},
		{"counting is not comparing", "SELECT COUNT(scanned_at) FROM t", false},
		{"summing another column", "SELECT MAX(node_count) FROM t", false},
		{"plain selection", "SELECT scanned_at FROM t", false},
		{"not SQL at all", "the scanned_at column, and MAX( is not closed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(bareStampAggregates(tc.query)) > 0; got != tc.want {
				t.Errorf("detector reported %v for %q, want %v", got, tc.query, tc.want)
			}
		})
	}
}

type stampAggregate struct{ expr, column string }

// bareStampAggregates names every MIN or MAX in one SQL string whose whole
// argument is a widened timestamp column, table qualifier and all. An argument
// that is any other expression — julianday(...), the fixed-width CASE — has
// already been normalised and is not reported.
func bareStampAggregates(query string) []stampAggregate {
	lower := strings.ToLower(query)
	var found []stampAggregate
	for _, agg := range []string{"max(", "min("} {
		from := 0
		for {
			i := strings.Index(lower[from:], agg)
			if i < 0 {
				break
			}
			i += from
			arg, end, ok := parenArgument(lower, i+len(agg)-1)
			from = i + len(agg)
			if !ok {
				continue
			}
			from = end
			arg = strings.TrimSpace(arg)
			column := arg
			if _, after, qualified := strings.Cut(arg, "."); qualified {
				column = after
			}
			if _, widened := widenedStampColumns[column]; widened {
				found = append(found, stampAggregate{
					expr:   strings.ToUpper(strings.TrimSuffix(agg, "(")) + "(" + arg + ")",
					column: column,
				})
			}
		}
	}
	return found
}

// parenArgument returns the text between the parenthesis at open and its match,
// and the index just past the closing one.
func parenArgument(s string, open int) (arg string, end int, ok bool) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], i + 1, true
			}
		}
	}
	return "", 0, false
}

// mentionsColumn reports whether one SQL string names col as a whole word, which
// is what keeps widenedStampColumns from going stale.
func mentionsColumn(query, col string) bool {
	from := 0
	for {
		i := strings.Index(query[from:], col)
		if i < 0 {
			return false
		}
		i += from
		from = i + len(col)
		before := byte(' ')
		if i > 0 {
			before = query[i-1]
		}
		after := byte(' ')
		if end := i + len(col); end < len(query) {
			after = query[end]
		}
		if !isWordByte(before) && !isWordByte(after) {
			return true
		}
	}
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
