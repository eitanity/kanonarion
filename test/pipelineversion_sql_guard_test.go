package cmd_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoSQLOrdersOrSelectsAPipelineVersionAsText guards the defect family in
// which a pipeline version — "v19" on the vuln and sbom ledgers, "0.4.1" on the
// callgraph, vendor and directive ones — is ordered or aggregated by SQLite,
// which compares a TEXT column as text.
//
// Text order inverts against generation order at every digit-count boundary:
// MAX over v9 and v19 returns v9, and the vuln pipeline reaches the unavoidable
// v99/v100 boundary on its own timeline. A newest-wins selection built on that
// serves a superseded generation while reporting it as the current one, and an
// ORDER BY built on it presents a census in an order that reads as a sequence
// and is not one.
//
// So SQL never orders or aggregates the column: the rows are read and the
// ordering happens in Go, against versionorder.ComparePipelineVersions, which
// reads the number. This regrew from an idiom once, which is why the guard is
// structural rather than a note in a handover.
func TestNoSQLOrdersOrSelectsAPipelineVersionAsText(t *testing.T) {
	files := 0
	literals := 0
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
			// Only string literals, never comments: this rule is discussed at
			// length in the store adapters, and a text search would report the
			// discussion as the defect.
			value, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			literals++
			for _, defect := range pipelineVersionTextOrderings(value) {
				pos := fset.Position(lit.Pos())
				t.Errorf("%s:%d orders a pipeline version in SQL (%s) — SQLite compares the column as "+
					"text, so v9 outranks v19 and 0.10.0 sorts below 0.9.0. Read the rows and order "+
					"them in Go with versionorder.ComparePipelineVersions",
					strings.TrimPrefix(filepath.ToSlash(path), "../"), pos.Line, defect)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking ../internal: %v", err)
	}
	// A guard that read nothing passes by finding nothing.
	if files == 0 || literals == 0 {
		t.Fatalf("read %d files and %d string literals: the guard would pass vacuously", files, literals)
	}
}

// TestPipelineVersionGuardCatchesAPlantedOrdering is the control: it plants
// each shape the guard exists to catch and requires the detector to report it,
// and plants the shapes it must not report. Without it the guard above could
// pass because it detects nothing at all.
func TestPipelineVersionGuardCatchesAPlantedOrdering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		want  bool
	}{
		{"the aggregate that started it", "SELECT MAX(pipeline_version) FROM vulnerability_records", true},
		{"lower case", "select max(pipeline_version) from t", true},
		{"the minimum is the same defect", "SELECT MIN(pipeline_version) FROM t", true},
		{"a whitespace-padded aggregate", "SELECT MAX( pipeline_version ) FROM t", true},
		{"ordering on it alone", "SELECT a FROM t ORDER BY pipeline_version", true},
		{"ordering on it among others", "SELECT a FROM t ORDER BY module_path, pipeline_version, walk_id", true},
		{"ordering on it descending", "SELECT a FROM t ORDER BY pipeline_version DESC", true},
		{"ordering on it before a limit", "SELECT a FROM t ORDER BY pipeline_version LIMIT 1", true},
		{"qualified by its table alias", "SELECT a FROM t vr ORDER BY vr.pipeline_version", true},

		{"grouping is not ordering", "SELECT pipeline_version, COUNT(*) FROM t GROUP BY pipeline_version", false},
		{"selecting it is not ordering", "SELECT pipeline_version FROM t ORDER BY scanned_at DESC", false},
		{"filtering on it is not ordering", "SELECT a FROM t WHERE pipeline_version = ?", false},
		{"a group-by clause after the order-by", "SELECT a FROM t GROUP BY pipeline_version ORDER BY walk_id", false},
		{"another column's aggregate", "SELECT MAX(scanned_at) FROM t GROUP BY pipeline_version", false},
		{"not SQL at all", "the pipeline_version column", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := len(pipelineVersionTextOrderings(tc.query)) > 0
			if got != tc.want {
				t.Errorf("detector reported %v for %q, want %v", got, tc.query, tc.want)
			}
		})
	}
}

// pipelineVersionTextOrderings names every place in one SQL string where the
// pipeline version is compared as text: an ORDER BY clause that keys on it, or
// an aggregate that selects the largest or smallest of it.
func pipelineVersionTextOrderings(query string) []string {
	const column = "pipeline_version"
	q := strings.ToLower(query)
	var found []string

	for _, agg := range []string{"max(", "min("} {
		from := 0
		for {
			i := strings.Index(q[from:], agg)
			if i < 0 {
				break
			}
			i += from
			from = i + len(agg)
			end := strings.Index(q[from:], ")")
			if end < 0 {
				break
			}
			if strings.TrimSpace(q[from:from+end]) == column {
				found = append(found, strings.TrimSuffix(agg, "(")+"("+column+")")
			}
		}
	}

	// The ORDER BY clause runs to the end of the statement or to the clause that
	// closes it. GROUP BY is not in that set going forwards — it precedes ORDER
	// BY in SQL — so a query that groups on the column and orders on another is
	// not reported.
	from := 0
	for {
		i := strings.Index(q[from:], "order by")
		if i < 0 {
			break
		}
		i += from
		clause := q[i+len("order by"):]
		from = i + len("order by")
		for _, closer := range []string{"limit", "offset", ";", ")"} {
			if j := strings.Index(clause, closer); j >= 0 {
				clause = clause[:j]
			}
		}
		for _, key := range strings.Split(clause, ",") {
			key = strings.TrimSpace(key)
			key = strings.TrimSuffix(strings.TrimSuffix(key, " asc"), " desc")
			if key == column || strings.HasSuffix(key, "."+column) {
				found = append(found, "ORDER BY "+key)
			}
		}
	}
	return found
}
