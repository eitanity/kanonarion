package sqlite

import (
	"strings"
	"testing"
)

// The store plans on SQLite's built-in estimates, so with no statistics every
// hot edge and dispatch read must still search its index rather than scan.
func TestHotReadsSearchTheirIndexWithoutStatistics(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	in := func(n int) string { return "IN (" + strings.TrimSuffix(strings.Repeat("?,", n), ",") + ")" }
	for _, c := range []struct {
		name, table, index, q string
	}{
		{"fetchEdges", "callgraph_edges", "sqlite_autoindex_callgraph_edges_1", fetchEdgesQuery},
		{"FindCallers", "callgraph_edges", "callgraph_edges_to_idx", edgesQuery("to_id", "= ?", "from_id", false)},
		{"FindCallers excluding tests", "callgraph_edges", "callgraph_edges_to_idx", edgesQuery("to_id", "= ?", "from_id", true)},
		{"FindCallees", "callgraph_edges", "callgraph_edges_from_idx", edgesQuery("from_id", "= ?", "to_id", false)},
		{"FindCallees excluding tests", "callgraph_edges", "callgraph_edges_from_idx", edgesQuery("from_id", "= ?", "to_id", true)},
		{"FindCallersOfEach, 1", "callgraph_edges", "callgraph_edges_to_idx", edgesQuery("to_id", in(1), "from_id", false)},
		{"FindCallersOfEach, 400", "callgraph_edges", "callgraph_edges_to_idx", edgesQuery("to_id", in(400), "from_id", true)},
		{"FindCalleesOfEach, 1", "callgraph_edges", "callgraph_edges_from_idx", edgesQuery("from_id", in(1), "to_id", false)},
		{"FindCalleesOfEach, 400", "callgraph_edges", "callgraph_edges_from_idx", edgesQuery("from_id", in(400), "to_id", true)},
		{"dispatchRows, 1", "callgraph_dependency_dispatch", "callgraph_dependency_dispatch_node_idx", dispatchQuery(1)},
		{"dispatchRows, 400", "callgraph_dependency_dispatch", "callgraph_dependency_dispatch_node_idx", dispatchQuery(400)},
	} {
		t.Run(c.name, func(t *testing.T) {
			plan := queryPlan(t, s, c.q)
			if !strings.Contains(plan, "SEARCH "+c.table+" USING INDEX "+c.index+" ") {
				t.Errorf("plan %q does not search %s", plan, c.index)
			}
			if strings.Contains(plan, "SCAN "+c.table) {
				t.Errorf("plan %q scans %s", plan, c.table)
			}
		})
	}
}

// queryPlan is EXPLAIN QUERY PLAN's detail lines for q, with every placeholder
// bound to NULL.
func queryPlan(t *testing.T, s *Store, q string) string {
	t.Helper()
	rows, err := s.db.DB().Query(`EXPLAIN QUERY PLAN `+q, make([]any, strings.Count(q, "?"))...)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scanning plan: %v", err)
		}
		lines = append(lines, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating plan: %v", err)
	}
	return strings.Join(lines, "; ")
}
