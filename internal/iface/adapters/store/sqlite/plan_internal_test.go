package sqlite

import (
	"strings"
	"testing"
)

// The store plans on SQLite's built-in estimates, so with no statistics the
// symbol read must still search its index rather than scan.
func TestFindSymbolSearchesItsIndexWithoutStatistics(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	rows, err := s.db.DB().Query(`EXPLAIN QUERY PLAN `+findSymbolQuery, nil, nil)
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
	plan := strings.Join(lines, "; ")
	if !strings.Contains(plan, "SEARCH interface_symbols USING INDEX interface_symbols_name_pipeline_idx ") {
		t.Errorf("plan %q does not search interface_symbols_name_pipeline_idx", plan)
	}
	if strings.Contains(plan, "SCAN interface_symbols") {
		t.Errorf("plan %q scans interface_symbols", plan)
	}
}
