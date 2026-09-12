package sqlitestore

// SortableStamp renders a stored timestamp column at fixed width, so that MIN
// and MAX over it return the earliest and latest INSTANT rather than the first
// and last string.
//
// The ledgers' timestamp columns hold two generations of encoding: a whole
// second on rows written before the stamp was widened, a fixed-width nine-digit
// fraction after. SQLite compares TEXT lexicographically and '.' is 0x2E while
// 'Z' is 0x5A, so within a shared second "…53.9Z" sorts BEFORE "…53Z" — a bare
// MAX returns the EARLIER instant, and a bare MIN the later one. Padding the
// whole-second form out to the same width makes text order chronological order
// again.
//
// It is for the aggregate select list, where there is no row to fall back on. An
// ORDER BY has a rowid tiebreak beneath it and uses julianday, whose resolution
// the tiebreak covers; an aggregate collapses the rows and has no tiebreak, so
// the comparison here is exact rather than approximate.
//
// The value it returns names the same instant as the stored one and parses as
// RFC3339. It is not the stored bytes for a legacy row — it is the padded form —
// so it is read as a time and never compared against a stored string.
//
// column is a column name this codebase writes, never caller input.
func SortableStamp(column string) string {
	// A whole-second RFC3339 stamp is 20 characters ("2006-01-02T15:04:05Z");
	// anything longer already carries the fraction.
	return `CASE WHEN length(` + column + `) > 20 THEN ` + column +
		` ELSE substr(` + column + `, 1, 19) || '.000000000Z' END`
}
