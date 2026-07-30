package sqlite

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
)

// contentHashPrefix is the label every record domain now writes in front of the
// digest it seals with, this one included.
const contentHashPrefix = "sha256:"

// perModuleResultsKey is the field of a serialised walk scan run that maps each
// scanned coordinate to the content hash of the record it produced. It is the
// reason a run is a recompute rather than a re-notation: re-spelling the record
// hashes changes the run's own sealed content.
const perModuleResultsKey = "per_module_results"

// renotateVulnSeals rewrites every stored vulnerability seal from bare hex into
// the labelled form, in the only order that is correct.
//
// The order is forced by what the two shapes are. A vulnerability record's seal
// covers its own JSON with content_hash blanked, so the blanked bytes do not
// depend on how that field is spelled and the digest is unchanged: each record's
// new value is exactly the prefix plus its old one, and nothing else about the
// record moves. A walk scan run is different — its per_module_results embed the
// record hashes — so re-notating the records genuinely changes each run's sealed
// content and the run's seal must be recomputed from the re-notated bytes.
//
// Hence: records, then the membership column that names them, then the runs.
//
// Every rewrite is a byte splice into the stored JSON, never a re-marshal
// through today's struct. Re-marshalling would silently re-render a record
// written by an older canonical shape into this build's shape, turning a
// generation this build cannot reproduce into one it appears to have written.
// Splicing changes exactly the field named, so a drifted row stays drifted and
// stays honest about it.
//
// A row whose stored bytes do not hash to the seal they carry is left exactly as
// it is. Such a row is already saying something is wrong with it, and re-sealing
// it would replace that statement with a valid seal over unexplained bytes —
// laundering the one condition the seal exists to report. It keeps its bare
// notation, which every reader accepts, and keeps reporting itself.
//
// No PipelineVersion bump accompanies this. The record describes the same
// measurement made by the same pipeline; only the spelling of its seal changes.
// A bump would mark every stored row a superseded generation while the read path
// pins on the current one, so the rows would go dark and no re-scan could
// supersede them — the record key carries the content hash, so a re-scan appends
// beside them rather than replacing them.
func renotateVulnSeals(tx *sql.Tx) error {
	if err := renotateRecords(tx); err != nil {
		return err
	}
	if err := renotateRunMembership(tx); err != nil {
		return err
	}
	return renotateRuns(tx)
}

// renotateRecords prefixes the seal of every vulnerability record, in the column
// and in the stored blob, and proves each rewrite was a pure re-notation.
func renotateRecords(tx *sql.Tx) error {
	ids, err := scanRowIDs(tx, `SELECT rowid FROM vulnerability_records`)
	if err != nil {
		return fmt.Errorf("listing vulnerability records to re-notate: %w", err)
	}

	for _, id := range ids {
		var stored string
		var blob []byte
		if serr := tx.QueryRow(
			`SELECT content_hash, serialised FROM vulnerability_records WHERE rowid = ?`, id,
		).Scan(&stored, &blob); serr != nil {
			return fmt.Errorf("reading vulnerability record %d: %w", id, serr)
		}

		rewritten, newHash, ok, rerr := renotateSealedBlob(blob, stored)
		if rerr != nil {
			return fmt.Errorf("re-notating vulnerability record %d: %w", id, rerr)
		}
		if !ok {
			continue
		}

		// The self-verifying property, asserted rather than assumed: the seal
		// covers the blanked bytes, so a pure re-notation leaves them identical
		// and the new value is the prefix plus the old one. Anything else means
		// this rewrite changed the record rather than its spelling, and the
		// migration must not commit.
		if newHash != contentHashPrefix+stored {
			return fmt.Errorf(
				"re-notating vulnerability record %d changed the seal: %q is not %q plus %q",
				id, newHash, contentHashPrefix, stored)
		}
		if verr := verifyPureRenotation(blob, rewritten); verr != nil {
			return fmt.Errorf("re-notating vulnerability record %d: %w", id, verr)
		}

		if _, uerr := tx.Exec(
			`UPDATE vulnerability_records SET content_hash = ?, serialised = ? WHERE rowid = ?`,
			newHash, rewritten, id,
		); uerr != nil {
			return fmt.Errorf("rewriting vulnerability record %d: %w", id, uerr)
		}
	}
	return nil
}

// renotateRunMembership prefixes the record hash each run's membership row
// names, so a run still names the exact generation it scanned.
//
// Legacy rows carry the empty string — a run that recorded only a coordinate —
// and are left alone; there is no digest there to label.
func renotateRunMembership(tx *sql.Tx) error {
	if _, err := tx.Exec(`
UPDATE walk_scan_run_modules
   SET record_content_hash = ? || record_content_hash
 WHERE record_content_hash != ''
   AND substr(record_content_hash, 1, ?) != ?`,
		contentHashPrefix, len(contentHashPrefix), contentHashPrefix,
	); err != nil {
		return fmt.Errorf("re-notating walk scan run membership: %w", err)
	}
	return nil
}

// renotateRuns re-notates the record hashes a run embeds and recomputes the
// run's own seal over the result.
//
// This is the genuine recompute the record rewrite is not, and it is why the
// order matters: the bytes being sealed have changed.
func renotateRuns(tx *sql.Tx) error {
	ids, err := scanRowIDs(tx, `SELECT rowid FROM walk_scan_runs`)
	if err != nil {
		return fmt.Errorf("listing walk scan runs to re-notate: %w", err)
	}

	for _, id := range ids {
		var stored string
		var blob []byte
		if serr := tx.QueryRow(
			`SELECT content_hash, serialised FROM walk_scan_runs WHERE rowid = ?`, id,
		).Scan(&stored, &blob); serr != nil {
			return fmt.Errorf("reading walk scan run %d: %w", id, serr)
		}

		intact, cerr := recordseal.SelfConsistent(blob, stored)
		if cerr != nil || !intact {
			// Unreadable or not hashing to its own seal. Leave it saying so.
			continue
		}
		if strings.HasPrefix(stored, contentHashPrefix) {
			continue
		}

		renotated, count, perr := renotateEmbeddedRecordHashes(blob)
		if perr != nil {
			// Unreadable bytes are not this migration's to interpret; see
			// renotateSealedBlob.
			continue
		}

		newHash, sealed, serr := reseal(renotated)
		if serr != nil {
			continue
		}

		// The recompute must land somewhere a reader can verify. If it does not,
		// the splice is wrong and no run may be written.
		consistent, verr := recordseal.SelfConsistent(sealed, newHash)
		if verr != nil {
			return fmt.Errorf("verifying the reseal of walk scan run %d: %w", id, verr)
		}
		if !consistent {
			return fmt.Errorf("the reseal of walk scan run %d does not hash to its own seal", id)
		}
		// A run with no embedded record hashes to re-notate seals the same bytes
		// it did, so only its own spelling may move.
		if count == 0 && newHash != contentHashPrefix+stored {
			return fmt.Errorf(
				"walk scan run %d embeds no record hash but its seal changed: %q is not %q plus %q",
				id, newHash, contentHashPrefix, stored)
		}

		if _, uerr := tx.Exec(
			`UPDATE walk_scan_runs SET content_hash = ?, serialised = ? WHERE rowid = ?`,
			newHash, sealed, id,
		); uerr != nil {
			return fmt.Errorf("rewriting walk scan run %d: %w", id, uerr)
		}
	}
	return nil
}

// renotateSealedBlob prefixes the seal a record blob carries, without touching
// any other byte. ok is false when the row must be left alone: already
// re-notated, or its column and its blob disagreeing about what the seal is.
//
// Unlike the run rewrite there is no self-consistency gate here, and there must
// not be one. Re-notating a record is a pure prefix: the sealed bytes do not
// move, so a row that verified before verifies after and a row that did not,
// still does not. Nothing is laundered because nothing is resealed, and a gate
// would only decide which broken rows get to keep the older spelling.
//
// A gate would also be WRONG here rather than merely unnecessary. The record's
// recipe zeroes FirstScannedAt before hashing, but the field is omitzero rather
// than omitted, so a record carrying a first-seen anchor stores a blob that does
// not hash to its own seal under the shared rule — the anchor is in the stored
// bytes and not in the sealed ones. Gating on that rule would skip exactly the
// records that have been re-scanned.
func renotateSealedBlob(blob []byte, stored string) (rewritten []byte, newHash string, ok bool, err error) {
	if strings.HasPrefix(stored, contentHashPrefix) {
		return nil, "", false, nil
	}

	newHash = contentHashPrefix + stored
	rewritten, embedded, located := locateSeal(blob, newHash)
	if !located {
		return nil, "", false, nil
	}
	if embedded != stored {
		// The row is already contradicting itself. Prefixing one side would
		// leave it contradicting itself in a new way and hide which side moved.
		return nil, "", false, nil
	}
	return rewritten, newHash, true, nil
}

// locateSeal splices newHash into blob's top-level content_hash, reporting
// whether the seal could be found at all.
//
// A blob this cannot read is a row whose seal has no located position, so there
// is nothing here to re-spell. It keeps the notation it has — which every reader
// accepts — and keeps reporting itself on read. That is deliberately not an
// error: a migration must not be the thing that makes a store unopenable, and
// the row's real problem is one the read path already states.
func locateSeal(blob []byte, newHash string) (rewritten []byte, embedded string, ok bool) {
	rewritten, embedded, err := recordseal.ReplaceTopLevelContentHash(blob, newHash)
	if err != nil {
		return nil, "", false
	}
	return rewritten, embedded, true
}

// verifyPureRenotation reports an error unless before and after seal over
// byte-identical content — the property that makes a record's re-notation a
// re-spelling rather than a reseal.
func verifyPureRenotation(before, after []byte) error {
	blankedBefore, _, err := recordseal.ReplaceTopLevelContentHash(before, "")
	if err != nil {
		return fmt.Errorf("blanking the seal before the rewrite: %w", err)
	}
	blankedAfter, _, err := recordseal.ReplaceTopLevelContentHash(after, "")
	if err != nil {
		return fmt.Errorf("blanking the seal after the rewrite: %w", err)
	}
	if !bytes.Equal(blankedBefore, blankedAfter) {
		return errors.New("the rewrite changed the sealed bytes, so it was not a re-notation")
	}
	return nil
}

// reseal computes the seal of raw and splices it into raw's own content_hash.
func reseal(raw []byte) (string, []byte, error) {
	blanked, _, err := recordseal.ReplaceTopLevelContentHash(raw, "")
	if err != nil {
		return "", nil, fmt.Errorf("blanking the seal: %w", err)
	}
	sum := sha256.Sum256(blanked)
	hash := contentHashPrefix + hex.EncodeToString(sum[:])
	sealed, _, err := recordseal.ReplaceTopLevelContentHash(raw, hash)
	if err != nil {
		return "", nil, fmt.Errorf("writing the recomputed seal: %w", err)
	}
	return hash, sealed, nil
}

// renotateEmbeddedRecordHashes returns raw with every bare record hash in its
// top-level per_module_results object prefixed, and how many it rewrote.
//
// Like the seal splice this is JSON-aware and byte-preserving: only the value
// bytes it names move, so the run keeps whatever shape the build that wrote it
// emitted.
func renotateEmbeddedRecordHashes(raw []byte) ([]byte, int, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, 0, fmt.Errorf("reading the serialised run: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, 0, errors.New("the serialised run is not a JSON object")
	}

	for {
		keyTok, kerr := dec.Token()
		if errors.Is(kerr, io.EOF) {
			return raw, 0, nil
		}
		if kerr != nil {
			return nil, 0, fmt.Errorf("reading the serialised run: %w", kerr)
		}
		if d, ok := keyTok.(json.Delim); ok && d == '}' {
			return raw, 0, nil
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, 0, fmt.Errorf("unexpected token %v where a key was expected", keyTok)
		}
		if key != perModuleResultsKey {
			if serr := skipJSONValue(dec); serr != nil {
				return nil, 0, serr
			}
			continue
		}
		return spliceMapValues(dec, raw)
	}
}

// spliceMapValues rewrites the string values of the object the decoder is
// positioned in front of, prefixing each bare digest.
func spliceMapValues(dec *json.Decoder, raw []byte) ([]byte, int, error) {
	openTok, err := dec.Token()
	if err != nil {
		return nil, 0, fmt.Errorf("reading %s: %w", perModuleResultsKey, err)
	}
	d, ok := openTok.(json.Delim)
	if !ok || d != '{' {
		// A run whose map is null carries no record hash to re-notate.
		return raw, 0, nil
	}

	out := make([]byte, 0, len(raw))
	cursor := 0
	rewritten := 0
	for {
		keyTok, kerr := dec.Token()
		if kerr != nil {
			return nil, 0, fmt.Errorf("reading %s: %w", perModuleResultsKey, kerr)
		}
		if nd, isDelim := keyTok.(json.Delim); isDelim && nd == '}' {
			out = append(out, raw[cursor:]...)
			return out, rewritten, nil
		}
		if _, isKey := keyTok.(string); !isKey {
			return nil, 0, fmt.Errorf("unexpected token %v where a %s key was expected", keyTok, perModuleResultsKey)
		}
		afterKey := int(dec.InputOffset())

		start := bytes.IndexByte(raw[afterKey:], '"')
		if start < 0 {
			return nil, 0, fmt.Errorf("a %s entry has no string value", perModuleResultsKey)
		}
		start += afterKey
		valTok, verr := dec.Token()
		if verr != nil {
			return nil, 0, fmt.Errorf("reading a %s value: %w", perModuleResultsKey, verr)
		}
		value, isString := valTok.(string)
		if !isString {
			return nil, 0, fmt.Errorf("a %s value is %T, want a string", perModuleResultsKey, valTok)
		}
		end := int(dec.InputOffset())

		if value == "" || strings.HasPrefix(value, contentHashPrefix) {
			continue
		}
		encoded, merr := json.Marshal(contentHashPrefix + value)
		if merr != nil {
			return nil, 0, fmt.Errorf("encoding a re-notated %s value: %w", perModuleResultsKey, merr)
		}
		out = append(out, raw[cursor:start]...)
		out = append(out, encoded...)
		cursor = end
		rewritten++
	}
}

// skipJSONValue consumes one complete JSON value, nesting included.
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("reading the serialised run: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		t, terr := dec.Token()
		if terr != nil {
			return fmt.Errorf("reading the serialised run: %w", terr)
		}
		if nd, isDelim := t.(json.Delim); isDelim {
			switch nd {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

// scanRowIDs collects the row identifiers a rewrite will visit before rewriting
// any of them.
//
// The pool holds one connection, so a cursor left open across an UPDATE would
// wait on the connection its own transaction is holding. Reading the identifiers
// first — and re-reading each row by identifier — also keeps the migration's
// memory bounded by one record rather than by the table.
func scanRowIDs(tx *sql.Tx, query string) ([]int64, error) {
	rows, err := tx.Query(query) //nolint:rowserrcheck // checked below, after the loop
	if err != nil {
		return nil, fmt.Errorf("querying row identifiers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if serr := rows.Scan(&id); serr != nil {
			return nil, fmt.Errorf("scanning a row identifier: %w", serr)
		}
		ids = append(ids, id)
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, fmt.Errorf("iterating row identifiers: %w", rerr)
	}
	return ids, nil
}
