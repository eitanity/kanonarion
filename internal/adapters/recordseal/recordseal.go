// Package recordseal tells a record written by an older shape apart from a
// record that has been altered.
//
// Every record domain seals itself the same way: the canonical JSON of the
// record with its content_hash field blanked is hashed, and the digest is stored
// back into that field. Verification recomputes it — by unmarshalling the stored
// bytes into today's struct and marshalling them again.
//
// That recomputation is a REPRODUCTION check, not a byte-integrity check, and
// the distinction is the reason this package exists. It answers "can this build
// reconstruct this record from its own contents", which is exactly the right
// question at an import boundary: an airgapped network runs an older build by
// definition, and a record it cannot fully reproduce is one it cannot safely
// interpret. Refusing to ingest it is fail-closed.
//
// What it is not is evidence of tampering, and until this package existed the
// store said it was. A field added to a canonical shape changes the bytes today's
// code emits, so every record written before the change stops reproducing and is
// reported in the words reserved for a detected tamper. That happened: 638
// licence records, every one of them written by this project's own earlier build,
// were reported as failing their integrity check. Measured against the
// maintainer's store, all 643 rows of that generation hash exactly to their
// stored seal — nothing was altered, and the store could not say so.
//
// SelfConsistent answers the other question, on the stored bytes alone and with
// no struct involved: do these bytes hash to the seal they carry? When they do
// and the reproduction check has failed, the record is intact and was written by
// a different shape. When they do not, the bytes really have changed.
//
// Neither check is a defence against a deliberate attacker. The seal is keyless,
// so anyone able to rewrite a stored record can recompute it; that is what the
// signature layer is for. These are checks against corruption and against
// mistaking a generation for a corruption.
package recordseal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrGenerationDrift reports a record whose stored bytes hash to their own seal
// but which this build cannot reproduce: it was written by a different canonical
// shape.
//
// Stores wrap it INSIDE their own integrity error rather than instead of it, so
// existing callers that match on the domain's integrity sentinel keep behaving
// as they did, while anything that wants to tell the two apart now can. The
// remedy differs: a drifted record is re-extracted, an altered one is
// investigated.
var ErrGenerationDrift = errors.New("record written by a different canonical shape")

// contentHashKey is the field every record domain seals into.
const contentHashKey = "content_hash"

// Exclusions names the top-level fields a domain leaves out of its seal on top
// of content_hash, by their JSON names.
//
// This package's premise is that a record's seal is the hash of its stored JSON
// with the top-level content_hash blanked. That premise holds only for a domain
// whose hash input differs from its stored bytes in that one field, and a domain
// is entitled to a second. The vulnerability record zeroes its first-seen anchor
// before hashing — a reused record must not change identity on account of
// provenance that never moves — while the anchor itself is real provenance and
// belongs in the stored record. Hash input and stored bytes then differ by that
// field, and a verifier that does not know about it cannot reproduce the seal of
// any record that has been re-scanned. It reports them as altered, which is the
// more alarming answer and therefore reads as the check working.
//
// An excluded field must encode as ABSENT when it is zeroed — omitzero or
// omitempty — because the recipe zeroes it and the seal covers what that
// produces. Removing the member is therefore what reconstructs the sealed bytes,
// where content_hash, which encodes as an empty string, is blanked in place. An
// exclusion that does not reproduce the seal is caught by the cross-domain
// contract test, which seals a fully populated record for every domain.
//
// The zero Exclusions excludes nothing, and the package-level SelfConsistent,
// VerifyBlob and Classify are defined in terms of it, so a domain that excludes
// nothing is treated byte-for-byte as it was before exclusions existed.
type Exclusions struct {
	fields []string
}

// Excluding returns the Exclusions for the named top-level JSON fields.
func Excluding(fields ...string) Exclusions {
	return Exclusions{fields: fields}
}

// SelfConsistent reports whether raw — the canonical JSON exactly as stored —
// hashes to the content hash it carries.
//
// It works on the bytes and never unmarshals into a record type, which is the
// whole point: a struct can only describe the shape it was compiled for, and the
// question here is about a shape it was not.
//
// The content hash is blanked IN PLACE rather than by re-serialising, so every
// other byte — key order, spacing, number formatting — is preserved exactly as
// the writing generation emitted it. Re-serialising would reintroduce the
// dependence on today's encoder that this function exists to avoid.
//
// Only the TOP-LEVEL content_hash is blanked. Some canonical shapes embed a
// nested one — the vulnerability record carries its database snapshot's hash —
// and that nested value is part of the sealed content, not the seal.
//
// Both notations for the same digest are accepted, "sha256:<hex>" and bare
// <hex>, and that tolerance is permanent rather than transitional.
//
// Every domain writes the prefixed form today. The vulnerability record and the
// walk scan run did not: they sealed bare hex, and insisting on the prefix here
// did not make those records suspicious, it made them unclassifiable — the
// comparison could never hold, so every drifted vuln record fell through to the
// wording reserved for altered bytes. Their notation has since been brought into
// line and the stored rows re-notated, but a store carries whatever the build
// that wrote it wrote: a store migrated by one binary and read by an older one,
// an imported blob, a row a migration has not yet reached. A reader that cannot
// classify those re-creates the false tamper report for exactly them.
//
// The digest is what is being compared; how it is spelled is not evidence about
// the record.
func SelfConsistent(raw []byte, storedHash string) (bool, error) {
	return Exclusions{}.SelfConsistent(raw, storedHash)
}

// SelfConsistent reports whether raw hashes to the content hash it carries once
// this domain's excluded fields are removed as well as its content_hash blanked.
// See SelfConsistent for what the check answers and Exclusions for why a domain
// may need to remove more than the seal itself.
func (x Exclusions) SelfConsistent(raw []byte, storedHash string) (bool, error) {
	if storedHash == "" {
		return false, nil
	}
	sealed, _, err := x.sealedBytes(raw)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(sealed)
	return isDigest(storedHash, hex.EncodeToString(sum[:])), nil
}

// VerifyBlob checks a stored record blob against its seal without unmarshalling
// it, and is the preferred read-path check for any store whose blob holds the
// whole record.
//
// It verifies the SAME seal the re-marshal path does — the seal is defined as
// the hash of the canonical JSON with content_hash blanked, and the stored blob
// is that canonical JSON with content_hash filled in, so blanking it in place
// reconstructs the sealed bytes exactly. Nothing is re-sealed and no record is
// rewritten; this is only a different way of arriving at the same expected
// digest, one that does not route through a struct.
//
// That is why the interface store never suffered the licence store's generation
// bug: it has verified blobs this way from the start. A store that can use this
// should, and one that cannot — the call graph store reconstructs its edges from
// a satellite table, so its blob is not the whole record — needs the schema
// version gate instead.
//
// Both the hash embedded in the blob and the hash stored in the column are
// checked, so a row whose column has been edited to match a doctored blob still
// fails.
//
// Both notations are accepted, for the reason SelfConsistent accepts them: the
// digest is what is being compared, and how it is spelled is not evidence about
// the record. Hard-coding the prefix here was correct only by luck of the sole
// caller being a domain that used it, and it is the same defect that reported
// intact vulnerability records as altered one function along.
func VerifyBlob(raw []byte, storedHash string) error {
	return Exclusions{}.VerifyBlob(raw, storedHash)
}

// VerifyBlob checks a stored blob against its seal with this domain's excluded
// fields removed as well as its content_hash blanked. See VerifyBlob.
func (x Exclusions) VerifyBlob(raw []byte, storedHash string) error {
	sealed, embedded, err := x.sealedBytes(raw)
	if err != nil {
		return fmt.Errorf("verifying record blob: %w", err)
	}
	sum := sha256.Sum256(sealed)
	digest := hex.EncodeToString(sum[:])
	expected := "sha256:" + digest
	if !isDigest(embedded, digest) {
		return fmt.Errorf("content hash mismatch: blob has %q, computed %q", embedded, expected)
	}
	if !isDigest(storedHash, digest) {
		return fmt.Errorf("content hash mismatch: stored %q, computed %q", storedHash, expected)
	}
	// The blob and the column must agree with each other as well as with the
	// digest, or a row whose column was edited to the other notation would pass
	// while no longer being the value the writer stored.
	if embedded != storedHash {
		return fmt.Errorf("content hash mismatch: blob has %q, stored %q", embedded, storedHash)
	}
	return nil
}

// isDigest reports whether stated spells digest, in either of the two notations
// the record domains write.
func isDigest(stated, digest string) bool {
	return stated == "sha256:"+digest || stated == digest
}

// Classify turns a failed reproduction check into the more specific finding.
//
// verifyErr is the error the domain's own VerifyContentHash returned; it is
// returned unchanged when the bytes have genuinely changed, so the caller's
// existing message survives. When the bytes are intact, ErrGenerationDrift is
// joined to it, so a caller matching either sentinel gets the answer it asked
// for.
//
// A record this cannot examine — unreadable JSON, no top-level content hash — is
// reported as the original failure rather than as drift. Absence of evidence
// that a record is merely old is not evidence that it is.
func Classify(raw []byte, storedHash string, verifyErr error) error {
	return Exclusions{}.Classify(raw, storedHash, verifyErr)
}

// Classify turns a failed reproduction check into the more specific finding,
// with this domain's excluded fields removed before the seal is recomputed. See
// Classify.
func (x Exclusions) Classify(raw []byte, storedHash string, verifyErr error) error {
	if verifyErr == nil {
		return nil
	}
	consistent, err := x.SelfConsistent(raw, storedHash)
	if err != nil || !consistent {
		return verifyErr
	}
	return fmt.Errorf("%w: the stored bytes hash to their own seal, so nothing has been altered — "+
		"this build cannot reproduce them, which means the record predates a change to its canonical "+
		"shape and should be re-extracted rather than investigated: %w", ErrGenerationDrift, verifyErr)
}

// ReplaceTopLevelContentHash returns raw with the value of its top-level
// content_hash field replaced by value — leaving every other byte untouched —
// together with the value it replaced.
//
// It exists for a migration that re-notates a stored seal without re-sealing it.
// Re-marshalling through today's struct would be the obvious way to rewrite a
// stored record and it is the wrong one: it silently re-renders a record written
// by an older canonical shape into today's, which converts a generation this
// build cannot reproduce into one it appears to have written. Splicing the bytes
// changes exactly the field named and nothing else, so a drifted record stays
// drifted and stays honest about it.
//
// value is JSON-encoded, so it may be any string.
func ReplaceTopLevelContentHash(raw []byte, value string) ([]byte, string, error) {
	return spliceTopLevelContentHash(raw, value)
}

// sealedBytes reconstructs the bytes the writing generation sealed: raw with its
// top-level content_hash blanked and every excluded top-level member removed. It
// also returns the content hash the blob carried.
//
// Both operations splice the bytes rather than re-serialising, for the reason
// SelfConsistent gives: key order, spacing and number formatting must stay
// exactly as the writing generation emitted them, or the check reacquires the
// dependence on today's encoder that it exists to avoid.
func (x Exclusions) sealedBytes(raw []byte) (sealed []byte, embedded string, err error) {
	sealed, embedded, err = splitTopLevelContentHash(raw)
	if err != nil {
		return nil, "", err
	}
	for _, field := range x.fields {
		sealed, err = deleteTopLevelMember(sealed, field)
		if err != nil {
			return nil, "", err
		}
	}
	return sealed, embedded, nil
}

// deleteTopLevelMember returns raw with the top-level member named key removed,
// together with the one comma that separated it from its neighbours.
//
// A key that is not present returns raw unchanged rather than an error: an
// excluded field is absent exactly when it was zero, which is the case the seal
// already covers.
//
// It is JSON-aware for the same reason the content_hash splice is — a byte
// search would find a nested member of the same name, and the vulnerability
// record nests a whole database snapshot.
func deleteTopLevelMember(raw []byte, key string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("reading canonical JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("canonical JSON is not an object")
	}
	// prevEnd is the offset just past the previous member, so the next opening
	// quote after it is the start of this member's key.
	prevEnd := int(dec.InputOffset())

	for {
		keyTok, kerr := dec.Token()
		if errors.Is(kerr, io.EOF) {
			return raw, nil
		}
		if kerr != nil {
			return nil, fmt.Errorf("reading canonical JSON: %w", kerr)
		}
		if d, ok := keyTok.(json.Delim); ok && d == '}' {
			return raw, nil
		}
		name, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected token %v where a key was expected", keyTok)
		}
		quote := bytes.IndexByte(raw[prevEnd:], '"')
		if quote < 0 {
			return nil, fmt.Errorf("top-level key %q has no opening quote", name)
		}
		start := prevEnd + quote
		if serr := skipValue(dec); serr != nil {
			return nil, serr
		}
		end := int(dec.InputOffset())
		if name == key {
			return spliceOutMember(raw, start, end), nil
		}
		prevEnd = end
	}
}

// spliceOutMember removes raw[start:end] and the single comma that separated it
// from its neighbours — the following one when there is one, otherwise the
// preceding one. A sole member has neither, and the object is left empty.
func spliceOutMember(raw []byte, start, end int) []byte {
	if after := skipSpaceForward(raw, end); after < len(raw) && raw[after] == ',' {
		end = after + 1
	} else if before := skipSpaceBackward(raw, start); before > 0 && raw[before-1] == ',' {
		start = before - 1
	}
	out := make([]byte, 0, len(raw)-(end-start))
	out = append(out, raw[:start]...)
	return append(out, raw[end:]...)
}

// skipSpaceForward returns the first offset at or after i that is not JSON
// whitespace.
func skipSpaceForward(raw []byte, i int) int {
	for i < len(raw) && isJSONSpace(raw[i]) {
		i++
	}
	return i
}

// skipSpaceBackward returns the first offset at or before i whose preceding byte
// is not JSON whitespace.
func skipSpaceBackward(raw []byte, i int) int {
	for i > 0 && isJSONSpace(raw[i-1]) {
		i--
	}
	return i
}

// isJSONSpace reports whether b is one of the four bytes JSON allows between
// tokens.
func isJSONSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// splitTopLevelContentHash returns raw with the value of the top-level
// content_hash field replaced by an empty string — leaving every other byte
// untouched — together with the value it replaced.
func splitTopLevelContentHash(raw []byte) ([]byte, string, error) {
	return spliceTopLevelContentHash(raw, "")
}

// spliceTopLevelContentHash rewrites the top-level content_hash value in place.
//
// It is JSON-aware rather than a byte search for `"content_hash":"`. That
// distinction is load-bearing: a byte search finds the FIRST occurrence, and the
// vulnerability record embeds its database snapshot's own content_hash, which is
// sealed CONTENT rather than the seal. Blanking that one instead would compute a
// digest over the wrong bytes and report an intact record as altered. The
// hand-rolled copies this replaced, in the interface and call graph domains, both
// had that bug latent.
func spliceTopLevelContentHash(raw []byte, value string) ([]byte, string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, "", fmt.Errorf("reading canonical JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, "", errors.New("canonical JSON is not an object")
	}

	// skipValue consumes each value whole, so the decoder is always back at the
	// root object's key position when the loop turns.
	for {
		keyTok, kerr := dec.Token()
		if errors.Is(kerr, io.EOF) {
			return nil, "", errors.New("canonical JSON has no top-level content_hash")
		}
		if kerr != nil {
			return nil, "", fmt.Errorf("reading canonical JSON: %w", kerr)
		}
		if d, ok := keyTok.(json.Delim); ok && d == '}' {
			return nil, "", errors.New("canonical JSON has no top-level content_hash")
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, "", fmt.Errorf("unexpected token %v where a key was expected", keyTok)
		}
		afterKey := dec.InputOffset()

		if key != contentHashKey {
			// Skip the value wholesale, however deeply nested.
			if serr := skipValue(dec); serr != nil {
				return nil, "", serr
			}
			continue
		}

		// The value is a JSON string. Its opening quote is the next such byte
		// after the key, past the colon; InputOffset after reading it is the byte
		// following its closing quote.
		start := bytes.IndexByte(raw[afterKey:], '"')
		if start < 0 {
			return nil, "", errors.New("top-level content_hash has no string value")
		}
		start += int(afterKey)
		valTok, verr := dec.Token()
		if verr != nil {
			return nil, "", fmt.Errorf("reading content_hash value: %w", verr)
		}
		old, ok := valTok.(string)
		if !ok {
			return nil, "", fmt.Errorf("top-level content_hash is %T, want a string", valTok)
		}
		end := int(dec.InputOffset())

		encoded, merr := json.Marshal(value)
		if merr != nil {
			return nil, "", fmt.Errorf("encoding replacement content_hash: %w", merr)
		}

		out := make([]byte, 0, len(raw)+len(encoded))
		out = append(out, raw[:start]...)
		out = append(out, encoded...)
		out = append(out, raw[end:]...)
		return out, old, nil
	}
}

// skipValue consumes one complete JSON value, including a nested object or
// array, from dec.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("reading canonical JSON: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		t, terr := dec.Token()
		if terr != nil {
			return fmt.Errorf("reading canonical JSON: %w", terr)
		}
		if nd, ok := t.(json.Delim); ok {
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
