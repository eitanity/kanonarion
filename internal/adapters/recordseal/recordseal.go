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
// <hex>. The choice is per domain and fixed by the records already stored: the
// vulnerability record and the walk scan run seal bare hex, and prefixing them
// now would invalidate every row. Insisting on the prefix here did not make
// those records suspicious, it made them unclassifiable — the comparison could
// never hold, so every drifted vuln record fell through to the wording reserved
// for altered bytes. The digest is what is being compared; how it is spelled is
// not evidence about the record.
func SelfConsistent(raw []byte, storedHash string) (bool, error) {
	if storedHash == "" {
		return false, nil
	}
	blanked, _, err := splitTopLevelContentHash(raw)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(blanked)
	digest := hex.EncodeToString(sum[:])
	return storedHash == "sha256:"+digest || storedHash == digest, nil
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
func VerifyBlob(raw []byte, storedHash string) error {
	blanked, embedded, err := splitTopLevelContentHash(raw)
	if err != nil {
		return fmt.Errorf("verifying record blob: %w", err)
	}
	sum := sha256.Sum256(blanked)
	expected := "sha256:" + hex.EncodeToString(sum[:])
	if embedded != expected {
		return fmt.Errorf("content hash mismatch: blob has %q, computed %q", embedded, expected)
	}
	if storedHash != expected {
		return fmt.Errorf("content hash mismatch: stored %q, computed %q", storedHash, expected)
	}
	return nil
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
	if verifyErr == nil {
		return nil
	}
	consistent, err := SelfConsistent(raw, storedHash)
	if err != nil || !consistent {
		return verifyErr
	}
	return fmt.Errorf("%w: the stored bytes hash to their own seal, so nothing has been altered — "+
		"this build cannot reproduce them, which means the record predates a change to its canonical "+
		"shape and should be re-extracted rather than investigated: %w", ErrGenerationDrift, verifyErr)
}

// splitTopLevelContentHash returns raw with the value of the top-level
// content_hash field replaced by an empty string — leaving every other byte
// untouched — together with the value it replaced.
//
// It is JSON-aware rather than a byte search for `"content_hash":"`. That
// distinction is load-bearing: a byte search finds the FIRST occurrence, and the
// vulnerability record embeds its database snapshot's own content_hash, which is
// sealed CONTENT rather than the seal. Blanking that one instead would compute a
// digest over the wrong bytes and report an intact record as altered. The
// hand-rolled copies this replaced, in the interface and call graph domains, both
// had that bug latent.
func splitTopLevelContentHash(raw []byte) ([]byte, string, error) {
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
		value, ok := valTok.(string)
		if !ok {
			return nil, "", fmt.Errorf("top-level content_hash is %T, want a string", valTok)
		}
		end := int(dec.InputOffset())

		out := make([]byte, 0, len(raw))
		out = append(out, raw[:start]...)
		out = append(out, '"', '"')
		out = append(out, raw[end:]...)
		return out, value, nil
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
