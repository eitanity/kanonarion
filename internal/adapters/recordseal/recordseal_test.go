package recordseal_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
)

// seal returns a canonical blob and its seal, built the way every record domain
// builds one: hash the JSON with content_hash blank, then write the digest back
// into that field.
func seal(t *testing.T, blankBody string) (blob []byte, hash string) {
	t.Helper()
	if !strings.Contains(blankBody, `"content_hash":""`) {
		t.Fatalf("test body must contain an empty content_hash: %s", blankBody)
	}
	sum := sha256.Sum256([]byte(blankBody))
	hash = "sha256:" + hex.EncodeToString(sum[:])
	return []byte(strings.Replace(blankBody, `"content_hash":""`, fmt.Sprintf(`"content_hash":%q`, hash), 1)), hash
}

func TestVerifyBlob(t *testing.T) {
	t.Parallel()

	blob, hash := seal(t, `{"content_hash":"","name":"example","value":1}`)

	t.Run("valid blob", func(t *testing.T) {
		t.Parallel()
		if err := recordseal.VerifyBlob(blob, hash); err != nil {
			t.Errorf("VerifyBlob on a valid blob: %v", err)
		}
	})

	t.Run("wrong stored hash", func(t *testing.T) {
		t.Parallel()
		if err := recordseal.VerifyBlob(blob, "sha256:badhash"); err == nil {
			t.Error("a stored hash disagreeing with the blob was accepted")
		}
	})

	t.Run("tampered blob", func(t *testing.T) {
		t.Parallel()
		tampered := make([]byte, len(blob))
		copy(tampered, blob)
		tampered[len(tampered)-2] ^= 0xff
		if err := recordseal.VerifyBlob(tampered, hash); err == nil {
			t.Error("a tampered blob was accepted")
		}
	})

	t.Run("blob and column edited together", func(t *testing.T) {
		t.Parallel()
		// Both the embedded hash and the column are checked, so re-sealing the
		// blob and updating the column to match is still caught — the digest no
		// longer describes the bytes.
		doctored, doctoredHash := seal(t, `{"content_hash":"","name":"substituted","value":1}`)
		if err := recordseal.VerifyBlob(doctored, doctoredHash); err != nil {
			t.Fatalf("precondition: the doctored blob should be internally valid: %v", err)
		}
		mixed := append([]byte(nil), doctored...)
		if err := recordseal.VerifyBlob(mixed[:len(mixed)-1], doctoredHash); err == nil {
			t.Error("a truncated blob was accepted")
		}
	})

	for name, body := range map[string]string{
		"no content_hash field":     `{"no_hash_field":"x"}`,
		"unterminated value":        `{"content_hash":"sha256:deadbeef`,
		"not an object":             `["content_hash"]`,
		"empty":                     ``,
		"content_hash not a string": `{"content_hash":42}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := recordseal.VerifyBlob([]byte(body), "sha256:whatever"); err == nil {
				t.Errorf("malformed blob %q was accepted", body)
			}
		})
	}
}

// TestVerifyBlob_NestedContentHashIsSealedContent is the bug the hand-rolled
// copies in the interface and call graph domains had latent. They found the
// content_hash key with a byte search, which takes the FIRST occurrence — and
// the vulnerability record embeds its database snapshot's own content_hash,
// which is sealed CONTENT, not the seal. Blanking that one computes the digest
// over the wrong bytes and reports an intact record as altered.
func TestVerifyBlob_NestedContentHashIsSealedContent(t *testing.T) {
	t.Parallel()

	// The nested hash sorts before the top-level one, so a first-match byte
	// search picks the wrong field.
	blob, hash := seal(t, `{"blob_ref":{"content_hash":"sha256:nested"},"content_hash":"","name":"x"}`)
	if err := recordseal.VerifyBlob(blob, hash); err != nil {
		t.Errorf("a record embedding a nested content_hash failed verification: %v", err)
	}

	// And the nested value is genuinely covered by the seal: changing it breaks
	// verification, which is what makes it content rather than decoration.
	tampered := []byte(strings.Replace(string(blob), "sha256:nested", "sha256:swapped", 1))
	if err := recordseal.VerifyBlob(tampered, hash); err == nil {
		t.Error("editing an embedded content hash left the seal valid")
	}
}

// TestClassify_SeparatesDriftFromAlteration is the whole point of the package.
// A record written by an older canonical shape and a record that has been
// altered both fail the re-marshal check, and until this existed the store
// reported them in the same words — which is how 638 licence records written by
// this project's own earlier build came to be reported as failing their
// integrity check.
func TestClassify_SeparatesDriftFromAlteration(t *testing.T) {
	t.Parallel()

	blob, hash := seal(t, `{"content_hash":"","name":"example"}`)
	reproductionFailed := errors.New("content hash mismatch: stored X, computed Y")

	t.Run("intact bytes are drift, not alteration", func(t *testing.T) {
		t.Parallel()
		err := recordseal.Classify(blob, hash, reproductionFailed)
		if !errors.Is(err, recordseal.ErrGenerationDrift) {
			t.Errorf("a record whose bytes hash to their own seal was not reported as drift: %v", err)
		}
		// The original failure is still readable, so nothing the caller used to
		// print is lost.
		if !errors.Is(err, reproductionFailed) {
			t.Errorf("the underlying verification error was dropped: %v", err)
		}
	})

	t.Run("altered bytes stay an alteration", func(t *testing.T) {
		t.Parallel()
		tampered := append([]byte(nil), blob...)
		tampered[len(tampered)-2] ^= 0xff
		err := recordseal.Classify(tampered, hash, reproductionFailed)
		if errors.Is(err, recordseal.ErrGenerationDrift) {
			t.Error("a record whose bytes do NOT hash to their seal was excused as drift")
		}
		if !errors.Is(err, reproductionFailed) {
			t.Errorf("the underlying verification error was dropped: %v", err)
		}
	})

	t.Run("unexaminable bytes are not excused", func(t *testing.T) {
		t.Parallel()
		// Absence of evidence that a record is merely old is not evidence that it
		// is: an unreadable blob must not be waved through as drift.
		err := recordseal.Classify([]byte(`{`), hash, reproductionFailed)
		if errors.Is(err, recordseal.ErrGenerationDrift) {
			t.Error("an unreadable blob was excused as drift")
		}
	})

	t.Run("success is passed through", func(t *testing.T) {
		t.Parallel()
		if err := recordseal.Classify(blob, hash, nil); err != nil {
			t.Errorf("Classify invented an error where verification succeeded: %v", err)
		}
	})
}

func TestSelfConsistent(t *testing.T) {
	t.Parallel()

	blob, hash := seal(t, `{"content_hash":"","name":"example"}`)

	ok, err := recordseal.SelfConsistent(blob, hash)
	if err != nil || !ok {
		t.Errorf("SelfConsistent on an intact blob = (%v, %v), want (true, nil)", ok, err)
	}

	ok, err = recordseal.SelfConsistent(blob, "")
	if err != nil || ok {
		t.Errorf("SelfConsistent with no stored hash = (%v, %v), want (false, nil)", ok, err)
	}
}
