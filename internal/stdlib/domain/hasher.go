package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// FactsHasher computes and embeds a content hash into a Facts measurement. The
// hash covers the canonical JSON serialisation with ContentHash zeroed.
//
// stdlib_facts was, until this existed, the only record table in the store whose
// rows carried no seal: every other domain hashes its record and verifies the
// hash on read, so a row edited in place is detected. These rows could be edited
// with nothing to notice, which matters more here than almost anywhere else —
// the row is the chain of custody for the compiler that builds everything else.
type FactsHasher struct{}

// SetContentHash computes the canonical hash of f (with ContentHash zeroed),
// sets f.ContentHash, and returns the updated measurement.
func (FactsHasher) SetContentHash(f Facts) (Facts, error) {
	f.ContentHash = ""
	data, err := marshalCanonical(f)
	if err != nil {
		return Facts{}, fmt.Errorf("marshalling for hash: %w", err)
	}
	sum := sha256.Sum256(data)
	f.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	return f, nil
}

// VerifyContentHash re-computes the canonical hash and checks it matches
// f.ContentHash.
//
// A measurement carrying no hash is NOT an error. Rows written before the seal
// existed legitimately have none, and refusing them on read would make an
// un-migrated store unreadable; ServesUnsealed reports the distinction so a
// caller can tell "not sealed" from "seal verified".
func (FactsHasher) VerifyContentHash(f Facts) error {
	if f.ContentHash == "" {
		return nil
	}
	saved := f.ContentHash
	f.ContentHash = ""
	data, err := marshalCanonical(f)
	if err != nil {
		return fmt.Errorf("marshalling for verification: %w", err)
	}
	sum := sha256.Sum256(data)
	expected := "sha256:" + hex.EncodeToString(sum[:])
	if saved != expected {
		return fmt.Errorf("content hash mismatch: stored %q, computed %q", saved, expected)
	}
	return nil
}

// Marshal returns the canonical JSON bytes for a measurement, including its
// ContentHash. Call SetContentHash before this.
func (FactsHasher) Marshal(f Facts) ([]byte, error) { return marshalCanonical(f) }

// IsSealed reports whether a measurement carries a content hash at all. It is
// the distinction between "verified" and "nothing to verify", which a bare error
// return cannot express.
func IsSealed(f Facts) bool { return f.ContentHash != "" }

// canonicalFacts is the wire shape the hash is taken over. Fields are ordered
// alphabetically by JSON tag, as every other record domain here does, so the
// encoding does not depend on the Go struct's field order.
type canonicalFacts struct {
	AcquiredAt string `json:"acquired_at"`
	// AcquisitionRoute and ContentHash are omitted when empty so records written
	// before they existed marshal to the bytes they always did. An absent route is
	// the "not recorded" value, not a third route.
	AcquisitionRoute   string `json:"acquisition_route,omitempty"`
	ContentHash        string `json:"content_hash"`
	ContentLocation    string `json:"content_location,omitempty"`
	GoVersion          string `json:"go_version"`
	LicenseSPDX        string `json:"license_spdx,omitempty"`
	PublishedSHA256    string `json:"published_sha256,omitempty"`
	SHA256             string `json:"sha256"`
	SHA384             string `json:"sha384"`
	SHA512             string `json:"sha512"`
	SourceURL          string `json:"source_url,omitempty"`
	VCSCommit          string `json:"vcs_commit,omitempty"`
	VCSRef             string `json:"vcs_ref,omitempty"`
	VCSURL             string `json:"vcs_url,omitempty"`
	VerificationDetail string `json:"verification_detail,omitempty"`
	VerificationStatus string `json:"verification_status"`
}

func marshalCanonical(f Facts) ([]byte, error) {
	c := canonicalFacts{
		AcquiredAt:         f.AcquiredAt.UTC().Format(time.RFC3339),
		AcquisitionRoute:   string(f.AcquisitionRoute),
		ContentHash:        f.ContentHash,
		ContentLocation:    f.ContentLocation,
		GoVersion:          f.GoVersion,
		LicenseSPDX:        f.LicenseSPDX,
		PublishedSHA256:    f.PublishedSHA256,
		SHA256:             f.Digests.SHA256,
		SHA384:             f.Digests.SHA384,
		SHA512:             f.Digests.SHA512,
		SourceURL:          f.SourceURL,
		VCSCommit:          f.VCSCommit,
		VCSRef:             f.VCSRef,
		VCSURL:             f.VCSURL,
		VerificationDetail: f.VerificationDetail,
		VerificationStatus: string(f.VerificationStatus),
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return nil, fmt.Errorf("marshalling canonical stdlib facts: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
