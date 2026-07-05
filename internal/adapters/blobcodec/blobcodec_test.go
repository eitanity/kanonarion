package blobcodec_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
)

func TestRoundTrip(t *testing.T) {
	payload := []byte(`{"content_hash":"sha256:abc","coordinate":{"path":"ex.com/m","version":"v1.0.0"}}`)
	compressed := blobcodec.Encode(payload)
	if bytes.Equal(compressed, payload) {
		t.Fatal("Encode returned input unchanged")
	}
	got, err := blobcodec.Decode(compressed)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, payload)
	}
}

func TestDecode_RawJSON_BackwardCompat(t *testing.T) {
	raw := []byte(`{"content_hash":"sha256:abc"}`)
	got, err := blobcodec.Decode(raw)
	if err != nil {
		t.Fatalf("Decode raw JSON: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("raw JSON should pass through unchanged")
	}
}

func TestDecode_CorruptedBlob(t *testing.T) {
	// Craft bytes that look like zstd magic but are garbage.
	bad := []byte{0x28, 0xb5, 0x2f, 0xfd, 0xde, 0xad, 0xbe, 0xef}
	if _, err := blobcodec.Decode(bad); err == nil {
		t.Error("expected error decoding corrupt blob")
	}
}

func TestEncode_SizeReduction(t *testing.T) {
	// Repetitive JSON compresses well.
	payload := []byte(`{"symbol":"` + strings.Repeat("example.com/mod.FuncAlpha", 1000) + `"}`)
	compressed := blobcodec.Encode(payload)
	if len(compressed) >= len(payload) {
		t.Errorf("compressed size %d >= original %d; expected reduction", len(compressed), len(payload))
	}
}
