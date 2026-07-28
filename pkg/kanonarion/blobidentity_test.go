package kanonarion_test

import (
	"testing"

	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// An external implementer of BlobStore cannot import anything internal, so the
// façade constructor is the only way it can build the address its own methods
// are handed. These exercise it from the published surface alone, on the terms
// test/consumer does — the accept path there, both refusals here.
func TestNewBlobIdentity_BuildsAnAddressFromThePublishedSurfaceAlone(t *testing.T) {
	t.Parallel()

	hash, err := kanonarion.NewModuleHash("h1", "published-surface=")
	if err != nil {
		t.Fatalf("NewModuleHash: %v", err)
	}

	identity, err := kanonarion.NewBlobIdentity(kanonarion.BlobKindZip, hash)
	if err != nil {
		t.Fatalf("NewBlobIdentity: %v", err)
	}
	if got, want := identity.String(), "zip:h1:published-surface="; got != want {
		t.Errorf("identity renders as %q, want %q", got, want)
	}
	if identity.Kind() != kanonarion.BlobKindZip {
		t.Errorf("Kind() = %q, want %q", identity.Kind(), kanonarion.BlobKindZip)
	}
}

// The refusals are what unexporting the fields bought: a struct literal could
// state a hash with no kind, and the resulting address collides the module zip
// with the standalone go.mod. A consumer must be told, not silently handed one.
func TestNewBlobIdentity_RefusesAnAddressNoReaderCouldReadBack(t *testing.T) {
	t.Parallel()

	hash, err := kanonarion.NewModuleHash("h1", "published-surface=")
	if err != nil {
		t.Fatalf("NewModuleHash: %v", err)
	}

	cases := []struct {
		name string
		kind kanonarion.BlobKind
		hash kanonarion.ModuleHash
	}{
		{"no kind", "", hash},
		{"unknown kind", "tarball", hash},
		{"zero hash", kanonarion.BlobKindZip, kanonarion.ModuleHash{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			identity, err := kanonarion.NewBlobIdentity(tc.kind, tc.hash)
			if err == nil {
				t.Fatalf("NewBlobIdentity(%q, %q) = %q, want a refusal", tc.kind, tc.hash, identity)
			}
			if !identity.IsZero() {
				t.Errorf("NewBlobIdentity(%q, %q) returned a usable identity alongside its refusal", tc.kind, tc.hash)
			}
		})
	}
}
