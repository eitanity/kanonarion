package gosum

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"golang.org/x/mod/sumdb"
)

// fuzzRT returns the same fuzzer-controlled body (HTTP 200) for every sumdb
// remote read (signed note, /lookup, Merkle tiles), with no network.
type fuzzRT struct{ body []byte }

func (rt fuzzRT) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(rt.body)),
		Header:     make(http.Header),
	}, nil
}

// FuzzSumDBNote fuzzes the checksum-DB signed-note parsing and Merkle-tree
// verification path (golang.org/x/mod/sumdb driven through our ops) plus our
// own /lookup line parsing in Client.Lookup. sumdb is a trust anchor (relates
// ): the remote bytes are attacker-controlled, and the fuzzer holds no
// private key for the configured ed25519 verifier.
//
// Invariants asserted:
// - No input panics.
// - Fuzzer-controlled remote bytes never verify: Lookup must never report
// Available=true, because a valid signed note requires a signature from
// the configured key that the fuzzer cannot forge.
//
// Run locally with:
//
//	go test -run=NONE -fuzz=FuzzSumDBNote./internal/adapters/sumdb/gosum
func FuzzSumDBNote(f *testing.F) {
	// Shaped like a signed note: text, blank line, "— <keyname> <b64sig>".
	f.Add([]byte("go.sum database tree\n3\nNANz4lXg1n+Q==\n\n— sum.golang.org+033de0ae+abcdEFGH\n"))
	// Tampered: plausible structure, garbage signature.
	f.Add([]byte("go.sum database tree\n42\nDEADBEEF==\n\n— sum.golang.org+033de0ae+AAAAAAAAAAAAAAAA\n"))
	// /lookup-shaped body: note + module hash lines.
	f.Add([]byte("rsc.io/quote v1.5.2 h1:aaaa=\nrsc.io/quote v1.5.2/go.mod h1:bbbb=\n\ngo.sum database tree\n5\nXXXX=\n\n— sum.golang.org+033de0ae+sig\n"))
	// Wrong field counts / malformed hash lines.
	f.Add([]byte("rsc.io/quote v1.5.2\nonly two\n\n\n"))
	// Empty / null / binary.
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte("\x00\x01\x02 not a note"))
	// Oversized body.
	f.Add(bytes.Repeat([]byte("A"), 1<<16))
	// Missing separator line.
	f.Add([]byte("go.sum database tree\n1\nhash\n— sum.golang.org+033de0ae+sig\n"))

	coord, err := domain2.NewModuleCoordinate("rsc.io/quote", "v1.5.2")
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		// Neutralise env so Lookup doesn't short-circuit on GOSUMDB=off or a
		// GOPRIVATE/GONOSUMCHECK pattern.
		t.Setenv("GOSUMDB", "")
		t.Setenv("GOPRIVATE", "")
		t.Setenv("GONOSUMCHECK", "")
		t.Setenv("GONOSUMDB", "")

		o := &ops{
			server:   defaultServer,
			key:      defaultKey,
			cacheDir: t.TempDir(),
			httpCli:  &http.Client{Transport: fuzzRT{body: body}},
		}
		c := &Client{sc: sumdb.NewClient(o), server: defaultServer}

		res := c.Lookup(context.Background(), coord)
		if res.Available {
			t.Fatalf("sumdb trust anchor violated: fuzzer-controlled remote bytes verified as Available for input %q", body)
		}
	})
}
