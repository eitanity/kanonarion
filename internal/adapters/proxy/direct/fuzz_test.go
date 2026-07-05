package direct

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// fuzzRT returns the same fuzzer-controlled body (HTTP 200) for every request,
// so the proxy's response-parsing paths run against adversarial bytes with no
// network.
type fuzzRT struct{ body []byte }

func (rt fuzzRT) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(rt.body)),
		Header:     make(http.Header),
	}, nil
}

func smallZip(tb testing.TB) []byte {
	tb.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("rsc.io/quote@v1.5.2/go.mod")
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := io.WriteString(f, "module rsc.io/quote\n"); err != nil {
		tb.Fatal(err)
	}
	if err := w.Close(); err != nil {
		tb.Fatal(err)
	}
	return buf.Bytes()
}

// FuzzProxyResponses fuzzes the module-proxy response handling: the.info /
// @latest JSON decoders, the @v/list line parser, and the zip-hashing path in
// Download. Proxy responses are untrusted network input (relates); the
// adapter must never panic and must never trust a proxy-supplied hash — every
// hash is recomputed from received bytes. Invariant asserted: no call panics
// on any response body.
//
// Run locally with:
//
//	go test -run=NONE -fuzz=FuzzProxyResponses./internal/adapters/proxy/direct
func FuzzProxyResponses(f *testing.F) {
	// Well-formed.info / @latest JSON.
	f.Add([]byte(`{"Version":"v1.5.2","Time":"2018-02-14T00:00:00Z"}`))
	f.Add([]byte(`{"Version":"v1.5.2","Time":"2018-02-14T00:00:00Z","Origin":{"VCS":"git","URL":"https://example.com","Ref":"refs/tags/v1.5.2","Hash":"abc"}}`))
	// Valid @v/list body.
	f.Add([]byte("v1.0.0\nv1.5.2\nv1.2.0\n"))
	// Empty / whitespace-only list.
	f.Add([]byte("\n\n  \n"))
	// Malformed JSON variants.
	f.Add([]byte(`{"Version":42,"Time":"not-a-time"}`))
	f.Add([]byte(`{"Version":`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte("\x00\x01 garbage not json"))
	// Version list with junk / huge token.
	f.Add([]byte("not-semver\n\tv1.0.0\n" + string(bytes.Repeat([]byte("9"), 4096))))
	// A real (small) module zip for the Download hashing path.
	f.Add(smallZip(f))
	// Truncated zip header.
	f.Add([]byte("PK\x03\x04 truncated"))

	coord, err := domain2.NewModuleCoordinate("rsc.io/quote", "v1.5.2")
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		p, err := New("https://proxy.example.com", false)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		p.httpClient = &http.Client{Transport: fuzzRT{body: body}}

		ctx := context.Background()
		// Each parser must return (zero, error) or a value — never panic.
		_, _ = p.Info(ctx, coord)
		_, _ = p.LatestInfo(ctx, "rsc.io/quote")
		_, _ = p.ListVersions(ctx, "rsc.io/quote")
		_, _ = p.Download(ctx, coord)
	})
}
