package govulncheck

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
)

// FuzzParseResults exercises the govulncheck subprocess output parser. The
// scanner consumes newline-delimited JSON streamed from an external
// govulncheck subprocess whose schema can drift between tool versions
// (relates, relates), so the parser must never panic on
// truncated, interleaved, garbage, or version-skewed input — it should
// degrade to "fewer/no findings", never crash.
//
// Run locally with:
//
//	go test -run=NONE -fuzz=FuzzParseResults./internal/vuln/adapters/vuln/govulncheck
func FuzzParseResults(f *testing.F) {
	// Well-formed OSV message followed by a reachable finding.
	f.Add([]byte(`{"osv":{"id":"GO-2024-0001","aliases":["CVE-2024-0001"],"summary":"boom","details":"details","published":"2024-01-02T03:04:05Z","modified":"2024-02-02T03:04:05Z"}}
{"finding":{"osv":"GO-2024-0001","fixed_version":"v1.2.3","trace":[{"module":"example.com/m","function":"Vuln","receiver":"T"},{"module":"example.com/m","function":"Caller"}]}}`))

	// Finding whose vulnerable module is a dependency (filtered out).
	f.Add([]byte(`{"finding":{"osv":"GO-2024-0002","trace":[{"module":"other.com/dep","function":"X"}]}}`))

	// stdlib pseudo-module finding.
	f.Add([]byte(`{"finding":{"osv":"GO-2024-0003","trace":[{"module":"stdlib","function":"net/http.Foo"}]}}`))

	// config/progress/sbom envelopes the parser must skip.
	f.Add([]byte(`{"config":{"version":"v1.1.0"}}
{"progress":{"message":"scanning"}}
{"sbom":{"format":"cyclonedx"}}`))

	// Truncated final line / mid-token cut-off.
	f.Add([]byte(`{"osv":{"id":"GO-2024-0001","summary":"ok"}}
{"finding":{"osv":"GO-2024-00`))

	// Interleaved garbage and blank lines between valid messages.
	f.Add([]byte(`not json at all
{"finding":{"osv":"GO-1","trace":[{"module":"m","function":"F"}]}}

<<<garbage>>>
{"osv":{"id":"GO-1","summary":"s"}}`))

	// Version-skew: legacy "symbol" key instead of "function".
	f.Add([]byte(`{"finding":{"osv":"GO-OLD","trace":[{"module":"m","symbol":"Pkg.Sym"}]}}`))

	// Wrong types where strings/arrays expected.
	f.Add([]byte(`{"osv":{"id":42,"aliases":"not-an-array","summary":["x"]}}`))
	f.Add([]byte(`{"finding":{"osv":"GO-1","trace":"not-an-array","function":1}}`))

	// Deeply nested / null / empty edge cases.
	f.Add([]byte(`{"finding":null}`))
	f.Add([]byte(`{"osv":{}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte("\x00\x01\x02 binary noise\n{not json}"))

	// Oversized details field (parser truncates to 512 bytes).
	big := append([]byte(`{"osv":{"id":"GO-BIG","summary":"s","details":"`), bytes.Repeat([]byte("A"), 4096)...)
	big = append(big, []byte(`"}}`)...)
	f.Add(big)

	disc := slog.New(slog.NewTextHandler(io.Discard, nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := New("fuzz", nil).WithLogger(disc)

		// Contract: parse never panics. It may return an error (e.g. a line
		// exceeding the scanner's 10MB cap) but must not crash, and on
		// success every returned finding must carry a non-empty ID and an
		// initialised reachability result.
		findings, err := s.parseResults(context.Background(), bytes.NewReader(data), "example.com/m")
		if err != nil {
			return
		}
		for i, fnd := range findings {
			if fnd.ID == "" {
				t.Fatalf("finding %d has empty ID for input %q", i, data)
			}
			if fnd.Reachable == nil {
				t.Fatalf("finding %d (%s) has nil Reachable for input %q", i, fnd.ID, data)
			}
		}
	})
}
