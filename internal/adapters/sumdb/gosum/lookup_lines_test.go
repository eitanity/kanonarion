package gosum

import (
	"context"
	"crypto/rand"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/ports"

	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/note"
)

// newSignedServerClient points a Client at a checksum database this test signs,
// so the lookup verifies and the record lines it serves reach Lookup's parse.
func newSignedServerClient(t *testing.T, record string) *Client {
	t.Helper()
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOSUMCHECK", "")
	t.Setenv("GONOSUMDB", "")
	skey, vkey, err := note.GenerateKey(rand.Reader, "test.sumdb")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	db := sumdb.NewTestServer(skey, func(string, string) ([]byte, error) { return []byte(record), nil })
	ts := httptest.NewServer(sumdb.NewServer(db))
	t.Cleanup(ts.Close)
	host := ts.Listener.Addr().String()
	cacheDir := t.TempDir()
	return &Client{
		server: host,
		newOps: func() *ops {
			return &ops{server: host, key: vkey, cacheDir: cacheDir, httpCli: ts.Client()}
		},
	}
}

const (
	zipLine   = "golang.org/x/text v0.37.0 h1:zipzipzipzipzipzipzipzipzipzipzipzipzipzipz=\n"
	goModLine = "golang.org/x/text v0.37.0/go.mod h1:modmodmodmodmodmodmodmodmodmodmodmodmodmodm=\n"
)

// A database line whose hash does not parse says nothing settled about the
// module. It must be a failed lookup a later run asks again, naming the line,
// and never the "no zip hash" policy answer, which is settled and unretryable.
func TestLookup_AnUnparseableHashLineIsAFailedLookupNotThePolicyAnswer(t *testing.T) {
	for name, record := range map[string]string{
		"zip line without a separator":   "golang.org/x/text v0.37.0 notahash\n" + goModLine,
		"zip line as a recorded absence": "golang.org/x/text v0.37.0 :\n" + goModLine,
		"zip line without a value":       "golang.org/x/text v0.37.0 h1:\n" + goModLine,
	} {
		t.Run(name, func(t *testing.T) {
			res := newSignedServerClient(t, record).Lookup(context.Background(), testCoord)
			if res.Available {
				t.Fatalf("Lookup reported available on an unparseable line: %+v", res)
			}
			if res.Unavailability != ports.SumDBUnavailabilityFailure || !res.LookupFailed() {
				t.Errorf("Unavailability = %q, LookupFailed = %v; want a failed lookup, never a settled answer",
					res.Unavailability, res.LookupFailed())
			}
			if res.Err == nil {
				t.Error("Err = nil; a failed lookup carries its error")
			}
			if !strings.Contains(res.Reason, "record line") || !strings.Contains(res.Reason, "invalid module hash") {
				t.Errorf("Reason = %q, want it to name the line and its hash parse error", res.Reason)
			}
		})
	}
}

// Control: a database that genuinely carries no zip line keeps the policy answer.
func TestLookup_NoZipLineKeepsThePolicyAnswer(t *testing.T) {
	res := newSignedServerClient(t, goModLine).Lookup(context.Background(), testCoord)
	assertPolicy(t, res, "no zip hash")
}

// Control: a well-formed zip line answers its hash.
func TestLookup_AWellFormedZipLineIsAvailable(t *testing.T) {
	res := newSignedServerClient(t, zipLine+goModLine).Lookup(context.Background(), testCoord)
	if !res.Available || res.ZipHash.IsZero() {
		t.Fatalf("Lookup = %+v, want the zip hash available", res)
	}
}
