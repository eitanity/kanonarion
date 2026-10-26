package gosum

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"code.eitanity.com/kanonarion/internal/fetch/ports"

	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/note"
)

// newSignedServerClient points a Client at a checksum database this test signs,
// so the lookup verifies and the record lines it serves reach Lookup's parse.
func newSignedServerClient(t *testing.T, record string) *Client {
	t.Helper()
	c, _ := newCountingSignedServerClient(t, record)
	return c
}

// newCountingSignedServerClient is newSignedServerClient that also counts the
// HTTP requests the database receives.
func newCountingSignedServerClient(t *testing.T, record string) (*Client, *atomic.Int64) {
	t.Helper()
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOSUMCHECK", "")
	t.Setenv("GONOSUMDB", "")
	skey, vkey, err := note.GenerateKey(rand.Reader, "test.sumdb")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	db := sumdb.NewTestServer(skey, func(string, string) ([]byte, error) { return []byte(record), nil })
	requests := new(atomic.Int64)
	server := sumdb.NewServer(db)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		server.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	host := ts.Listener.Addr().String()
	cacheDir := t.TempDir()
	return &Client{
		server: host,
		newOps: func() *ops {
			return &ops{server: host, key: vkey, cacheDir: cacheDir, httpCli: ts.Client()}
		},
	}, requests
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

// The database records a go.mod hash beside the zip hash; the lookup returns
// both, each the one its own line carries.
func TestLookup_ReturnsTheZipAndGoModHashes(t *testing.T) {
	res := newSignedServerClient(t, zipLine+goModLine).Lookup(context.Background(), testCoord)
	if !res.Available {
		t.Fatalf("Lookup = %+v, want available", res)
	}
	if got, want := res.ZipHash.String(), strings.Fields(zipLine)[2]; got != want {
		t.Errorf("ZipHash = %q, want %q", got, want)
	}
	if got, want := res.GoModHash.String(), strings.Fields(goModLine)[2]; got != want {
		t.Errorf("GoModHash = %q, want %q", got, want)
	}
}

// Control: a database that answers with only a zip line keeps the go.mod hash
// zero, so the caller's "no go.mod hash" branch still serves that case.
func TestLookup_AZipLineOnlyKeepsTheGoModHashZero(t *testing.T) {
	res := newSignedServerClient(t, zipLine).Lookup(context.Background(), testCoord)
	if !res.Available || res.ZipHash.IsZero() {
		t.Fatalf("Lookup = %+v, want the zip hash available", res)
	}
	if !res.GoModHash.IsZero() {
		t.Errorf("GoModHash = %q, want zero: the database carried no go.mod line", res.GoModHash)
	}
}

// Asking for the go.mod line costs no request: a lookup makes exactly as many
// as one x/mod lookup of the zip line alone on a fresh client.
func TestLookup_TheGoModLineCostsNoExtraRequest(t *testing.T) {
	control, controlRequests := newCountingSignedServerClient(t, zipLine+goModLine)
	sc, _ := control.client()
	if _, err := sc.Lookup(testCoord.Path(), testCoord.Version()); err != nil {
		t.Fatalf("control lookup: %v", err)
	}

	c, requests := newCountingSignedServerClient(t, zipLine+goModLine)
	if res := c.Lookup(context.Background(), testCoord); !res.Available || res.GoModHash.IsZero() {
		t.Fatalf("Lookup = %+v, want both hashes", res)
	}
	if controlRequests.Load() == 0 {
		t.Fatal("control made no request; the count measures nothing")
	}
	t.Logf("checksum-database requests: zip-line lookup %d, both-line lookup %d", controlRequests.Load(), requests.Load())
	if got, want := requests.Load(), controlRequests.Load(); got != want {
		t.Errorf("lookup made %d checksum-database requests, want %d (one zip-line lookup)", got, want)
	}
}
