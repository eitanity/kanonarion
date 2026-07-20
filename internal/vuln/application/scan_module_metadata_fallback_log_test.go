package application_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// The govulncheck adapter records its non-zero exit at debug and hands the error
// up for classification; severity is decided here, in the application, by reason.
// This locks that split: an out-of-toolchain module (its isolated build selects a
// version outside the project toolchain) reads as an expected metadata-only
// outcome at info, while a genuine build incompatibility still surfaces a warn.
func TestScanModule_MetadataFallbackLogLevelByReason(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}

	const (
		infoMsg = "vuln-scan: metadata-only, version outside the project build"
		warnMsg = "vuln-scan: source analysis unavailable, falling back to metadata"
	)

	cases := []struct {
		name        string
		errorDetail string // the scanner's ScanFailed ErrorDetail, as classified here
		wantMsg     string // the message that must be emitted…
		wantLevel   string // …at this level
		notWantMsg  string // and this message must not appear at all
	}{
		{
			name:        "out-of-toolchain reads as expected info, not warn",
			errorDetail: "govulncheck exited with error: exit status 1; stderr: loading packages: example.com/dep@v2.0.0: module lookup disabled by GOPROXY=off",
			wantMsg:     infoMsg,
			wantLevel:   "INFO",
			notWantMsg:  warnMsg,
		},
		{
			name:        "genuine build incompatibility still warns",
			errorDetail: "govulncheck exited with error: exit status 1; stderr: loading packages: build constraints exclude all Go files in /tmp/mod",
			wantMsg:     warnMsg,
			wantLevel:   "WARN",
			notWantMsg:  infoMsg,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			facts := newFakeFacts()
			blobs := newFakeBlob()
			vulnStore := newFakeVulnStore()
			db := &fakeDatabase{
				snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now},
				content:  "vulndb content",
			}
			scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{
				coord.String(): {
					Coordinate:    coord,
					OverallStatus: domain.StatusScanFailed,
					ErrorDetail:   tc.errorDetail,
				},
			}}

			handle, err := blobs.Put(ctx, strings.NewReader("zip content"))
			if err != nil {
				t.Fatalf("blobs.Put: %v", err)
			}
			if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
				ModulePath:      coord.Path,
				ModuleVersion:   coord.Version,
				PipelineVersion: "v1",
				ContentLocation: string(handle),
			}); err != nil {
				t.Fatalf("PutFetchRecord: %v", err)
			}

			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
			uc := application.NewScanModuleUseCase(
				facts, blobs, vulnStore, nil, scanner, db, nil, fixedClock{t: now}, "v1", "v1", logger,
			)

			res, err := uc.Scan(ctx, application.ScanModuleParams{
				Coordinate: coord,
				WalkID:     "walk-1",
				Force:      true, // skip the metadata pre-filter so the source-scan/fallback path runs
			})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			// The build incompatibility routes to a metadata-only Unscannable coverage
			// gap, never a confident clean.
			if res.OverallStatus != domain.StatusUnscannable {
				t.Fatalf("OverallStatus = %s, want %s", res.OverallStatus, domain.StatusUnscannable)
			}

			logs := buf.String()
			assertLogLevel(t, logs, tc.wantMsg, tc.wantLevel)
			if strings.Contains(logs, tc.notWantMsg) {
				t.Errorf("message %q must not appear for this reason; logs:\n%s", tc.notWantMsg, logs)
			}
		})
	}
}

// assertLogLevel finds the slog text line carrying msgSubstr and asserts it was
// emitted at wantLevel (e.g. "INFO", "WARN").
func assertLogLevel(t *testing.T, logs, msgSubstr, wantLevel string) {
	t.Helper()
	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, msgSubstr) {
			if !strings.Contains(line, "level="+wantLevel) {
				t.Errorf("message %q logged at wrong level; want level=%s, line:\n%s", msgSubstr, wantLevel, line)
			}
			return
		}
	}
	t.Errorf("expected a log line containing %q; logs:\n%s", msgSubstr, logs)
}
