package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/clock"
	"github.com/eitanity/kanonarion/internal/coordinate"
	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"
)

// probeStubResolver answers the same-major question and then gives the named
// outcome for every major-suffixed path above it.
type probeStubResolver struct {
	latest string
	// majorErr is what a /vN path resolves to. ErrPathAbsent is the ordinary
	// negative; anything else is a failure.
	majorErr error
}

func (p probeStubResolver) LatestInfo(_ context.Context, path string) (staleports.LatestInfo, error) {
	if strings.Contains(path, "/v") {
		return staleports.LatestInfo{}, p.majorErr
	}
	return staleports.LatestInfo{Version: p.latest, Time: time.Now()}, nil
}

// TestAuditStaleness_ProbeOutcomesReachStderrOnlyWhenTheLookupFailed
//
// Most modules have no next major, so the ordinary negative is the COMMON
// outcome and must be silent. It used to arrive on stderr as
// "probing <mod> for a newer major: ... decoding latest response for <mod>/v2:
// EOF" — the common case reported as a failure, in the vocabulary of a JSON
// decoder. The genuine failure still warns, and now says so.
//
// The staleness answer itself is unchanged in every case: that is the control
// which keeps this a change of what is reported, not of what is measured.
func TestAuditStaleness_ProbeOutcomesReachStderrOnlyWhenTheLookupFailed(t *testing.T) {
	tests := []struct {
		name     string
		majorErr error
		wantWarn bool
	}{
		{
			name:     "no newer major is a normal negative and is silent",
			majorErr: fmt.Errorf("%w: example.com/mod/v2", staleports.ErrPathAbsent),
			wantWarn: false,
		},
		{
			name:     "an empty proxy response is a failed lookup and warns",
			majorErr: fmt.Errorf("%w: proxy returned an empty response for example.com/mod/v2@latest", staleports.ErrLookupFailed),
			wantWarn: true,
		},
		{
			name:     "a transport failure warns",
			majorErr: fmt.Errorf("%w: %w", staleports.ErrLookupFailed, errors.New("dial tcp: connection refused")),
			wantWarn: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.2.0")
			if err != nil {
				t.Fatalf("NewModuleCoordinate: %v", err)
			}
			resolver := staleapp.NewResolver(
				probeStubResolver{latest: "v1.4.0", majorErr: tc.majorErr},
				nil, clock.System{}, time.Hour, false)

			var res auditModuleResult
			var stderr bytes.Buffer
			applyAuditStaleness(context.Background(), &res, coord, resolver, &stderr)

			// The control: the same-major answer is the same in all three cases.
			if res.IsLatest == nil || *res.IsLatest {
				t.Fatalf("same-major answer changed: is_latest %v", res.IsLatest)
			}
			if res.LatestVersion != "v1.4.0" {
				t.Errorf("latest_version = %q, want v1.4.0", res.LatestVersion)
			}
			if res.NewerMajorModule != "" {
				t.Errorf("a newer major was reported where none resolved: %q", res.NewerMajorModule)
			}
			// And "probed, none exists" is never claimed for a probe that failed.
			if got := res.MajorProbed; got != !tc.wantWarn {
				t.Errorf("major_probed = %v, want %v", got, !tc.wantWarn)
			}

			warned := stderr.Len() > 0
			if warned != tc.wantWarn {
				t.Fatalf("stderr = %q, want a warning: %v", stderr.String(), tc.wantWarn)
			}
			if !warned {
				return
			}
			if !strings.Contains(stderr.String(), "module proxy lookup failed") {
				t.Errorf("the warning does not say the lookup failed: %q", stderr.String())
			}
			if strings.Contains(stderr.String(), "EOF") {
				t.Errorf("the warning names a decode failure: %q", stderr.String())
			}
		})
	}
}

// TestLatestModules_AProbeFailureDoesNotDiscardTheAnswer
//
// `latest <module>` resolved the same-major answer and then returned the
// probe's error, so a failed second question about a DIFFERENT path threw away
// a measurement that had succeeded — and, with several modules named, every
// module after it. The other two readers of this resolver (the audit row and
// the --gomod row) already report the half they have and leave MajorProbed
// false; this one now does too.
func TestLatestModules_AProbeFailureDoesNotDiscardTheAnswer(t *testing.T) {
	resolver := staleapp.NewResolver(
		probeStubResolver{
			latest:   "v1.4.0",
			majorErr: fmt.Errorf("%w: %w", staleports.ErrLookupFailed, errors.New("dial tcp: connection refused")),
		},
		nil, clock.System{}, time.Hour, false)

	var stdout, stderr bytes.Buffer
	err := runLatestModules(context.Background(),
		[]string{"example.com/first", "example.com/second"}, resolver, &stdout, &stderr)
	if err != nil {
		t.Fatalf("a failed newer-major probe failed the whole command: %v", err)
	}
	// Both modules are answered, not just the one before the failure.
	for _, want := range []string{"example.com/first@v1.4.0", "example.com/second@v1.4.0"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing %q:\n%s", want, stdout.String())
		}
	}
	// The failure is reported, and says the lookup failed.
	if !strings.Contains(stderr.String(), "module proxy lookup failed") {
		t.Errorf("the probe failure was swallowed: %q", stderr.String())
	}
	// The row says the question was not answered. It must not claim a newer
	// major, and it must not render as the clean negative either: those two are
	// the same bytes only if the failed probe prints nothing at all.
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if !strings.Contains(line, "newer major: not probed") {
			t.Errorf("a failed probe renders as a clean answer:\n%s", line)
		}
		if strings.Contains(line, "newer major: example.com") {
			t.Errorf("a newer-major claim was made for a probe that failed:\n%s", line)
		}
	}
}
