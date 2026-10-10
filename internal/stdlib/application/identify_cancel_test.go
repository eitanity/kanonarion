package application_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/stdlib/application"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

// A licence classification the run's cancellation stopped is not a classifier
// that failed: neither acquisition route logs it as one. A classifier that
// genuinely failed still warns on both.
func TestAcquire_ClassifierStoppedByTheCancellationIsNotLogged(t *testing.T) {
	tarball := buildTarball(t, map[string]string{"go/LICENSE": "BSD-3-Clause text"})
	routes := map[string]func(ctx context.Context, lic fakeLicense, log *slog.Logger) error{
		"online": func(ctx context.Context, lic fakeLicense, log *slog.Logger) error {
			m := fakeManifest{releases: []domain.Release{{
				Version: causeVersion,
				Files:   []domain.ReleaseFile{{Kind: "source", SHA256: sha256hex(tarball)}},
			}}}
			_, err := application.NewAcquirer(m, &fakeTarball{data: tarball}, &fakeCommits{commit: "c0ffee"}, lic,
				newMemStore(), nil, fixedClock{t: time.Unix(1_700_000_000, 0)}, log).
				Acquire(ctx, causeVersion, application.Options{})
			return err //nolint:wrapcheck // the test reads the acquirer's own error
		},
		"local": func(ctx context.Context, lic fakeLicense, log *slog.Logger) error {
			src := fakeSource{fsys: stdlibSrcFS(), license: []byte("BSD-3-Clause text")}
			_, err := application.NewLocalAcquirer(&fakeToolchain{goRoot: "/opt/go", version: "go1.26.4"}, src, lic,
				newMemStore(), fixedClock{t: time.Unix(1_700_000_000, 0)}, log).
				Acquire(ctx, "go1.26.4", application.Options{})
			return err //nolint:wrapcheck // as above
		},
	}
	for name, acquire := range routes {
		for _, tc := range []struct {
			name      string
			err       error
			cancelled bool
		}{
			{"cancelled", fmt.Errorf("license detection cancelled: %w", context.Canceled), true},
			{"genuine failure", errors.New("classifier unavailable"), false},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				var logs bytes.Buffer
				ctx, cancel := context.WithCancel(t.Context())
				if tc.cancelled {
					cancel()
				}
				defer cancel()
				_ = acquire(ctx, fakeLicense{err: tc.err}, slog.New(slog.NewTextHandler(&logs, nil))) //nolint:errcheck // the subject is what it logs
				logged := strings.Contains(logs.String(), "stdlib.license.identify_failed")
				if tc.cancelled == logged {
					t.Errorf("cancelled=%v but logged=%v:\n%s", tc.cancelled, logged, logs.String())
				}
			})
		}
	}
}
