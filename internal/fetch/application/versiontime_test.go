package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// sourceTime is a version time as a source might report it: not in UTC, and
// with sub-second precision, both of which the record must keep as one instant.
var sourceTime = time.Date(2026, 9, 8, 18, 29, 55, 500000000, time.FixedZone("CEST", 2*3600))

const sourceTimeRecorded = "2026-09-08T16:29:55.5Z"

func withInfoTime(p *fakeProxy, coord coordinate.ModuleCoordinate, at time.Time) *fakeProxy {
	p.infos = map[string]ports.ModuleInfo{coord.String(): {Version: coord.Version(), Time: at}}
	return p
}

// Every acquisition route records the time its source gave for the version, and
// a source that gave none records it as unknown, never as the zero time.
func TestExecute_RecordsTheVersionTimeOnEveryRoute(t *testing.T) {
	zip, mod := fetchtest.H1("vt-zip="), fetchtest.H1("vt-mod=")
	anchor := func() *fakeSumDB {
		return &fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zip, GoModHash: mod}}
	}
	cases := []struct {
		name  string
		path  string
		at    time.Time
		setup func(p *fakeProxy) *application.FetchModuleUseCase
		want  string
	}{
		{"proxy", "github.com/example/mod", sourceTime, func(p *fakeProxy) *application.FetchModuleUseCase {
			return newUseCaseWithSumDB(p, &fakeVCS{}, newFakeBlob(), newFakeFacts(), anchor())
		}, sourceTimeRecorded},
		{"proxy with no time", "github.com/example/mod", time.Time{}, func(p *fakeProxy) *application.FetchModuleUseCase {
			return newUseCaseWithSumDB(p, &fakeVCS{}, newFakeBlob(), newFakeFacts(), anchor())
		}, ""},
		{"module cache", "github.com/example/mod", sourceTime, func(p *fakeProxy) *application.FetchModuleUseCase {
			return newUseCaseWithSumDB(p, &fakeVCS{}, newModcacheBlob(t), newFakeFacts(), anchor()).WithModcacheMode()
		}, sourceTimeRecorded},
		{"module cache with no time", "github.com/example/mod", time.Time{}, func(p *fakeProxy) *application.FetchModuleUseCase {
			return newUseCaseWithSumDB(p, &fakeVCS{}, newModcacheBlob(t), newFakeFacts(), anchor()).WithModcacheMode()
		}, ""},
		{"private module", "corp.example.com/a", sourceTime, func(p *fakeProxy) *application.FetchModuleUseCase {
			return newUseCaseWithSumDB(p, &fakeVCS{}, newModcacheBlob(t), newFakeFacts(), anchor()).
				WithPrivateModules(corpIsPrivate, anchor())
		}, sourceTimeRecorded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coord := coordinatetest.MustNew(tc.path, "v1.0.0")
			uc := tc.setup(withInfoTime(downloadWithHashes(coord, zip, mod), coord, tc.at))
			res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := string(res.Record.VersionTime); got != tc.want {
				t.Errorf("VersionTime = %q, want %q", got, tc.want)
			}
		})
	}
}

// A module cache whose .info cannot be read still yields its measurement, with
// the version time unknown: the cache's go.sum anchor, not the time, decides it.
func TestExecuteModcache_UnreadableInfoRecordsAnUnknownTime(t *testing.T) {
	coord := modcacheCoord(t)
	zip, mod := fetchtest.H1("vt-zip="), fetchtest.H1("vt-mod=")
	p := downloadWithHashes(coord, zip, mod)
	p.infoErr = errors.New("decoding module-cache info: unexpected end of JSON input")
	uc := newUseCaseWithSumDB(p, &fakeVCS{}, newModcacheBlob(t), newFakeFacts(),
		&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zip, GoModHash: mod}}).WithModcacheMode()
	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.VersionTime != "" {
		t.Errorf("VersionTime = %q, want unknown", res.Record.VersionTime)
	}
}
