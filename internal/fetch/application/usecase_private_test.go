package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// countingSumDB answers like fakeSumDB and counts the lookups made.
type countingSumDB struct {
	fakeSumDB
	lookups int
}

func (c *countingSumDB) Lookup(ctx context.Context, coord coordinate.ModuleCoordinate) ports.SumDBResult {
	c.lookups++
	return c.fakeSumDB.Lookup(ctx, coord)
}

func corpIsPrivate(path string) (string, bool) {
	return "GOPRIVATE", strings.HasPrefix(path, "corp.example.com")
}

type privateFixture struct {
	coord    coordinate.ModuleCoordinate
	proxy    *fakeProxy
	vcs      *fakeVCS
	network  *countingSumDB
	facts    *fakeFacts
	blobs    *modcacheBlob
	zip, mod domain2.ModuleHash
}

func newPrivateFixture(t *testing.T) *privateFixture {
	t.Helper()
	coord := coordinatetest.MustNew("corp.example.com/a", "v1.0.0")
	zip, mod := fetchtest.H1("corp-zip="), fetchtest.H1("corp-mod=")
	return &privateFixture{
		coord:   coord,
		proxy:   downloadWithHashes(coord, zip, mod),
		vcs:     &fakeVCS{},
		network: &countingSumDB{fakeSumDB: fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zip, GoModHash: mod}}},
		facts:   newFakeFacts(),
		blobs:   newModcacheBlob(t),
		zip:     zip,
		mod:     mod,
	}
}

func (f *privateFixture) useCase(anchor ports.SumDBClient) *application.FetchModuleUseCase {
	return newUseCaseWithSumDB(f.proxy, f.vcs, f.blobs, f.facts, f.network).WithPrivateModules(corpIsPrivate, anchor)
}

// TestExecute_PrivateModuleIsReadFromTheCacheAgainstTheProjectGoSum: a private
// module is verified against the project go.sum alone, records VerifiedByGoSum
// with the variable named and the private VCS leg, stores its bytes, and never
// reaches the checksum database or git. Its .info is read through the proxy
// port, which the router sends to the module cache, so the network proxy is
// never contacted.
func TestExecute_PrivateModuleIsReadFromTheCacheAgainstTheProjectGoSum(t *testing.T) {
	f := newPrivateFixture(t)
	anchor := &countingSumDB{fakeSumDB: fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: f.zip, GoModHash: f.mod}}}
	res, err := f.useCase(anchor).Execute(context.Background(), application.FetchRequest{Coordinate: f.coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	r := res.Record
	if r.VerificationStatus != string(domain2.VerifiedByGoSum) {
		t.Errorf("VerificationStatus = %q, want VerifiedByGoSum", r.VerificationStatus)
	}
	if r.VCSCheck != string(domain2.LegPrivateModule) {
		t.Errorf("VCSCheck = %q, want %q", r.VCSCheck, domain2.LegPrivateModule)
	}
	if !strings.Contains(r.VerificationDetail, "private module (GOPRIVATE)") {
		t.Errorf("detail %q does not name the variable in force", r.VerificationDetail)
	}
	if r.AcquisitionMode != string(domain2.AcquisitionModcache) {
		t.Errorf("AcquisitionMode = %q, want modcache", r.AcquisitionMode)
	}
	if anchor.lookups != 1 || f.network.lookups != 0 {
		t.Errorf("go.sum lookups %d, checksum-database lookups %d; want 1 and 0", anchor.lookups, f.network.lookups)
	}
	if f.vcs.resolves != 0 || f.vcs.checkouts != 0 {
		t.Errorf("git leg ran: %d resolves, %d checkouts", f.vcs.resolves, f.vcs.checkouts)
	}
	if _, ok := f.blobs.held[fetchtest.Blob(ports.BlobKindZip, f.zip).String()]; !ok {
		t.Error("the private module's zip was not stored in the blob store")
	}
}

// TestExecute_PrivateGoModOnlyIsAnchoredTheSameWay.
func TestExecute_PrivateGoModOnlyIsAnchoredTheSameWay(t *testing.T) {
	f := newPrivateFixture(t)
	anchor := &fakeSumDB{result: ports.SumDBResult{Available: true, GoModHash: f.mod}}
	res, err := f.useCase(anchor).Execute(context.Background(), application.FetchRequest{Coordinate: f.coord, GoModOnly: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Record.IsGoModOnly() || res.Record.VerificationStatus != string(domain2.VerifiedByGoSum) {
		t.Errorf("record = %+v, want a VerifiedByGoSum go.mod-only record", res.Record.FactRecord)
	}
	if !strings.Contains(res.Record.VerificationDetail, "private module (GOPRIVATE)") {
		t.Errorf("detail %q does not name the variable in force", res.Record.VerificationDetail)
	}
	if f.network.lookups != 0 {
		t.Errorf("checksum database consulted %d times for a private module", f.network.lookups)
	}
}

// TestExecute_PrivateModuleMissingFromGoSumIsRefused: the hard failure
// --from-modcache gives, with nothing written.
func TestExecute_PrivateModuleMissingFromGoSumIsRefused(t *testing.T) {
	f := newPrivateFixture(t)
	anchor := &fakeSumDB{result: ports.SumDBResult{Available: false, Reason: "no go.sum entry", Unavailability: ports.SumDBUnavailabilityPolicy}}
	_, err := f.useCase(anchor).Execute(context.Background(), application.FetchRequest{Coordinate: f.coord})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("err = %v, want ErrGoSumVerification", err)
	}
	if _, ok, rerr := f.facts.GetFetchRecord(context.Background(), f.coord, "test-0.1.0"); rerr != nil || ok {
		t.Errorf("a record was written for a module go.sum does not hold (read error: %v)", rerr)
	}
}

// TestExecute_PrivateModuleWithoutAGoSumIsRefusedBeforeAnyFetch.
func TestExecute_PrivateModuleWithoutAGoSumIsRefusedBeforeAnyFetch(t *testing.T) {
	f := newPrivateFixture(t)
	f.proxy.dlErr = errors.New("the proxy was asked")
	for _, goModOnly := range []bool{false, true} {
		_, err := f.useCase(nil).Execute(context.Background(), application.FetchRequest{Coordinate: f.coord, GoModOnly: goModOnly})
		if !errors.Is(err, application.ErrPrivateModuleUnanchored) || !strings.Contains(err.Error(), "matches GOPRIVATE") ||
			!strings.Contains(err.Error(), "kanonarion fetch corp.example.com/a@v1.0.0 --gomod") {
			t.Errorf("go.mod-only %v: err = %v, want ErrPrivateModuleUnanchored naming GOPRIVATE", goModOnly, err)
		}
	}
}

// TestExecute_PublicModuleKeepsTheProxyPath: the control. A module the matcher
// does not name is measured exactly as without the route.
func TestExecute_PublicModuleKeepsTheProxyPath(t *testing.T) {
	f := newPrivateFixture(t)
	pub := coordinatetest.MustNew("example.org/pub", "v1.0.0")
	f.proxy = downloadWithHashes(pub, f.zip, f.mod)
	anchor := &countingSumDB{}
	res, err := f.useCase(anchor).Execute(context.Background(), application.FetchRequest{Coordinate: pub, SkipVCSVerify: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.AcquisitionMode != string(domain2.AcquisitionProxy) || res.Record.VerificationStatus != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("public record = %s/%s, want proxy/VerifiedBySumDBOnly", res.Record.AcquisitionMode, res.Record.VerificationStatus)
	}
	if anchor.lookups != 0 || f.network.lookups != 1 {
		t.Errorf("go.sum lookups %d, checksum-database lookups %d; want 0 and 1", anchor.lookups, f.network.lookups)
	}
}
