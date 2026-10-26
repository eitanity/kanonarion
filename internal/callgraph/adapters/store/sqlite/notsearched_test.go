package sqlite_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/store/sqlite"
	domain2 "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
)

const (
	nsServed = "9.9.9"
	nsOld    = "0.1.0"
)

func nsCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func nsPut(t *testing.T, s *sqlite.Store, r domain2.CallGraphRecord) {
	t.Helper()
	if err := s.PutCallGraphRecord(context.Background(), r); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
}

// nsWorktree is a superseded generation of a local coordinate analysed in root.
func nsWorktree(t *testing.T, c coordinate.ModuleCoordinate, root string, at time.Time) domain2.CallGraphRecord {
	t.Helper()
	r := makeFanRecord(c, nsOld, 1)
	r.ContentHash = ""
	r.AnalysisSource = domain2.AnalysisSourceWorktree
	r.ArtefactIdentity = ""
	r.WorktreeDigest = "sha256:" + root
	r.AnalysisRoot = root
	r.ExtractedAt = at
	sealed, err := domain2.CallGraphRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// TestSupersededHolders_CrossTheChunkAndHonourScope: 450 symbols is over the
// 400-symbol chunk, a holder found only in the second chunk is still named, and
// scope narrows on the owning module.
func TestSupersededHolders_CrossTheChunkAndHonourScope(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := nsCoord(t, "example.com/a", "v1.0.0")
	b := nsCoord(t, "example.com/b", "v1.0.0")
	nsPut(t, s, makeFanRecord(a, nsOld, 450))
	nsPut(t, s, makeFanRecord(b, nsOld, 450))
	nsPut(t, s, makeFanRecord(b, nsServed, 450))

	var to, from []string
	for i := range 450 {
		to = append(to, fmt.Sprintf("example.com/mod.To%04d", i))
		from = append(from, fmt.Sprintf("example.com/mod.From%04d", i))
	}
	got, err := s.SupersededCallerHolders(ctx, to[440:], nsServed, coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil || !reflect.DeepEqual(got, []coordinate.ModuleCoordinate{a, b}) {
		t.Errorf("callers holders = %v, %v; want a and b", got, err)
	}
	got, err = s.SupersededCalleeHolders(ctx, from, nsServed, coordinate.NewModuleSet([]coordinate.ModuleCoordinate{a}), ports.EdgeQueryOptions{})
	if err != nil || !reflect.DeepEqual(got, []coordinate.ModuleCoordinate{a}) {
		t.Errorf("scoped callee holders = %v, %v; want a", got, err)
	}
	got, err = s.SupersededCallerHolders(ctx, to, nsOld, coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil || !reflect.DeepEqual(got, []coordinate.ModuleCoordinate{b}) {
		t.Errorf("holders at another pipeline than %s = %v, %v; want b", nsOld, got, err)
	}
	if got, err = s.SupersededCallerHolders(ctx, nil, nsServed, coordinate.ModuleSet{}, ports.EdgeQueryOptions{}); err != nil || got != nil {
		t.Errorf("no symbols = %v, %v; want nothing", got, err)
	}
}

// TestSupersededHolders_ExcludeTestsDropsTestEdges: a holder whose only
// touching edge is a test edge is not named under --exclude-tests.
func TestSupersededHolders_ExcludeTestsDropsTestEdges(t *testing.T) {
	s := openTestStore(t)
	c := nsCoord(t, "example.com/a", "v1.0.0")
	r := makeFanRecord(c, nsOld, 1)
	r.ContentHash = ""
	r.Nodes[0].IsTest = true
	r, err := domain2.CallGraphRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatal(err)
	}
	nsPut(t, s, r)
	ctx := context.Background()
	to := []string{"example.com/mod.To0000"}
	if got, herr := s.SupersededCallerHolders(ctx, to, nsServed, coordinate.ModuleSet{}, ports.EdgeQueryOptions{}); herr != nil || len(got) != 1 {
		t.Errorf("with tests = %v, %v; want a", got, herr)
	}
	if got, herr := s.SupersededCallerHolders(ctx, to, nsServed, coordinate.ModuleSet{}, ports.EdgeQueryOptions{ExcludeTests: true}); herr != nil || len(got) != 0 {
		t.Errorf("excluding tests = %v, %v; want nothing", got, herr)
	}
}

// TestUnservedCoordinates_NamesPipelinesAndTheNewestTree: a served coordinate
// is dropped, a repeat is answered once, a coordinate never analysed has no
// pipelines, and a local one names the newest generation's tree.
func TestUnservedCoordinates_NamesPipelinesAndTheNewestTree(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := nsCoord(t, "example.com/a", "v1.0.0")
	b := nsCoord(t, "example.com/b", "v1.0.0")
	never := nsCoord(t, "example.com/never", "v1.0.0")
	wt := nsCoord(t, "example.com/wt", coordinate.LocalVersion)
	nozip := nsCoord(t, "example.com/nozip", coordinate.LocalVersion)
	nsPut(t, s, makeFanRecord(a, nsOld, 1))
	nsPut(t, s, makeFanRecord(a, "0.10.0", 2))
	nsPut(t, s, makeFanRecord(b, nsOld, 1))
	nsPut(t, s, makeFanRecord(b, nsServed, 1))
	nsPut(t, s, nsWorktree(t, wt, "/older", testTime))
	nsPut(t, s, nsWorktree(t, wt, "/newer", testTime.Add(time.Hour)))
	nsPut(t, s, makeFanRecord(nozip, nsOld, 1))

	got, err := s.UnservedCoordinates(ctx, []coordinate.ModuleCoordinate{wt, b, a, never, a, nozip}, nsServed)
	if err != nil {
		t.Fatal(err)
	}
	want := []ports.UnservedCoordinate{
		{Coordinate: a, Pipelines: []string{nsOld, "0.10.0"}},
		{Coordinate: never},
		{Coordinate: nozip, Pipelines: []string{nsOld}},
		{Coordinate: wt, Pipelines: []string{nsOld}, AnalysisRoot: "/newer"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("UnservedCoordinates =\n%+v\nwant\n%+v", got, want)
	}
}

// TestNotSearchedReads_FailOnAClosedStore: a read that cannot run returns its
// error rather than naming nothing.
func TestNotSearchedReads_FailOnAClosedStore(t *testing.T) {
	s, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if cerr := s.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	ctx := context.Background()
	local := nsCoord(t, "example.com/wt", coordinate.LocalVersion)
	if _, herr := s.SupersededCallerHolders(ctx, []string{"x"}, nsServed, coordinate.ModuleSet{}, ports.EdgeQueryOptions{}); herr == nil {
		t.Error("holders on a closed store returned no error")
	}
	if _, uerr := s.UnservedCoordinates(ctx, []coordinate.ModuleCoordinate{local}, nsServed); uerr == nil {
		t.Error("UnservedCoordinates on a closed store returned no error")
	}
}
