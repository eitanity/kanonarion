package consumer_test

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/pkg/kanonarion"
)

// analysedCoordinate is a small published module with no dependencies.
const analysedCoordinate = "github.com/google/uuid@v1.6.0"

// runIdentity names every field the comparison leaves out, wherever it
// occurs: which walk or run a record belongs to, when that run did something,
// and how long it took. RecordID and ContentHash are content hashes, which
// validate their own record and are never compared across runs.
var runIdentity = map[string]bool{
	"ID": true, "WalkID": true,
	"StartedAt": true, "CompletedAt": true, "ResolvedAt": true, "FirstFetchedAt": true,
	"FetchedAt": true, "LatestFetchedAt": true, "EstablishedAt": true, "ScannedAt": true, "FirstScannedAt": true,
	"DurationMs": true,
	"RecordID":   true, "ContentHash": true,
}

// keysOnly names maps whose values are content hashes: which keys are present
// is compared, and the hashes are not.
var keysOnly = map[string]bool{"WalkScanRun.PerModuleResults": true}

// The coordinate entry records, for a fixed module version, what `kanonarion
// inspect` records on the same version, and the rescan entry what
// `vuln-scan-rescan` records on the walk each produced.
func TestConsumer_CoordinateAnalysisAndRescanRecordWhatTheCLIRecords(t *testing.T) {
	if os.Getenv("KANONARION_NETWORK_TESTS") == "" {
		t.Skip("set KANONARION_NETWORK_TESTS=1 to analyse a published module over the network")
	}
	cliRoot, libRoot := t.TempDir(), t.TempDir()

	if _, stderr, code := runKanonarion(t, cliRoot, nil, "inspect", analysedCoordinate, "--no-progress"); code != 0 {
		t.Fatalf("kanonarion inspect exited %d:\n%s", code, stderr)
	}
	cliWalkID := onlyWalk(t, cliRoot)
	if _, stderr, code := runKanonarion(t, cliRoot, nil, "vuln-scan-rescan", cliWalkID, "--no-progress"); code > 1 {
		t.Fatalf("kanonarion vuln-scan-rescan exited %d:\n%s", code, stderr)
	}
	libWalkID := analyseAndRescan(t, libRoot)

	cli, lib := readRecords(t, cliRoot, cliWalkID), readRecords(t, libRoot, libWalkID)
	if len(cli.extraction.PerModuleResults) == 0 || len(cli.records[0]) == 0 || len(cli.records[1]) == 0 {
		t.Fatal("the CLI's store holds no per-module results; the comparison would be vacuous")
	}
	var diffs []string
	diffs = append(diffs, diff("walk", cli.walk, lib.walk)...)
	diffs = append(diffs, diff("extraction", cli.extraction, lib.extraction)...)
	for i, name := range []string{"scan run", "rescan run"} {
		diffs = append(diffs, diff(name, cli.runs[i], lib.runs[i])...)
		diffs = append(diffs, diff(name+" records", cli.records[i], lib.records[i])...)
	}
	for _, d := range diffs {
		t.Error(d)
	}
}

// analyseAndRescan runs the two entries on a driver over root, as $USER, and
// returns the walk they recorded.
func analyseAndRescan(t *testing.T, root string) string {
	t.Helper()
	path, version, _ := strings.Cut(analysedCoordinate, "@")
	coord, err := kanonarion.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatal(err)
	}
	drv, cleanup, err := kanonarion.OpenDriver(root)
	if err != nil {
		t.Fatalf("OpenDriver: %v", err)
	}
	defer closeStore(t, cleanup)
	operator := os.Getenv("USER")
	res, err := drv.CoordinateAnalysis.Run(t.Context(), kanonarion.CoordinateAnalysisRequest{Coordinate: coord, Operator: operator})
	if err != nil {
		t.Fatalf("CoordinateAnalysis.Run: %v", err)
	}
	if _, err := drv.Rescan.Run(t.Context(), kanonarion.RescanRequest{WalkID: res.Walk.ID, Operator: operator}); err != nil {
		t.Fatalf("Rescan.Run: %v", err)
	}
	return res.Walk.ID
}

// closeStore runs a store's cleanup, failing the test on its error.
func closeStore(t *testing.T, cleanup func() error) {
	t.Helper()
	if err := cleanup(); err != nil {
		t.Errorf("cleanup: %v", err)
	}
}

// storedRecords is one store's records for one walk: the scan runs oldest
// first, each with its vulnerability records ordered by coordinate.
type storedRecords struct {
	walk       kanonarion.WalkRecord
	extraction kanonarion.ExtractionRun
	runs       []kanonarion.WalkScanRun
	records    [][]kanonarion.VulnerabilityRecord
}

func readRecords(t *testing.T, root, walkID string) storedRecords {
	t.Helper()
	q, cleanup, err := kanonarion.Open(root)
	if err != nil {
		t.Fatalf("Open %s: %v", root, err)
	}
	defer closeStore(t, cleanup)
	ctx := t.Context()
	var out storedRecords
	if out.walk, err = q.Walks.GetWalk(ctx, walkID); err != nil {
		t.Fatalf("GetWalk: %v", err)
	}
	runs, err := q.Extraction.ListExtractionRuns(ctx, kanonarion.ExtractionRunFilter{WalkID: walkID})
	if err != nil || len(runs) != 1 {
		t.Fatalf("ListExtractionRuns: %d runs, %v; want one", len(runs), err)
	}
	if out.extraction, err = q.Extraction.GetExtractionRun(ctx, runs[0].ID); err != nil {
		t.Fatalf("GetExtractionRun: %v", err)
	}
	if out.runs, err = q.ScanRuns.ListRunsForWalk(ctx, walkID); err != nil || len(out.runs) != 2 {
		t.Fatalf("ListRunsForWalk: %d runs, %v; want the scan and the rescan", len(out.runs), err)
	}
	sort.Slice(out.runs, func(i, j int) bool { return out.runs[i].StartedAt.Before(out.runs[j].StartedAt) })
	for _, run := range out.runs {
		recs, err := q.Vuln.ListRecordsForRun(ctx, run.ID)
		if err != nil {
			t.Fatalf("ListRecordsForRun: %v", err)
		}
		sort.Slice(recs, func(i, j int) bool { return recs[i].Coordinate.String() < recs[j].Coordinate.String() })
		out.records = append(out.records, recs)
	}
	return out
}

// onlyWalk is the id of the one walk the store at root holds.
func onlyWalk(t *testing.T, root string) string {
	t.Helper()
	q, cleanup, err := kanonarion.Open(root)
	if err != nil {
		t.Fatalf("Open %s: %v", root, err)
	}
	defer closeStore(t, cleanup)
	walks, err := q.Walks.ListWalks(t.Context(), kanonarion.WalkFilter{})
	if err != nil || len(walks) != 1 {
		t.Fatalf("ListWalks: %d walks, %v; want one", len(walks), err)
	}
	return walks[0].ID
}

// diff lists every path at which a and b differ, skipping runIdentity fields.
func diff(name string, a, b any) []string {
	var out []string
	diffValue(name, reflect.ValueOf(a), reflect.ValueOf(b), &out)
	return out
}

var timeType = reflect.TypeOf(time.Time{})

func diffValue(path string, a, b reflect.Value, out *[]string) {
	if a.IsValid() != b.IsValid() {
		*out = append(*out, path+": present on one side only")
		return
	}
	if !a.IsValid() {
		return
	}
	if a.Type() == timeType {
		diffTime(path, a, b, out)
		return
	}
	switch a.Kind() {
	case reflect.Struct:
		diffStruct(path, a, b, out)
	case reflect.Pointer, reflect.Interface:
		if a.IsNil() || b.IsNil() {
			if a.IsNil() != b.IsNil() {
				*out = append(*out, path+": nil on one side only")
			}
			return
		}
		diffValue(path, a.Elem(), b.Elem(), out)
	case reflect.Slice, reflect.Array:
		if a.Len() != b.Len() {
			*out = append(*out, fmt.Sprintf("%s: length %d != %d", path, a.Len(), b.Len()))
			return
		}
		for i := 0; i < a.Len(); i++ {
			diffValue(fmt.Sprintf("%s[%d]", path, i), a.Index(i), b.Index(i), out)
		}
	case reflect.Map:
		if a.Len() != b.Len() {
			*out = append(*out, fmt.Sprintf("%s: %d keys != %d", path, a.Len(), b.Len()))
		}
		for _, k := range a.MapKeys() {
			diffValue(fmt.Sprintf("%s[%v]", path, k), a.MapIndex(k), b.MapIndex(k), out)
		}
	default:
		diffScalar(path, a, b, out)
	}
}

func diffStruct(path string, a, b reflect.Value, out *[]string) {
	for i := 0; i < a.NumField(); i++ {
		f := a.Type().Field(i)
		switch {
		case runIdentity[f.Name]:
		case keysOnly[a.Type().Name()+"."+f.Name]:
			diffKeys(path+"."+f.Name, a.Field(i), b.Field(i), out)
		default:
			diffValue(path+"."+f.Name, a.Field(i), b.Field(i), out)
		}
	}
}

// diffTime compares instants; an unexported time.Time (a value type's own
// field) cannot be read and is reached through its accessors' records instead.
func diffTime(path string, a, b reflect.Value, out *[]string) {
	if !a.CanInterface() || !b.CanInterface() {
		return
	}
	ta, okA := a.Interface().(time.Time)
	tb, okB := b.Interface().(time.Time)
	if okA && okB && !ta.Equal(tb) {
		*out = append(*out, fmt.Sprintf("%s: %v != %v", path, ta, tb))
	}
}

func diffScalar(path string, a, b reflect.Value, out *[]string) {
	var equal bool
	switch a.Kind() {
	case reflect.String:
		equal = a.String() == b.String()
	case reflect.Bool:
		equal = a.Bool() == b.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		equal = a.Int() == b.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		equal = a.Uint() == b.Uint()
	case reflect.Float32, reflect.Float64:
		equal = a.Float() == b.Float()
	default:
		*out = append(*out, fmt.Sprintf("%s: %s is not compared", path, a.Kind()))
		return
	}
	if !equal {
		*out = append(*out, fmt.Sprintf("%s: %v != %v", path, a, b))
	}
}

func diffKeys(path string, a, b reflect.Value, out *[]string) {
	keys := func(m reflect.Value) []string {
		var ks []string
		for _, k := range m.MapKeys() {
			ks = append(ks, fmt.Sprint(k))
		}
		sort.Strings(ks)
		return ks
	}
	if ka, kb := keys(a), keys(b); !reflect.DeepEqual(ka, kb) {
		*out = append(*out, fmt.Sprintf("%s: keys %v != %v", path, ka, kb))
	}
}
