package domain

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// sealTestRecord is a record the append-side reuse check would actually compare:
// it names the artefact it read, so NamesAnalysedContent holds and the
// comparison is reached rather than refused before it.
func sealTestRecord(t *testing.T, packages int) InterfaceRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	pkgs := make([]PackageInterface, packages)
	for i := range pkgs {
		pkgs[i] = PackageInterface{
			ImportPath: fmt.Sprintf("example.com/mod/pkg%d", i),
			Name:       fmt.Sprintf("pkg%d", i),
			Funcs: []FuncDecl{
				{Name: fmt.Sprintf("Func%d", i)},
			},
		}
	}
	r := InterfaceRecord{
		SchemaVersion:    InterfaceSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		Packages:         pkgs,
		OverallStatus:    InterfaceStatusExtracted,
		BuildFrame:       BuildFrame{GOOS: "linux", GOARCH: "amd64"},
		Toolchain:        "go1.26.6",
		ExtractedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "0.6.0",
		ArtefactIdentity: "zip:h1:tree-one=",
	}
	if !NamesAnalysedContent(r) {
		t.Fatal("the fixture names no analysed content, so the comparison is never reached")
	}
	return r
}

// TestMeasurementSeal_IsTheComparisonItReplaced.
//
// The reuse check used to marshal both records whole and compare the bytes, once
// per candidate. It now encodes each record once and compares digests, which is a
// different statement — "the same seal over the compared fields" rather than
// "the same bytes". For this question the two coincide, and that is shown here
// rather than assumed.
func TestMeasurementSeal_IsTheComparisonItReplaced(t *testing.T) {
	t.Parallel()

	variants := map[string]func(r InterfaceRecord) InterfaceRecord{
		"unchanged":   func(r InterfaceRecord) InterfaceRecord { return r },
		"later clock": func(r InterfaceRecord) InterfaceRecord { r.ExtractedAt = r.ExtractedAt.Add(time.Hour); return r },
		"another seal": func(r InterfaceRecord) InterfaceRecord {
			r.ContentHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			return r
		},
		"another fetch record": func(r InterfaceRecord) InterfaceRecord { r.SourceContentHash = "sha256:beef"; return r },
		"one package fewer":    func(r InterfaceRecord) InterfaceRecord { r.Packages = r.Packages[:len(r.Packages)-1]; return r },
		"one symbol renamed": func(r InterfaceRecord) InterfaceRecord {
			p := append([]PackageInterface(nil), r.Packages...)
			funcs := append([]FuncDecl(nil), p[0].Funcs...)
			funcs[0].Name = "Renamed"
			p[0].Funcs = funcs
			r.Packages = p
			return r
		},
		"another frame":     func(r InterfaceRecord) InterfaceRecord { r.BuildFrame.GOARCH = "arm64"; return r },
		"another toolchain": func(r InterfaceRecord) InterfaceRecord { r.Toolchain = "go1.26.5"; return r },
		"another artefact":  func(r InterfaceRecord) InterfaceRecord { r.ArtefactIdentity = "zip:h1:tree-two="; return r },
		"another status":    func(r InterfaceRecord) InterfaceRecord { r.OverallStatus = InterfaceStatusPartial; return r },
	}

	var agreed, differed int
	for name, mutate := range variants {
		base := sealTestRecord(t, 3)
		other := mutate(sealTestRecord(t, 3))

		ab, err := marshalCanonical(forMeasurementComparison(base))
		if err != nil {
			t.Fatalf("%s: marshalCanonical: %v", name, err)
		}
		bb, err := marshalCanonical(forMeasurementComparison(other))
		if err != nil {
			t.Fatalf("%s: marshalCanonical: %v", name, err)
		}
		sameBytes := bytes.Equal(ab, bb)

		sealed, named, err := SealMeasurement(base)
		if err != nil || !named {
			t.Fatalf("%s: SealMeasurement: err=%v named=%v", name, err, named)
		}
		sameSeal, err := sealed.SameAs(other)
		if err != nil {
			t.Fatalf("%s: SameAs: %v", name, err)
		}
		if sameSeal != sameBytes {
			t.Errorf("%s: the seal says %v and the bytes say %v", name, sameSeal, sameBytes)
		}

		pairwise, err := SameMeasurement(base, other)
		if err != nil {
			t.Fatalf("%s: SameMeasurement: %v", name, err)
		}
		if pairwise != sameBytes {
			t.Errorf("%s: SameMeasurement says %v and the bytes say %v", name, pairwise, sameBytes)
		}

		if sameBytes {
			agreed++
		} else {
			differed++
		}
	}
	if agreed == 0 || differed == 0 {
		t.Errorf("the population is one-sided: %d agreed, %d differed", agreed, differed)
	}
}

// TestMeasurementSeal_AnUnsealedComparisonRefuses. A seal is taken OVER a
// record, so the zero value was taken over none, and answering "not the same
// measurement" would report a comparison that never happened — which on this
// path means appending another generation.
func TestMeasurementSeal_AnUnsealedComparisonRefuses(t *testing.T) {
	t.Parallel()

	if _, err := (MeasurementSeal{}).SameAs(sealTestRecord(t, 1)); !errors.Is(err, ErrUnsealedMeasurement) {
		t.Errorf("SameAs on a zero seal = %v, want ErrUnsealedMeasurement", err)
	}
}

// TestSealMeasurement_ARecordNamingNoAnalysedContentSealsNothing, on both sides.
// The naming rule is what makes dropping SourceContentHash sound, so it is
// refused before a seal exists rather than inside the comparison.
func TestSealMeasurement_ARecordNamingNoAnalysedContentSealsNothing(t *testing.T) {
	t.Parallel()

	unnamed := sealTestRecord(t, 1)
	unnamed.ArtefactIdentity = ""
	if NamesAnalysedContent(unnamed) {
		t.Fatal("the fixture still names its analysed content")
	}
	if _, named, err := SealMeasurement(unnamed); err != nil || named {
		t.Errorf("SealMeasurement of an unnamed record: named=%v err=%v", named, err)
	}

	sealed, named, err := SealMeasurement(sealTestRecord(t, 1))
	if err != nil || !named {
		t.Fatalf("SealMeasurement: err=%v named=%v", err, named)
	}
	same, err := sealed.SameAs(unnamed)
	if err != nil {
		t.Fatalf("SameAs: %v", err)
	}
	if same {
		t.Error("a held record naming no analysed content was read as the same measurement")
	}
}

// TestMeasurementSeal_AMarshalFailureIsNotAgreement covers the guard on the
// terms this package's other digests are held to: a seal that failed to compute
// must never come back as a value two records could match on. On this path a
// false match means declining to append a measurement the ledger does not hold.
//
// The marshal is a fault seam: no value this shape carries can make json.Marshal
// fail today, so this proves the error is propagated rather than that the
// failure is reachable.
func TestMeasurementSeal_AMarshalFailureIsNotAgreement(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	injected := errors.New("injected marshal failure")

	sealed, named, err := SealMeasurement(sealTestRecord(t, 1))
	if err != nil || !named {
		t.Fatalf("SealMeasurement: err=%v named=%v", err, named)
	}
	held := sealTestRecord(t, 1)

	canonicalMarshal = func(any) ([]byte, error) { return nil, injected }

	if _, _, err := SealMeasurement(sealTestRecord(t, 1)); !errors.Is(err, injected) {
		t.Errorf("SealMeasurement error = %v, want it to wrap the injected error", err)
	}
	same, err := sealed.SameAs(held)
	if !errors.Is(err, injected) {
		t.Errorf("SameAs error = %v, want it to wrap the injected error", err)
	}
	if same {
		t.Error("a failed seal reported the same measurement")
	}
	if _, err := SameMeasurement(sealTestRecord(t, 1), held); !errors.Is(err, injected) {
		t.Errorf("SameMeasurement error = %v, want it to wrap the injected error", err)
	}
}
