package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/iface/adapters/spelling/goast"
	"github.com/eitanity/kanonarion/internal/iface/application"
	"github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"
)

func seedDiffIfaceRecord(t *testing.T, store *fakeInterfaceStore, path, ver string, funcs ...domain.FuncDecl) coordinate.ModuleCoordinate {
	t.Helper()
	coord := coordinatetest.MustNew(path, ver)
	rec := domain.InterfaceRecord{
		Coordinate:      coord,
		OverallStatus:   domain.InterfaceStatusExtracted,
		PipelineVersion: application.PipelineVersion,
		Packages:        []domain.PackageInterface{{ImportPath: path, Name: "mod", Funcs: funcs}},
	}
	if err := store.PutInterfaceRecord(context.Background(), rec); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return coord
}

// Both records present: the use case loads them and hands the pair to the pure
// domain comparison.
func TestDiffInterfaceUseCase_BothPresent(t *testing.T) {
	store := &fakeInterfaceStore{}
	a := seedDiffIfaceRecord(t, store, "example.com/mod", "v1.0.0",
		domain.FuncDecl{Name: "Gone", Signature: "func Gone() error"},
		domain.FuncDecl{Name: "Cast", Signature: "func Cast(i interface{}) error"},
	)
	b := seedDiffIfaceRecord(t, store, "example.com/mod", "v2.0.0",
		domain.FuncDecl{Name: "Cast", Signature: "func Cast(i any) error"},
	)

	diff, err := application.NewDiffInterfaceUseCase(store, goast.Reader{}).Diff(context.Background(), a, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := diff.BreakingCount(), 1; got != want {
		t.Errorf("BreakingCount = %d, want %d", got, want)
	}
	if got, want := len(diff.Spelling), 1; got != want {
		t.Errorf("spelling = %d, want %d", got, want)
	}
	if diff.RecordA.Coordinate != a || diff.RecordB.Coordinate != b {
		t.Error("the diff does not name the records it compared")
	}
}

// A missing record is a sentinel, not an empty delta: "no record" and "no
// change" are opposite answers, and the refusal names the command that produces
// the record.
func TestDiffInterfaceUseCase_MissingRecordIsRefused(t *testing.T) {
	store := &fakeInterfaceStore{}
	a := seedDiffIfaceRecord(t, store, "example.com/mod", "v1.0.0")
	missing := coordinatetest.MustNew("example.com/mod", "v9.9.9")

	uc := application.NewDiffInterfaceUseCase(store, goast.Reader{})
	for _, tc := range []struct {
		name       string
		x, y, want coordinate.ModuleCoordinate
	}{
		{name: "A side missing", x: missing, y: a, want: missing},
		{name: "B side missing", x: a, y: missing, want: missing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := uc.Diff(context.Background(), tc.x, tc.y)
			var notFound *application.ErrInterfaceRecordNotFound
			if !errors.As(err, &notFound) {
				t.Fatalf("err = %v, want *ErrInterfaceRecordNotFound", err)
			}
			if notFound.Coordinate != tc.want {
				t.Errorf("refusal names %s, want %s", notFound.Coordinate, tc.want)
			}
			if !strings.Contains(err.Error(), "run 'kanonarion interface") {
				t.Errorf("refusal names no remedy: %v", err)
			}
		})
	}
}

// A store that fails is not a store that holds nothing. The failure is
// propagated rather than reported as an absent record.
func TestDiffInterfaceUseCase_StoreFailureIsNotAbsence(t *testing.T) {
	boom := errors.New("disk on fire")
	store := &fakeInterfaceStore{getErr: boom}
	a := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	b := coordinatetest.MustNew("example.com/mod", "v2.0.0")

	_, err := application.NewDiffInterfaceUseCase(store, goast.Reader{}).Diff(context.Background(), a, b)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the store failure", err)
	}
	var notFound *application.ErrInterfaceRecordNotFound
	if errors.As(err, &notFound) {
		t.Error("a store failure was reported as a missing record")
	}
}

// The B-side load is the second read, so its failure must also survive: an
// error handler that only guarded the first would report a broken store as a
// clean comparison against an empty record.
func TestDiffInterfaceUseCase_StoreFailureOnTheSecondRead(t *testing.T) {
	store := &failOnSecondReadStore{inner: &fakeInterfaceStore{}}
	a := seedDiffIfaceRecord(t, store.inner, "example.com/mod", "v1.0.0")
	b := seedDiffIfaceRecord(t, store.inner, "example.com/mod", "v2.0.0")

	_, err := application.NewDiffInterfaceUseCase(store, goast.Reader{}).Diff(context.Background(), a, b)
	if !errors.Is(err, errSecondRead) {
		t.Fatalf("err = %v, want the second read's failure", err)
	}
}

var errSecondRead = errors.New("second read failed")

// failOnSecondReadStore serves the first read and fails the second, which is the
// only way to reach the B-side error branch.
type failOnSecondReadStore struct {
	inner *fakeInterfaceStore
	reads int
}

func (s *failOnSecondReadStore) PutInterfaceRecord(ctx context.Context, r domain.InterfaceRecord) error {
	return s.inner.PutInterfaceRecord(ctx, r)
}

func (s *failOnSecondReadStore) GetInterfaceRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pv string) (domain.InterfaceRecord, bool, error) {
	s.reads++
	if s.reads > 1 {
		return domain.InterfaceRecord{}, false, errSecondRead
	}
	return s.inner.GetInterfaceRecord(ctx, coord, pv)
}

func (s *failOnSecondReadStore) ListInterfaceRecords(ctx context.Context, f ports.InterfaceFilter) ([]ports.InterfaceSummary, error) {
	return s.inner.ListInterfaceRecords(ctx, f)
}

func (s *failOnSecondReadStore) FindSymbol(ctx context.Context, name, pv string, scope coordinate.ModuleSet) ([]ports.SymbolRef, error) {
	return s.inner.FindSymbol(ctx, name, pv, scope)
}

var _ ports.InterfaceStore = (*failOnSecondReadStore)(nil)

// The whole thing, put together on the shape the ticket was measured against: a
// module that respells its entire surface from interface{} to any, plus two
// signatures that also stop naming their results. Every one of them is spelling
// and the breaking count is zero — the report that a naive text comparison got
// wrong 56 times.
func TestDiffInterfaceUseCase_WholeSurfaceRespeltIsZeroBreaking(t *testing.T) {
	store := &fakeInterfaceStore{}
	var oldFuncs, newFuncs []domain.FuncDecl
	const n = 56
	for i := range n {
		name := string(rune('A'+i%26)) + string(rune('a'+i/26))
		oldFuncs = append(oldFuncs, domain.FuncDecl{
			Name: name, Signature: "func " + name + "(i interface{}) (v time.Duration, err error)",
		})
		newFuncs = append(newFuncs, domain.FuncDecl{
			Name: name, Signature: "func " + name + "(i any) (time.Duration, error)",
		})
	}
	a := seedDiffIfaceRecord(t, store, "example.com/mod", "v1.4.1", oldFuncs...)
	b := seedDiffIfaceRecord(t, store, "example.com/mod", "v1.10.0", newFuncs...)

	diff, err := application.NewDiffInterfaceUseCase(store, goast.Reader{}).Diff(context.Background(), a, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := diff.BreakingCount(); got != 0 {
		t.Errorf("BreakingCount = %d, want 0", got)
	}
	if got := len(diff.Spelling); got != n {
		t.Errorf("spelling = %d, want %d", got, n)
	}
}

// Without a reader the same comparison reports every one of them as breaking.
// That is the conservative direction, and it is what the injected reader buys.
func TestDiffInterfaceUseCase_NoReaderDiscountsNothing(t *testing.T) {
	store := &fakeInterfaceStore{}
	a := seedDiffIfaceRecord(t, store, "example.com/mod", "v1.0.0",
		domain.FuncDecl{Name: "Cast", Signature: "func Cast(i interface{}) error"})
	b := seedDiffIfaceRecord(t, store, "example.com/mod", "v2.0.0",
		domain.FuncDecl{Name: "Cast", Signature: "func Cast(i any) error"})

	diff, err := application.NewDiffInterfaceUseCase(store, nil).Diff(context.Background(), a, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := diff.BreakingCount(), 1; got != want {
		t.Errorf("BreakingCount = %d, want %d", got, want)
	}
}
