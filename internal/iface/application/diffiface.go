package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

// DiffInterfaceUseCase loads two interface records by coordinate and returns
// the deterministic delta between them. The comparison itself is
// domain.DiffRecords, a pure function; this use case only orchestrates the
// loads.
type DiffInterfaceUseCase struct {
	store ifaceports.InterfaceStore
	// reader answers the questions about signature TEXT that the domain must
	// not answer itself; see ifaceports.SignatureReader.
	reader          ifaceports.SignatureReader
	pipelineVersion string
}

// NewDiffInterfaceUseCase constructs the diff use case.
//
// A nil reader is accepted and produces the conservative comparison: no
// signature difference is discounted as spelling and no registry surface is
// detected. It overstates the delta rather than quietly understating it.
func NewDiffInterfaceUseCase(store ifaceports.InterfaceStore, reader ifaceports.SignatureReader) *DiffInterfaceUseCase {
	return &DiffInterfaceUseCase{store: store, reader: reader, pipelineVersion: PipelineVersion}
}

// ErrInterfaceRecordNotFound is returned when one of the requested coordinates
// has no interface record in the store. It is a sentinel so CLI callers can map
// it to a deterministic exit code, and it names the command that produces the
// record it is missing.
type ErrInterfaceRecordNotFound struct {
	Coordinate coordinate.ModuleCoordinate
}

func (e *ErrInterfaceRecordNotFound) Error() string {
	return fmt.Sprintf("interface record not found: %s — run: kanonarion interface %s",
		e.Coordinate, e.Coordinate)
}

// Diff returns the deterministic delta between the interface records for coordA
// (the baseline) and coordB (the newer). Both records must exist; a missing one
// yields *ErrInterfaceRecordNotFound rather than an empty delta, because "no
// record" and "no change" are opposite answers.
func (uc *DiffInterfaceUseCase) Diff(
	ctx context.Context,
	coordA, coordB coordinate.ModuleCoordinate,
) (domain.InterfaceDiff, error) {
	a, foundA, err := uc.store.GetInterfaceRecord(ctx, coordA, uc.pipelineVersion)
	if err != nil {
		return domain.InterfaceDiff{}, fmt.Errorf("loading interface record for %s: %w", coordA, err)
	}
	if !foundA {
		return domain.InterfaceDiff{}, &ErrInterfaceRecordNotFound{Coordinate: coordA}
	}

	b, foundB, err := uc.store.GetInterfaceRecord(ctx, coordB, uc.pipelineVersion)
	if err != nil {
		return domain.InterfaceDiff{}, fmt.Errorf("loading interface record for %s: %w", coordB, err)
	}
	if !foundB {
		return domain.InterfaceDiff{}, &ErrInterfaceRecordNotFound{Coordinate: coordB}
	}

	if uc.reader == nil {
		return domain.DiffRecords(a, b, nil), nil
	}
	return domain.DiffRecords(a, b, uc.reader), nil
}
