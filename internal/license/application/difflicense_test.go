package application_test

import (
	"context"
	"errors"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

func diffCoord(path, ver string) fetchdomain.ModuleCoordinate {
	return fetchdomain.ModuleCoordinate{Path: path, Version: ver}
}

func seedDiffRecord(t *testing.T, store *fakeLicenseStore, path, ver, spdx string, files ...domain.LicenseFileEntry) {
	t.Helper()
	r := domain.LicenseRecord{
		Coordinate:      diffCoord(path, ver),
		PrimarySPDX:     spdx,
		OverallStatus:   domain.LicenseStatusDetected,
		LicenseFiles:    files,
		PipelineVersion: application.PipelineVersion,
	}
	if err := store.PutLicenseRecord(context.Background(), r); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// both records present — diff is returned with correct SPDX escalation.
func TestDiffLicenseUseCase_BothPresent(t *testing.T) {
	store := &fakeLicenseStore{}
	seedDiffRecord(t, store, "example.com/app", "v1.0.0", "MIT",
		domain.LicenseFileEntry{Path: "LICENSE", SPDX: "MIT",
			CopyrightStatements: []domain.CopyrightStatement{{Verbatim: "Copyright 2020 Alice"}}},
	)
	seedDiffRecord(t, store, "example.com/app", "v2.0.0", "GPL-3.0-only",
		domain.LicenseFileEntry{Path: "LICENSE", SPDX: "GPL-3.0-only",
			CopyrightStatements: []domain.CopyrightStatement{{Verbatim: "Copyright 2023 Bob"}}},
	)

	uc := application.NewDiffLicenseUseCase(store)
	diff, err := uc.Diff(context.Background(),
		diffCoord("example.com/app", "v1.0.0"),
		diffCoord("example.com/app", "v2.0.0"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff.SPDXChanged == nil {
		t.Fatal("SPDXChanged is nil, want non-nil")
	}
	if diff.SPDXChanged.From != "MIT" || diff.SPDXChanged.To != "GPL-3.0-only" {
		t.Errorf("SPDXChanged = {%q → %q}, want {MIT → GPL-3.0-only}", diff.SPDXChanged.From, diff.SPDXChanged.To)
	}
	if diff.Escalation == nil {
		t.Fatal("Escalation is nil, want non-nil for MIT → GPL-3.0-only")
	}
	if diff.Escalation.To != domain.CopyleftStrong {
		t.Errorf("Escalation.To = %v, want CopyleftStrong", diff.Escalation.To)
	}
	if len(diff.CopyrightAdded) != 1 || diff.CopyrightAdded[0].Verbatim != "Copyright 2023 Bob" {
		t.Errorf("CopyrightAdded = %v, want [Copyright 2023 Bob]", diff.CopyrightAdded)
	}
	if len(diff.CopyrightRemoved) != 1 || diff.CopyrightRemoved[0].Verbatim != "Copyright 2020 Alice" {
		t.Errorf("CopyrightRemoved = %v, want [Copyright 2020 Alice]", diff.CopyrightRemoved)
	}
}

// first coordinate has no record — ErrLicenseRecordNotFound.
func TestDiffLicenseUseCase_FirstMissing(t *testing.T) {
	store := &fakeLicenseStore{}
	seedDiffRecord(t, store, "example.com/app", "v2.0.0", "GPL-3.0-only")

	uc := application.NewDiffLicenseUseCase(store)
	_, err := uc.Diff(context.Background(),
		diffCoord("example.com/app", "v1.0.0"),
		diffCoord("example.com/app", "v2.0.0"),
	)
	var notFound *application.ErrLicenseRecordNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("error = %v, want *ErrLicenseRecordNotFound", err)
	}
	if notFound.Coordinate.Version != "v1.0.0" {
		t.Errorf("ErrLicenseRecordNotFound.Coordinate = %v, want v1.0.0", notFound.Coordinate)
	}
}

// second coordinate has no record — ErrLicenseRecordNotFound.
func TestDiffLicenseUseCase_SecondMissing(t *testing.T) {
	store := &fakeLicenseStore{}
	seedDiffRecord(t, store, "example.com/app", "v1.0.0", "MIT")

	uc := application.NewDiffLicenseUseCase(store)
	_, err := uc.Diff(context.Background(),
		diffCoord("example.com/app", "v1.0.0"),
		diffCoord("example.com/app", "v2.0.0"),
	)
	var notFound *application.ErrLicenseRecordNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("error = %v, want *ErrLicenseRecordNotFound", err)
	}
	if notFound.Coordinate.Version != "v2.0.0" {
		t.Errorf("ErrLicenseRecordNotFound.Coordinate = %v, want v2.0.0", notFound.Coordinate)
	}
}

// store error on first Get is propagated as a wrapped error (not ErrLicenseRecordNotFound).
func TestDiffLicenseUseCase_StoreError(t *testing.T) {
	sentinel := errors.New("db offline")
	// queryLicFakeStore (defined in querylicense_test.go) supports a getErr field.
	store := &queryLicFakeStore{getErr: sentinel}

	uc := application.NewDiffLicenseUseCase(store)
	_, err := uc.Diff(context.Background(),
		diffCoord("example.com/app", "v1.0.0"),
		diffCoord("example.com/app", "v2.0.0"),
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var notFound *application.ErrLicenseRecordNotFound
	if errors.As(err, &notFound) {
		t.Error("store error must not be wrapped as ErrLicenseRecordNotFound")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want to wrap %v", err, sentinel)
	}
}
