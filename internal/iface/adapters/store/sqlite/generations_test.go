package sqlite_test

import (
	"context"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
	domain2 "code.eitanity.com/kanonarion/internal/iface/domain"
	"code.eitanity.com/kanonarion/internal/iface/ports"
)

// The generation keys are read from the columns, once per key: two
// re-extractions at one pipeline are one generation, and a second pipeline is
// another. Pipelines are ordered as versions, so 0.10.0 follows 0.3.0.
func TestListInterfaceGenerations_NamesEachKeyOnce(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	artefact := fetchtest.ZipArtefact("same-bytes=").String()
	a := mustCoord(t, "example.com/a", "v1.0.0")
	b := mustCoord(t, "example.com/b", "v1.0.0")
	newer := ledgerRecord(t, a, domain2.InterfaceStatusExtracted, []string{"New"},
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), artefact)
	newer.PipelineVersion = "0.10.0"
	var h domain2.InterfaceRecordHasher
	newer, err := h.SetContentHash(newer)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []domain2.InterfaceRecord{
		newer,
		ledgerRecord(t, a, domain2.InterfaceStatusPartial, []string{"New"},
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, a, domain2.InterfaceStatusExtracted, []string{"New"},
			time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, b, domain2.InterfaceStatusExtracted, []string{"Open"},
			time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), artefact),
	} {
		if perr := s.PutInterfaceRecord(ctx, r); perr != nil {
			t.Fatalf("PutInterfaceRecord: %v", perr)
		}
	}
	got, err := s.ListInterfaceGenerations(ctx)
	if err != nil {
		t.Fatalf("ListInterfaceGenerations: %v", err)
	}
	want := []ports.InterfaceGeneration{
		{ModulePath: "example.com/a", ModuleVersion: "v1.0.0", PipelineVersion: ledgerPipeline},
		{ModulePath: "example.com/a", ModuleVersion: "v1.0.0", PipelineVersion: "0.10.0"},
		{ModulePath: "example.com/b", ModuleVersion: "v1.0.0", PipelineVersion: ledgerPipeline},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("generation %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestListInterfaceGenerations_ClosedStoreIsAnError(t *testing.T) {
	s := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListInterfaceGenerations(context.Background()); err == nil {
		t.Error("a store that cannot be read must report it")
	}
}
