package application_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

func toolchainSet() domain.ToolchainAdvisorySet {
	return domain.ToolchainAdvisorySet{
		KeyPresent: true,
		Advisories: []domain.ToolchainAdvisory{{
			ID:     "GO-2026-4984",
			Ranges: []domain.ToolchainRange{{Introduced: "0", Fixed: "1.25.10"}, {Introduced: "1.26.0-0", Fixed: "1.26.3"}},
		}},
	}
}

// TestJudgeToolchain_ReadsTheStoredSnapshotOnce: the judgment is derived at
// report time on every run, so its cost has to be one local read of a snapshot
// already held — never a fetch, and never one read per module.
func TestJudgeToolchain_ReadsTheStoredSnapshotOnce(t *testing.T) {
	db := &fakeDatabase{toolchainSet: toolchainSet()}
	uc, _ := refreshFixture(t, db)

	j, err := uc.JudgeToolchain(t.Context(), vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"), "go1.26.2")
	if err != nil {
		t.Fatalf("JudgeToolchain: %v", err)
	}
	if j.Status != domain.ToolchainAffected {
		t.Errorf("status = %q, want %q", j.Status, domain.ToolchainAffected)
	}
	if got := db.toolchainCalls.Load(); got != 1 {
		t.Errorf("the snapshot was read %d times, want exactly 1", got)
	}
	if db.snapshotCalls.Load() != 0 {
		t.Errorf("the judgment downloaded a database snapshot; it must read the stored one only")
	}
}

// A missing input is answered without touching the store at all: there is
// nothing to read a judgment out of, and the reason says which input is absent.
func TestJudgeToolchain_MissingInputsSkipTheRead(t *testing.T) {
	db := &fakeDatabase{toolchainSet: toolchainSet()}
	uc, _ := refreshFixture(t, db)

	noVersion, err := uc.JudgeToolchain(t.Context(), vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"), "")
	if err != nil {
		t.Fatalf("JudgeToolchain: %v", err)
	}
	if noVersion.Reason != domain.ToolchainReasonNoVersion {
		t.Errorf("reason = %q, want %q", noVersion.Reason, domain.ToolchainReasonNoVersion)
	}

	noSnapshot, err := uc.JudgeToolchain(t.Context(), domain.DatabaseSnapshot{}, "go1.26.5")
	if err != nil {
		t.Fatalf("JudgeToolchain: %v", err)
	}
	if noSnapshot.Reason != domain.ToolchainReasonNoSnapshot {
		t.Errorf("reason = %q, want %q", noSnapshot.Reason, domain.ToolchainReasonNoSnapshot)
	}
	if got := db.toolchainCalls.Load(); got != 0 {
		t.Errorf("the store was read %d times for a judgment with a missing input", got)
	}
}

// A snapshot that cannot be read is an error naming the snapshot, not a quiet
// clear: the caller renders it as a toolchain that could not be judged.
func TestJudgeToolchain_AnUnreadableSnapshotIsReported(t *testing.T) {
	db := &fakeDatabase{toolchainErr: errors.New("stored snapshot is truncated")}
	uc, _ := refreshFixture(t, db)

	_, err := uc.JudgeToolchain(t.Context(), vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"), "go1.26.5")
	if err == nil {
		t.Fatal("an unreadable snapshot produced a judgment")
	}
	if !strings.Contains(err.Error(), "2026-07-27T20:14:16Z") {
		t.Errorf("the failure does not name the snapshot it could not read: %v", err)
	}
}
