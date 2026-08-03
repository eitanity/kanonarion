package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/driver"
	extractapp "github.com/eitanity/kanonarion/internal/extract/application"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// bothPathsGoMod is the project's go.mod, held as a constant so the walk request
// the container path builds by hand carries exactly the bytes the driver reads
// off disk for itself.
const bothPathsGoMod = "module example.test/proj\n\ngo 1.22\n"

const bothPathsLicence = `MIT License

Copyright (c) 2026 Example Author

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
`

// writeBothPathsProject writes a dependency-free Go module working tree with one
// exported declaration, a licence, and one example. Dependency-free keeps the
// walk offline; the three files make each extraction stage produce a real record
// rather than an empty one.
func writeBothPathsProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":      bothPathsGoMod,
		"lib.go":      "// Package proj is the project root.\npackage proj\n\n// Answer returns 42.\nfunc Answer() int { return 42 }\n",
		"lib_test.go": "package proj_test\n\nfunc ExampleAnswer() {\n}\n",
		"LICENSE":     bothPathsLicence,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

// auditEventCounts tallies the assurance log under storeRoot by event type. An
// absent log is an empty tally: a run that appended nothing leaves no file.
func auditEventCounts(t *testing.T, storeRoot string) map[string]int {
	t.Helper()
	path := filepath.Join(storeRoot, "audit.jsonl")
	f, err := os.Open(filepath.Clean(path))
	if os.IsNotExist(err) {
		return map[string]int{}
	}
	if err != nil {
		t.Fatalf("opening audit log: %v", err)
	}
	defer func() { _ = f.Close() }()

	counts := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var envelope struct {
			EventType string `json:"event_type"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			t.Fatalf("decoding audit line %q: %v", string(line), err)
		}
		counts[envelope.EventType]++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	return counts
}

func sortedEventTypes(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// The stages the comparison drives. Callgraph is excluded because the extract
// pipeline spawns the kanonarion binary as a subprocess for it, and an in-process
// test run has no such binary; its events are covered by the callgraph context's
// own tests.
var bothPathsStages = []string{"license", "interface", "example"}

// TestAuditParity_ContainerAndLibraryPathsAppendIdentically is the acceptance
// guard for the second half of the gap: the library composition root wired an
// audit sink for the fetch pair only, so the same operation driven through
// pkg/kanonarion left a quieter assurance log than the CLI did — silently, since
// nothing compares the two.
//
// The same project is walked and extracted twice into two separate stores, once
// through the CLI container's use cases and once through the library driver, and
// the two logs must agree event type for event type.
func TestAuditParity_ContainerAndLibraryPathsAppendIdentically(t *testing.T) {
	projDir := writeBothPathsProject(t)
	ctx := context.Background()

	// ---- CLI container path ----
	cliRoot := t.TempDir()
	ctr, cleanup, err := NewContainer(cliRoot, "", "", false, domain.DefaultConfig(), quietLogger())
	if err != nil {
		t.Fatalf("NewContainer: %v", err)
	}
	defer func() { _ = cleanup() }()

	target, err := coordinate.NewLocalCoordinate("example.test/proj")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	walkRes, err := ctr.ExecuteWalk.Execute(ctx, walkapp.WalkRequest{
		Target:           target,
		Scope:            walkdomain.WalkScopeComplete,
		ProjectMode:      true,
		MainModuleGoMod:  []byte(bothPathsGoMod),
		AnalyseLocalRoot: true,
		ProjectDir:       projDir,
		ResolutionDir:    projDir,
	})
	if err != nil {
		t.Fatalf("container walk: %v", err)
	}
	if _, err := ctr.Extract.Execute(ctx, extractapp.ExtractRequest{
		WalkID: walkRes.Record.ID,
		Stages: bothPathsStages,
	}); err != nil {
		t.Fatalf("container extract: %v", err)
	}
	cliCounts := auditEventCounts(t, cliRoot)

	// ---- library (pkg/kanonarion) path ----
	libRoot := t.TempDir()
	drv, libCleanup, err := composition.NewDriver(libRoot)
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	defer func() { _ = libCleanup() }()

	if _, err := drv.LocalWalkExtract.Run(ctx, driver.LocalWalkExtractRequest{
		Dir:              projDir,
		Stages:           bothPathsStages,
		AnalyseLocalRoot: true,
	}); err != nil {
		t.Fatalf("library walk+extract: %v", err)
	}
	libCounts := auditEventCounts(t, libRoot)

	// The operation is the same, so the logs must be. A missing type on either
	// side is a path that writes records nothing can later attest to.
	for _, et := range sortedEventTypes(cliCounts) {
		if libCounts[et] != cliCounts[et] {
			t.Errorf("event %q: CLI path appended %d, library path appended %d", et, cliCounts[et], libCounts[et])
		}
	}
	for _, et := range sortedEventTypes(libCounts) {
		if _, ok := cliCounts[et]; !ok {
			t.Errorf("event %q: library path appended %d, CLI path appended none", et, libCounts[et])
		}
	}

	// The comparison is only meaningful if the operation appended anything at
	// all, and specifically the stages this batch made audible.
	for _, et := range []string{
		"fact_record_written",
		"walk_completed",
		"license_extracted",
		"interface_extracted",
		"examples_extracted",
		"extraction_run_completed",
	} {
		if cliCounts[et] == 0 {
			t.Errorf("CLI path appended no %q event; the parity assertions above are vacuous for it", et)
		}
	}
}
