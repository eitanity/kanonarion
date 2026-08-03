package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

// jsonDocumentBytes returns the size, in bytes, of the canonical JSON document
// for v — the indented form the --json path writes, plus the trailing newline
// it writes with it.
//
// This is the single definition of "context size" in the command. Every surface
// that reports one — --size-only on a coordinate, on a walk, on a go.mod scope,
// and the hint printed under a rendered text block — measures this same
// quantity, so two answers to the same question about the same module cannot
// disagree. Measuring the rendered text instead reports the size of the digest
// on screen, which is not what a caller deciding whether to pull the context is
// budgeting against.
func jsonDocumentBytes(v any) (int, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("encoding context: %w", err)
	}
	return len(raw) + 1, nil
}

// printDocumentSize measures v's JSON document and reports its estimated token
// count and byte size, in the active output format.
func printDocumentSize(v any, jsonOut bool, stdout io.Writer) error {
	byteCount, err := jsonDocumentBytes(v)
	if err != nil {
		return err
	}
	if jsonOut {
		type sizeResult struct {
			EstimatedTokens int `json:"estimated_tokens"`
			ByteCount       int `json:"byte_count"`
		}
		enc := json.NewEncoder(stdout)
		if err := enc.Encode(sizeResult{EstimatedTokens: byteCount / 4, ByteCount: byteCount}); err != nil {
			return fmt.Errorf("encoding size: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "~%d tokens (%d bytes)\n", byteCount/4, byteCount); err != nil {
		return fmt.Errorf("writing size: %w", err)
	}
	return nil
}

// contextModuleSize is one module's entry in a multi-module size report.
type contextModuleSize struct {
	Module          string `json:"module"`
	EstimatedTokens int    `json:"estimated_tokens"`
	ByteCount       int    `json:"byte_count"`
}

// contextSizeReport accumulates per-module context document sizes for the
// multi-module paths (--walk-id, --gomod, and inspect --gomod). Every path that
// answers "how big is this module set's context" answers in one shape — a total
// plus a per-module breakdown — so the same question about a different module
// set does not acquire a second vocabulary.
type contextSizeReport struct {
	totalBytes int
	modules    []contextModuleSize
}

// add measures one module's context document and records it against the total.
func (r *contextSizeReport) add(module string, out contextOutput) error {
	byteCount, err := jsonDocumentBytes(out)
	if err != nil {
		return fmt.Errorf("%s: %w", module, err)
	}
	r.totalBytes += byteCount
	r.modules = append(r.modules, contextModuleSize{
		Module:          module,
		EstimatedTokens: byteCount / 4,
		ByteCount:       byteCount,
	})
	return nil
}

// write emits the accumulated report in the active output format.
func (r *contextSizeReport) write(jsonOut bool, stdout io.Writer) error {
	if jsonOut {
		type sizeReport struct {
			EstimatedTokens int                 `json:"estimated_tokens"`
			ByteCount       int                 `json:"byte_count"`
			ModuleCount     int                 `json:"module_count"`
			Modules         []contextModuleSize `json:"modules"`
		}
		modules := r.modules
		if modules == nil {
			modules = []contextModuleSize{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sizeReport{
			EstimatedTokens: r.totalBytes / 4,
			ByteCount:       r.totalBytes,
			ModuleCount:     len(modules),
			Modules:         modules,
		}); err != nil {
			return fmt.Errorf("encoding size report: %w", err)
		}
		return nil
	}

	if _, err := fmt.Fprintf(stdout, "Total: ~%d tokens (%d bytes) across %d modules\n\nPer-module breakdown:\n",
		r.totalBytes/4, r.totalBytes, len(r.modules)); err != nil {
		return fmt.Errorf("writing size summary: %w", err)
	}
	for _, m := range r.modules {
		if _, err := fmt.Fprintf(stdout, "  %s: ~%d tokens (%d bytes)\n", m.Module, m.EstimatedTokens, m.ByteCount); err != nil {
			return fmt.Errorf("writing size entry: %w", err)
		}
	}
	return nil
}
