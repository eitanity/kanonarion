// Package interrupt tells an operation that stopped because the operator
// cancelled the run apart from one that failed on its own terms, and counts the
// former so the run can state the interruption once.
//
// A cancelled fetch is not a failed fetch. Logging each one under the failure's
// event name buried the run's closing lines under hundreds of warnings and made
// an interrupted run indistinguishable from a broken one, so a site that meets a
// cancellation logs it at debug under its own name and records it here instead.
package interrupt

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"
)

// Kind names what was in flight when the run was interrupted.
type Kind int

// The kinds, in the order the run's statement lists them.
const (
	ModuleFetch Kind = iota
	StdlibCustody
	ModuleScan
	CallGraph
	Extraction
	StalenessLookup
	ModuleCopy
	numKinds
)

var nouns = [numKinds][2]string{
	ModuleFetch:     {"module fetch", "module fetches"},
	StdlibCustody:   {"stdlib custody check", "stdlib custody checks"},
	ModuleScan:      {"module scan", "module scans"},
	CallGraph:       {"call-graph build", "call-graph builds"},
	Extraction:      {"extraction stage", "extraction stages"},
	StalenessLookup: {"latest-version lookup", "latest-version lookups"},
	ModuleCopy:      {"module copy", "module copies"},
}

// counts is process-wide for the same reason the store's contention counter
// is: the statement is about the run, and a run holds several use cases.
var counts [numKinds]atomic.Int64

// Cancelled reports whether err is the result of ctx being cancelled rather
// than a failure of the operation itself: the cancellation, or a child process
// killed by a signal, which is how a cancelled context ends one. A deadline the
// program set is not a cancellation: it is the operation failing to finish in
// its budget.
func Cancelled(ctx context.Context, err error) bool {
	if err == nil || !Stopped(ctx) {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		if ws, ok := ee.Sys().(interface{ Signaled() bool }); ok && ws.Signaled() {
			return true
		}
	}
	return false
}

// Stopped reports whether ctx was cancelled, for a summary built from many
// operations' outcomes where no single error is to hand.
func Stopped(ctx context.Context) bool {
	return errors.Is(ctx.Err(), context.Canceled)
}

// Note records that one operation of kind k was stopped by the cancellation.
func Note(k Kind) {
	if k >= 0 && k < numKinds {
		counts[k].Add(1)
	}
}

// Reset zeroes every count. A command reports once and exits; tests reuse the
// process.
func Reset() {
	for i := range counts {
		counts[i].Store(0)
	}
}

// Statement renders the one line an interrupted run prints: the cause, and what
// was in flight as counts. A run stopped between operations names no counts.
func Statement(cause error) string {
	var parts []string
	for k := range numKinds {
		if n := counts[k].Load(); n > 0 {
			noun := nouns[k][1]
			if n == 1 {
				noun = nouns[k][0]
			}
			parts = append(parts, fmt.Sprintf("%d %s", n, noun))
		}
	}
	line := "interrupted"
	if cause != nil {
		line += " (" + cause.Error() + ")"
	}
	if len(parts) > 0 {
		line += "; stopped with " + strings.Join(parts, ", ") + " in flight"
	}
	return line
}
