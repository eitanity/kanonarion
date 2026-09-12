package ports

import "time"

// ProgressPrefix marks a line on a call-graph child's stderr as a report that
// the analysis has moved on. It is the whole protocol between a spawned child
// and the parent bounding it: the child writes one line per phase transition,
// the parent resets its stall clock when one arrives and copies it to the
// operator's stderr verbatim.
//
// It reads like the other narrations this tool writes ("walk progress: ",
// "extract progress: ") because it IS one — the same line serves the operator
// running `kanonarion callgraph` by hand and the parent deciding whether the
// child is still working.
const ProgressPrefix = "callgraph progress: "

// DefaultStallWindow is how long a call-graph child may go without reporting
// progress before the parent ends it.
//
// It bounds a STALLED subprocess, which is what the wall-clock
// deadline it replaced was chosen to do and could not: elapsed time is not
// evidence of a hang, so a healthy analysis of a large module under a busy
// worker pool was killed while a genuinely wedged one was given the same ten
// minutes. Ten minutes of NO PROGRESS keeps that bound exactly and stops
// measuring the wrong thing — a child descheduled by contention still reports a
// phase when it resumes; a stalled one never does.
//
// It must exceed the longest phase an analysis can spend silent, which is the
// package load: on a cold module cache the go command extracts the whole
// transitive closure inside a single call this process cannot see into.
const DefaultStallWindow = 10 * time.Minute

// DefaultCeiling is the wall-clock backstop, in force whatever the child
// reports. It is a last resort rather than a policy: the heaviest analysis
// observed on a mainstream project took just over seven minutes, so nothing
// real reaches this, and an operator who wants to give a module more can raise
// it. See the --callgraph-timeout flag.
const DefaultCeiling = 2 * time.Hour
