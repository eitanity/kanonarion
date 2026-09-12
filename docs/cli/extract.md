# `kanonarion extract` - Multi-stage Extraction

Runs a multi-stage extraction pipeline over all modules in a completed walk. This
orchestrates the individual extraction stages (licence, interface, callgraph,
example) in a deterministic order.

## Prerequisites

A walk must have been completed successfully:

```bash
kanonarion walk --policy policy.yaml
```

## Commands

### `kanonarion extract <walk-id>`

Executes the requested extraction stages for all modules in the specified walk.

```bash
kanonarion extract 01J1Z... --stages license,interface
kanonarion extract 01J1Z... --force
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--stages` | `license,interface,example` | Comma-separated list of stages to run |
| `--force` | false | Re-extract even if cached records exist for current pipeline versions |
| `--workers` | `runtime.NumCPU()` | Number of modules to process concurrently. It sizes the pool that runs the cheap in-process stages; it does **not** bound the callgraph subprocesses |
| `--callgraph-workers` | `0` (host-sized: `min(NumCPU, 4, available memory / 4 GiB)`) | How many callgraph subprocesses may run at once |
| `--callgraph-memory-ceiling` | `0` (host-sized: available memory less one 4 GiB budget, shared between the subprocesses) | How much memory one callgraph analysis may hold, in bytes, before it stops itself |
| `--json` | false | Output extraction run record as JSON |
| `--go-binary` | | Path to `go` binary (used for callgraph stage) |
| `--no-progress` | false | Suppress stderr progress output (the throttled extraction heartbeat); results and warnings are unaffected |

> **Note:** `callgraph` is not run by default. It loads each module's full
> transitive dependency closure into SSA, which costs far more than the other
> stages even with `--callgraph-workers` bounding how many run at once. Pass it
> explicitly when needed:
> ```bash
> kanonarion extract 01J1Z... --stages callgraph
> ```

### `kanonarion extract list`

Lists historical extraction runs.

```bash
kanonarion extract list
kanonarion extract list --limit 50
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for storage |
| `--limit` | `20` | Maximum number of runs to list (0 = unlimited) |
| `--offset` | `0` | Skip this many runs before listing |

When the limit bites, the listing says so on both output paths and names the
invocation that lifts it, per [Truncated listings](conventions.md#truncated-listings).

Under `--json` the command answers with one object carrying `records` and the
paging state, not a bare array, and writes nothing to stderr — see [Listing
documents](conventions.md#listing-documents).

### `kanonarion extract show <run-id>`

Displays the results of a specific extraction run, including per-module stage outcomes.

```bash
kanonarion extract show 01J1Z...
kanonarion extract show 01J1Z... --json
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for storage |
| `--json` | false | Output as JSON |

### Exit codes

`extract` exits on the status of the run it recorded, and the `--json` document
and the process agree:

| Code | Meaning |
|---|---|
| `0` | `succeeded`: every requested stage completed for every module |
| `1` | `partial`: some stage failed. The stages that ran ARE stored and usable; the `Failed stages (N)` breakdown names the module and stage of each one |
| `2` | `failed`: the run produced no usable stage |
| `3` | `cancelled`: the context ended before every module was reached |

A partial run leaves the named modules' facts permanently unmeasured until they
are re-extracted, so a pipeline step reading only the exit code must be able to
see it. `extract show` is a store-inspection command and exits `0` whatever
status it reprints.

## Orchestration Logic

1.  **Walk Loading**: The orchestrator loads the module graph from the specified `walk-id`.
2.  **Parallel Execution**: Modules are processed concurrently using a bounded worker
    pool (`--workers`, default `runtime.NumCPU()`). Stages within each module execute
    sequentially, so one worker runs every stage for its module. The callgraph
    stage carries its own bound on top of that pool (`--callgraph-workers`), because
    the cheap in-process stages have no reason to queue behind an SSA build.
3.  **Stage Dispatch**: For each module, requested stages are executed in canonical
    order. The `callgraph` stage is special (see below).
4.  **Result Aggregation**: One `ExtractionRun` record links all module-level
    results. It is written before the first module is touched, re-written every
    30 seconds while the run proceeds, and sealed when the run ends. A run whose
    process is ended by the operating system therefore still leaves a run,
    carrying status `in_progress`, a zero `completed_at`, and the modules it had
    finished. `extract show <run-id>` reads it.

## Callgraph Subprocess Isolation

The `callgraph` stage spawns a child process (`kanonarion callgraph <coord>
[--force]`) for each module, so the module's SSA closure is held outside the
run's own process and released when the child exits.

**The kernel chooses its own victim, and it is not always the child.** When it
takes the child, the parent captures the exit code and stderr, records
`StageFailed` with `status=OutOfMemory` and `cause=environment`, and continues to
the next module. When it takes the parent, the run ends there and no further
module is attempted; what the run had completed is in its checkpointed
`ExtractionRun` record (see [Orchestration Logic](#orchestration-logic)), which
still says `in_progress`.

Two things keep the parent out of the kernel's way. It reads back only what the
child's record *states* — its hash, status and failure cause — and never the
graph itself, so finishing a module costs the parent nothing that scales with the
module. And it re-reads the host before starting each analysis: while an analysis
is already running and the host reports less than the per-subprocess budget free,
the next one waits rather than starting beside it. At least one analysis always
runs, so a host permanently short of memory runs the walk one module at a time
instead of hanging.

A child exiting `1` is the exception: that is the child saying it built a graph
and knows it to be incomplete ([`callgraph` exit codes](callgraph.md#exit-codes)).
The record is in the store, so the parent classifies the record — `Partial`
counts as a stage that ran — rather than the exit status. Only an exit saying no
graph was produced makes the stage failed.

### How many subprocesses run at once

`--callgraph-workers` controls how many callgraph subprocesses run at once. It
is separate from `--workers`, which sizes the module pool: one worker runs every
stage for its module, and the licence, interface and example stages are cheap
and in-process, so bounding the pool would slow those to fix a problem neither
causes.

Each subprocess holds its own module's SSA closure, so the run's peak is roughly
`--callgraph-workers` times the smaller of the most expensive module's peak and
[the ceiling](#how-large-one-analysis-may-get), plus the parent — see
[what one run costs](callgraph.md#what-one-run-costs) for the per-module figure
this multiplies. The tail is far above the typical module: on a 172-module walk
measured here, most subprocesses held under 3 GiB and one, given the host to
itself, held **about 22 GB** — and that module is not the largest in the walk,
which costs about half as much. Cost tracks the edges the analysis resolves, not
size; see [what one run costs](callgraph.md#what-one-run-costs). The bound is what
stops several ordinary modules adding up to more than the host has; the ceiling is
what stops one expensive module doing it alone.

**A figure measured while the host is short of memory is not that module's
requirement.** A subprocess starved of headroom collects far more often and its
peak reflects the shortage, not the analysis: the module above was first recorded
at over 50 GB during a run that had driven the host to 0.8 GB available with swap
exhausted. Measured alone on an idle host it is 22 GB. Record `MemAvailable` and
swap beside any figure taken from a whole-walk run.

The parent term is small and does not grow with the walk: it holds the module
graph, the run record it is building, and one child's stderr per running
analysis. It is written down here because it used to be the largest term of the
three — the stage read each child's whole call graph back out of the store to
learn four fields from it, so the parent's memory grew with every heavy module
that *finished*, and on the 172-module walk it reached tens of gigabytes before
the kernel ended it.

Because the bound is sized once, from the host as it was when the extractor was
built, it cannot know which module a worker will reach twenty minutes later. The
headroom check above is what covers that: the bound decides how many analyses the
run will ever admit, and the check decides whether now is the moment.

The bound also protects the store. Every subprocess writes its record through
one SQLite writer, and a walk that admits one subprocess per CPU puts that many
writers on it at once. The write retry recovers a queue of a few; it does not
recover a queue of thirty-two, and a record lost to the lock is a module left
with no call graph.

The default, `0`, sizes the bound from the host:

```
callgraph-workers = max(1, min(NumCPU, 4, floor(available memory / 4 GiB)))
```

Available memory is read once, when the extractor is built (on Linux,
`MemAvailable` from `/proc/meminfo`). When the memory term lowers the bound it is
logged at info with the available bytes, the per-subprocess budget and the
result; when the reading cannot be taken at all, which is the normal case off
Linux, the bound falls back to `min(NumCPU, 4)` and says so at debug. A missing
reading never fails a run.

**The budget prices admission; the ceiling is what an analysis enforces on
itself.** The 4 GiB budget decides how many analyses may run at once and whether
now is the moment to start one. It does not bound a running analysis, and the
most expensive modules go far past it — so a second number does.

The run states the bound it adopted, what decided it, and the ceiling it shared
out, on stderr, before it starts:

```
Call-graph subprocesses: 4 at once (55.1 GiB available, 4.0 GiB budgeted each, CPU cap 4), 12.8 GiB ceiling each
```

`--no-progress` silences that line along with the rest of the narration.

Raise it only on a host with memory to spare, and expect the peak to rise by
about one more module's worth per step:

```bash
kanonarion extract 01J1Z... --stages callgraph --callgraph-workers 8
```

[`inspect`](inspect.md), which runs this stage over a whole walk as one step,
takes the same flag and the same default.

### How large one analysis may get

`--callgraph-memory-ceiling` is how much memory one analysis may hold before it
stops itself. The default, `0`, shares the host out between the subprocesses the
bound admits:

```
callgraph-memory-ceiling = max(4 GiB, (available memory - 4 GiB) / callgraph-workers)
```

One budget is held back, so every analysis sitting at its ceiling still leaves
the host able to fund the next thing that asks; and the ceiling is never below
the budget admission is priced in, or the headroom check would start analyses
the ceiling ended at once.

A child that reaches it writes one line saying what it reached and stops. That is
a different record from one the operating system chose, and the stage says which:

```
Failed stages (1):
  example.com/mod@v1.2.3  stage=callgraph  cause=environment  error=callgraph stage
    status=OutOfMemory: the analysis reached the memory ceiling this host allows
    one analysis and stopped itself; give it more with --callgraph-memory-ceiling,
    or analyse this module on its own: memory ceiling reached: 13478385144 bytes
    in use against a ceiling of 13300219904
```

The ceiling is enforced by the analysis reading its own memory ten times a
second, so it is crossed by whatever that analysis allocates between two reads:
measured overshoots on this walk were 40-180 MB against ceilings of 1 GiB and
12.4 GiB. The figure quoted is what the Go runtime has mapped and not returned,
which runs somewhat above resident memory — a 12.4 GiB ceiling held the heaviest
module in this walk to 12.1 GB resident.

**A module larger than any affordable ceiling is still not analysable**, and the
ceiling does not change that. What it changes is the cost of failing: a recorded
`OutOfMemory` naming the number it hit, instead of a host with no memory left.
Raise it for a module you want analysed on a host with the room:

```bash
kanonarion extract 01J1Z... --stages callgraph --callgraph-memory-ceiling 34359738368
```

A subprocess the operating system ends anyway is still recorded as a failed stage
with `status=OutOfMemory` and `cause=environment`, and reads differently: that
one names no number the operator chose.

### How long a subprocess may run

The child is bounded by the progress it reports, not by how long it has been
working. It writes one `callgraph progress:` line to stderr each time the
analysis enters a phase - unpacking, materialising the module cache, loading
metadata, loading syntax, building SSA, building and walking the call graph -
and the parent ends it only when **10 minutes pass with no such line**.

That is the condition a stalled subprocess actually has. A wall-clock deadline could not
tell one apart from a healthy analysis of a large module: under
`--callgraph-workers` concurrency a subprocess competes with its siblings for CPU while its own clock
keeps running, so the same module, on the same host, from the same walk, could
be analysed or dropped depending on what else the pool happened to be doing. A
child descheduled by contention still reports the next phase when it resumes; a
wedged one never does.

A wall-clock **ceiling** remains as a backstop, defaulting to 2 h and settable
with `--callgraph-timeout`:

```bash
kanonarion extract 01J1Z... --stages callgraph --callgraph-timeout 4h
```

A module lost to either deadline is a `StageFailed` naming which one, and
carries `cause=environment` - the module was not measured, this host is why, and
running again (or raising the ceiling) is what repairs it:

```
Failed stages (1):
  example.com/mod@v1.2.3  stage=callgraph  cause=environment  error=callgraph stage
    status=ExtractionFailed: the analysis reported no progress for 10m0s and was stopped
```

A module ended by the operating system rather than by either deadline, or one
that reached [the ceiling](#how-large-one-analysis-may-get), reads the same way,
naming the status the run concluded:

```
Failed stages (1):
  example.com/mod@v1.2.3  stage=callgraph  cause=environment  error=callgraph stage
    status=OutOfMemory: the analysis was ended by the operating system before it
    finished, which is usually memory: lower --callgraph-workers, or analyse this
    module on its own
```

In `--json` the same fact is the `cause` field on each stage of
`per_module_results`, and on each entry of `extract_failures` in
[`inspect --json`](inspect.md). A stage that states no cause is one whose failure
this classification does not recognise; it is never read as the module's fault. A module can be retried via
`extract <walk-id> --stages callgraph --force`.

### If a write loses the store lock

The store has a single writer, and concurrent children contend for it. A write
refused with `SQLITE_BUSY` is retried with bounded exponential backoff rather
than abandoned - the work at stake is a completed analysis, and the condition is
transient. A run that waited says so on stderr as it finishes:

```
kanonarion: store writes retried for lock contention: 48
```

An uncontended run prints nothing. A write that still cannot take the lock after
its whole budget fails with a message naming lock contention, and the stage it
belongs to is recorded `cause=environment` for the same reason a deadline is:
running again stores it.

## Progress output

A long extraction run prints a throttled **progress heartbeat** to stderr -
about one line every 20 s, e.g.
`extract progress: 89 modules processed (1m40s elapsed)` - so a large or cold
walk is visibly alive rather than silent between "Starting extraction..." and
completion. It is written to stderr only, so stdout (and `--json`) is
unaffected. Disable it with `--no-progress` or
`kanonarion config set preferences.progress false`; a warm run shorter than
the interval prints nothing. For full per-module detail pass `--log-level info`
to stream per-stage `*_extract_start`/`*_cache_hit`/`*_extract_end` lines
(which suppresses the heartbeat, since the stream already shows liveness).

## Caching

If a stage has already been successfully extracted for a module with the current
`pipeline-version`, the orchestrator will skip it unless `--force` is used.
This allows resuming interrupted extraction runs efficiently.

The database schema is versioned via the shared `schema_migrations` table
(migration version 7).

## Assurance log

Each run appends one `extraction_run_completed` event to the append-only audit
log (`{store-root}/audit.jsonl`): run id, walk id, the requested stages, the
module count, the per-stage outcome counts (`stages_succeeded`, `stages_failed`,
`stages_skipped`), the overall status and the run's content hash. The stages
themselves append their own events (`license_extracted`, `interface_extracted`,
`examples_extracted`, `callgraph_extracted`) as they persist records; this event
is what says those belong to one orchestrated run rather than to separate
single-module re-extractions.

A run record is written on every outcome, including a cancelled one, so every
invocation appends a line. A stage served from cache re-serves the stored record
without re-extracting and appends nothing of its own - so a run over a fully
warm store still appends its own event, with the stages silent beneath it.

## Fetch pipeline version dependency

Each extraction stage looks up the module's fact record (the stored zip blob
and metadata) using the fetch pipeline version constant from
`internal/fetch/application`. If `extract` is built from a different version of
kanonarion than the one that ran `fetch`, the fact records may not be found and
every stage will be silently skipped - producing `(not run)` in the context
output.

This is not a normal user-facing concern: the binary you run is always a
consistent build. It is relevant when building or testing kanonarion itself
across commits that bump the fetch pipeline version.

## See also

- `inspect` - run walk + extract + vuln-scan + context in one command
- `walk` - prerequisite: produces the walk record that extract operates on
