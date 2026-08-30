package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

// The envelope the per-module answers are framed in.
//
// `audit`, `context` and `latest` each answer with one row per module, and each
// used to write those rows as a bare JSON array. An array has nowhere to put a
// fact about the RUN — which scope resolved the rows, how many modules that was,
// which build the verdicts were read in — so those facts were stated to a person
// on stderr and to a machine nowhere. The envelope is the place they live.
//
// Two rules hold it together:
//
//	the rows do not change. `modules` holds exactly the documents the array
//	held, field for field, so a consumer that has one row in hand reads it the
//	same way it always did.
//
//	the shape does not follow the form or the count. One module named on the
//	command line, a scope that resolved twenty, a scope that resolved none —
//	all of them are one object with a `modules` array. A caller holding the
//	argument in a variable does not know which form it invoked, and a document
//	whose type depends on that is one the caller cannot parse without asking.

// envelopeScope is the run-level dependency-scope disclosure every enveloped
// answer carries: which scope resolved the answer, the test axis that scope
// applied, how many modules it resolved, and the flag that narrows it.
//
// It is the machine-readable half of the line writeDepScopeNotice puts on
// stderr, and it is built from the same scopeResolution and the same count, so
// the two cannot state different things.
//
// DependencyScope repeats the object the rows already carry, under the same key
// and with the same members: the row states the criterion by which THAT row
// exists, and the envelope states it once for the answer. A form that projects
// no go.mod scope — a coordinate named on the command line, a walk named with
// --walk-id — emits null rather than omitting the key, because a reader cannot
// tell an unstated scope from a missing one.
type envelopeScope struct {
	DependencyScope *scopeJSON `json:"dependency_scope"`
	// ModuleCount is how many modules the answer is over. On a go.mod form it is
	// the count the scope resolved — the number the scope notice states — so a
	// module that failed to render leaves `modules` shorter than this, with the
	// failure named on stderr and a non-zero exit.
	ModuleCount int `json:"module_count"`
	// NarrowWith is the flag that would narrow this scope, carried as data
	// because a remedy a consumer has to parse out of a sentence is not one it
	// can act on. Absent where nothing narrows the answer: a scope with no test
	// axis to remove, and a command that refuses the flag rather than honouring
	// it.
	NarrowWith string `json:"narrow_with,omitempty"`
}

// newEnvelopeScope builds the disclosure from the resolution that produced the
// module set, the count it resolved, and whether this command honours the
// narrowing flag.
//
// It takes the same three arguments writeDepScopeNotice takes, and is called
// beside it, so the sentence and the fields are built from one measurement.
func newEnvelopeScope(r scopeResolution, modules int, offerFlag bool) envelopeScope {
	out := envelopeScope{DependencyScope: newScopeJSON(r), ModuleCount: modules}
	if offerFlag && r.narrowable() {
		out.NarrowWith = "--" + testScopeFlagName
	}
	return out
}

// unscopedEnvelope is the disclosure for a form that projected no go.mod scope:
// a coordinate, a pinned walk, a list of module paths. The scope is null because
// none was resolved; the count still answers how many modules came back.
func unscopedEnvelope(modules int) envelopeScope {
	return envelopeScope{ModuleCount: modules}
}

// jsonEnvelopeWriter frames a sequence of per-module documents as the `modules`
// array of one envelope object, without holding the documents in memory.
//
// Nothing is buffered because the answer it frames can be large — one project's
// context is megabytes, which is why --size-only exists — and an envelope that
// had to marshal the whole document at once would take that cost back.
//
// Each element is written with the same json.Marshal call the bare array used,
// so an element inside the envelope is byte-identical to the element the array
// held. Only the framing around it differs.
type jsonEnvelopeWriter struct {
	out io.Writer
	// head carries the envelope's own fields and must marshal to a JSON object.
	// It is marshalled once, when the first element is written or the envelope is
	// closed, so a caller can finish assembling it while the rows are being
	// resolved.
	head   any
	opened bool
	begun  bool
}

// open writes the envelope's fields and opens the modules array.
func (e *jsonEnvelopeWriter) open() error {
	if e.opened {
		return nil
	}
	raw, err := json.Marshal(e.head)
	if err != nil {
		return fmt.Errorf("encoding envelope: %w", err)
	}
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		return fmt.Errorf("envelope is not a JSON object: %s", raw)
	}
	// The head's closing brace is dropped and the modules array opened in its
	// place, so the elements can be streamed into it one at a time.
	prefix := string(raw[:len(raw)-1])
	if len(raw) > 2 {
		prefix += ","
	}
	if _, err := fmt.Fprintf(e.out, `%s"modules":[`, prefix); err != nil {
		return fmt.Errorf("%w: %w", errContextOutputWrite, err)
	}
	e.opened = true
	return nil
}

// write appends one per-module document to the modules array.
func (e *jsonEnvelopeWriter) write(v any) error {
	if err := e.open(); err != nil {
		return err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encoding: %w", err)
	}
	sep := ""
	if e.begun {
		sep = ","
	}
	if _, err := fmt.Fprintf(e.out, "%s%s", sep, raw); err != nil {
		return fmt.Errorf("%w: %w", errContextOutputWrite, err)
	}
	e.begun = true
	return nil
}

// close ends the modules array and the envelope. An envelope that took no
// element is still written whole: the empty answer is one object with an empty
// modules array, which decodes as the same type as a populated one.
func (e *jsonEnvelopeWriter) close() error {
	if err := e.open(); err != nil {
		return err
	}
	if _, err := fmt.Fprint(e.out, "]}\n"); err != nil {
		return fmt.Errorf("%w: %w", errContextOutputWrite, err)
	}
	return nil
}
