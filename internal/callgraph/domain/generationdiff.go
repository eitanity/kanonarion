package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrUnverifiableGeneration is returned by DiffGenerations when a record does
// not match its own content hash.
//
// Diffing is refused rather than attempted, because a record that failed its
// seal is not evidence of anything and a diff of it would read as one.
var ErrUnverifiableGeneration = errors.New("generation does not match its own content hash")

// GenerationDiff is what a comparison of two generations of one coordinate
// found.
//
// It is the instrument a refusal sends the reader to. A refusal that names two
// digests asks an operator to adjudicate a graph by eye; this names the fields.
type GenerationDiff struct {
	// Left and Right are the content hashes of the two generations compared, in
	// the order they were given.
	Left, Right string
	// Fields are the record-level values that differ, sorted by field name. The
	// collections that carry the graph itself are reported below instead.
	Fields []FieldDiff
	// The graph's collections, each compared by the identity of its members.
	Nodes           CollectionDiff
	Edges           CollectionDiff
	Interfaces      CollectionDiff
	Implementations CollectionDiff
}

// FieldDiff is one record-level field two generations state differently. An
// empty side means that generation states nothing for the field.
type FieldDiff struct {
	Field string
	Left  string
	Right string
}

// CollectionDiff is how two generations' members of one collection differ.
type CollectionDiff struct {
	// Kind names what the members are, singular: "node", "edge".
	Kind string
	// OnlyLeft and OnlyRight are the member identities one generation holds and
	// the other does not, sorted.
	OnlyLeft  []string
	OnlyRight []string
	// Changed are the members both generations hold and describe differently,
	// sorted by identity.
	Changed []MemberChange
}

// MemberChange is one member two generations describe differently. Field names
// the first difference by canonical field name; a member may differ in more.
type MemberChange struct {
	ID    string
	Field string
	Left  string
	Right string
}

// Empty reports whether the two generations hold the identical collection.
func (d CollectionDiff) Empty() bool {
	return len(d.OnlyLeft) == 0 && len(d.OnlyRight) == 0 && len(d.Changed) == 0
}

// Empty reports whether the two generations state the identical record.
func (d GenerationDiff) Empty() bool {
	return len(d.Fields) == 0 && d.Nodes.Empty() && d.Edges.Empty() &&
		d.Interfaces.Empty() && d.Implementations.Empty()
}

// Collections returns the four graph collections in report order.
func (d GenerationDiff) Collections() []CollectionDiff {
	return []CollectionDiff{d.Nodes, d.Edges, d.Interfaces, d.Implementations}
}

// Summary is a one-line account of what differs, for a refusal to carry.
func (d GenerationDiff) Summary() string {
	parts := make([]string, 0, 5)
	if len(d.Fields) > 0 {
		names := make([]string, 0, len(d.Fields))
		for _, f := range d.Fields {
			names = append(names, f.Field)
		}
		parts = append(parts, strings.Join(names, ", ")+" differ")
	}
	for _, c := range d.Collections() {
		if c.Empty() {
			continue
		}
		var counts []string
		if n := len(c.OnlyLeft); n > 0 {
			counts = append(counts, plural(n, c.Kind)+" only in "+d.Left)
		}
		if n := len(c.OnlyRight); n > 0 {
			counts = append(counts, plural(n, c.Kind)+" only in "+d.Right)
		}
		if n := len(c.Changed); n > 0 {
			counts = append(counts, plural(n, c.Kind)+" described differently")
		}
		parts = append(parts, strings.Join(counts, ", "))
	}
	if len(parts) == 0 {
		return "the two generations state the same record"
	}
	return strings.Join(parts, "; ")
}

func plural(n int, kind string) string {
	if n == 1 {
		return "1 " + kind
	}
	return strconv.Itoa(n) + " " + kind + "s"
}

// DiffGenerations validates two generations of one coordinate and reports what
// they differ about.
//
// Validation comes first and is not optional. The content hash is sealed over
// the time of measurement, so it can only ever answer "is this record intact"
// and never "do these two agree"; using it as an equality test is how an
// earlier investigation concluded the analyser was non-deterministic. Here it
// does the one job it can do, and the semantic fields answer the other.
//
// The comparison is over the canonical shape rather than a hand-listed set of
// fields, so a field added tomorrow is diffed without being remembered here.
// The time of measurement and the seal computed over it are the only fields set
// aside — they differ on every write by construction.
func DiffGenerations(left, right CallGraphRecord) (GenerationDiff, error) {
	var h CallGraphRecordHasher
	for _, r := range []CallGraphRecord{left, right} {
		if err := h.VerifyContentHash(r); err != nil {
			return GenerationDiff{}, fmt.Errorf("%w: %s: %w", ErrUnverifiableGeneration, r.ContentHash, err)
		}
	}

	lf, err := recordFields(left)
	if err != nil {
		return GenerationDiff{}, err
	}
	rf, err := recordFields(right)
	if err != nil {
		return GenerationDiff{}, err
	}

	d := GenerationDiff{Left: left.ContentHash, Right: right.ContentHash}
	for _, name := range sortedKeys(lf, rf) {
		if _, isCollection := collectionIdentity[name]; isCollection {
			continue
		}
		l, r := renderJSON(lf[name]), renderJSON(rf[name])
		if l != r {
			d.Fields = append(d.Fields, FieldDiff{Field: name, Left: l, Right: r})
		}
	}

	if d.Nodes, err = diffMembers("nodes", "node",
		orderedBy(left.Nodes, CallNodeLess), orderedBy(right.Nodes, CallNodeLess),
		nodeIdentityLess, CallNodeLess, describeNode); err != nil {
		return GenerationDiff{}, err
	}
	if d.Edges, err = diffMembers("edges", "edge",
		orderedBy(left.Edges, CallEdgeLess), orderedBy(right.Edges, CallEdgeLess),
		edgeIdentityLess, CallEdgeLess, describeEdge); err != nil {
		return GenerationDiff{}, err
	}
	if d.Interfaces, err = diffMembers("interfaces", "interface",
		orderedInterfaces(left.Interfaces), orderedInterfaces(right.Interfaces),
		interfaceIdentityLess, InterfaceTypeLess, describeInterface); err != nil {
		return GenerationDiff{}, err
	}
	if d.Implementations, err = diffMembers("implementations", "implementation",
		orderedImplementations(left.Implementations), orderedImplementations(right.Implementations),
		implementationIdentityLess, InterfaceImplementationLess, describeImplementation); err != nil {
		return GenerationDiff{}, err
	}
	return d, nil
}

// diffMembers compares one collection of two generations by walking both in
// canonical order, and reports what differs.
//
// It works on the records rather than on their JSON, and that is the whole of
// why it is affordable. Rendering a collection to compare it means holding the
// canonical bytes of both generations, a decoded element per member and a keying
// map over them; on a module with four million edges that came to twenty-odd
// gigabytes, almost all of it spent establishing that every edge was identical.
// Here a member is rendered only when it is going to be REPORTED, so the cost
// tracks what differs rather than how big the graph is.
//
// lessIdentity must be the leading keys of less. Every canonical order in
// ordering.go is keyed on identity first and then on every remaining wire field,
// which is what lets one comparator answer both questions: lessIdentity decides
// which members are the same thing described twice, and less decides whether
// those two descriptions agree — a total order, so incomparable IS equal, and no
// second hand-listed set of fields can drift from the wire shape.
func diffMembers[T any](field, kind string, left, right []T,
	lessIdentity, less func(a, b T) bool,
	describe func(T) (map[string]json.RawMessage, error),
) (CollectionDiff, error) {
	d := CollectionDiff{Kind: kind}
	name := func(v T) (string, error) {
		fields, err := describe(v)
		if err != nil {
			return "", err
		}
		return identityOf(field, fields), nil
	}

	i, j := 0, 0
	for i < len(left) && j < len(right) {
		li, rj := runEnd(left, i, lessIdentity), runEnd(right, j, lessIdentity)
		switch {
		case lessIdentity(left[i], right[j]):
			id, err := name(left[li-1])
			if err != nil {
				return CollectionDiff{}, err
			}
			d.OnlyLeft = append(d.OnlyLeft, id)
			i = li
		case lessIdentity(right[j], left[i]):
			id, err := name(right[rj-1])
			if err != nil {
				return CollectionDiff{}, err
			}
			d.OnlyRight = append(d.OnlyRight, id)
			j = rj
		default:
			// The last of a run wins, which is what keying members by identity into a
			// map did when two members shared one identity.
			l, r := left[li-1], right[rj-1]
			if less(l, r) || less(r, l) {
				change, err := memberDifference(field, l, r, describe)
				if err != nil {
					return CollectionDiff{}, err
				}
				d.Changed = append(d.Changed, change)
			}
			i, j = li, rj
		}
	}
	for i < len(left) {
		li := runEnd(left, i, lessIdentity)
		id, err := name(left[li-1])
		if err != nil {
			return CollectionDiff{}, err
		}
		d.OnlyLeft = append(d.OnlyLeft, id)
		i = li
	}
	for j < len(right) {
		rj := runEnd(right, j, lessIdentity)
		id, err := name(right[rj-1])
		if err != nil {
			return CollectionDiff{}, err
		}
		d.OnlyRight = append(d.OnlyRight, id)
		j = rj
	}

	sort.Strings(d.OnlyLeft)
	sort.Strings(d.OnlyRight)
	sort.Slice(d.Changed, func(i, j int) bool { return MemberChangeLess(d.Changed[i], d.Changed[j]) })
	return d, nil
}

// MemberChangeLess is the canonical ordering for MemberChange slices. One
// member can change in more than one field between two generations, so the id
// alone does not identify a change, and the two values are what a reader
// distinguishes two changes on the same field by.
func MemberChangeLess(a, b MemberChange) bool {
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	if a.Field != b.Field {
		return a.Field < b.Field
	}
	if a.Left != b.Left {
		return a.Left < b.Left
	}
	return a.Right < b.Right
}

// runEnd returns the index one past the members sharing s[i]'s identity.
func runEnd[T any](s []T, i int, lessIdentity func(a, b T) bool) int {
	k := i + 1
	for k < len(s) && !lessIdentity(s[i], s[k]) {
		k++
	}
	return k
}

// memberDifference names what two members of one identity differ about.
func memberDifference[T any](field string, left, right T,
	describe func(T) (map[string]json.RawMessage, error),
) (MemberChange, error) {
	lf, err := describe(left)
	if err != nil {
		return MemberChange{}, err
	}
	rf, err := describe(right)
	if err != nil {
		return MemberChange{}, err
	}
	id := identityOf(field, lf)
	if change, differs := firstDifference(id, lf, rf); differs {
		return change, nil
	}
	// The canonical order is total over every wire field, so two members it cannot
	// separate are equal and this is unreachable. Naming the member rather than
	// dropping it keeps an order that stopped being total from reading as agreement.
	return MemberChange{ID: id, Field: "canonical form"}, nil
}

// The identity comparators. Each is the leading keys of its collection's
// canonical order in ordering.go, so a collection sorted for the wire is sorted
// by identity too and diffMembers can walk it without building an index.
func nodeIdentityLess(a, b CallNode) bool { return a.ID < b.ID }

func edgeIdentityLess(a, b CallEdge) bool {
	if a.FromID != b.FromID {
		return a.FromID < b.FromID
	}
	if a.ToID != b.ToID {
		return a.ToID < b.ToID
	}
	if a.CallSite.File != b.CallSite.File {
		return a.CallSite.File < b.CallSite.File
	}
	if a.CallSite.Line != b.CallSite.Line {
		return a.CallSite.Line < b.CallSite.Line
	}
	return a.Kind < b.Kind
}

func interfaceIdentityLess(a, b InterfaceType) bool { return a.ID < b.ID }

func implementationIdentityLess(a, b InterfaceImplementation) bool {
	if a.InterfaceID != b.InterfaceID {
		return a.InterfaceID < b.InterfaceID
	}
	return a.TypeID < b.TypeID
}

// orderedBy returns s in canonical order, sorting a copy only when it is not
// already in it. A record read from the store was sealed in canonical order, so
// the usual answer is the caller's own slice and no copy of four million edges.
func orderedBy[T any](s []T, less func(a, b T) bool) []T {
	if sort.SliceIsSorted(s, func(i, j int) bool { return less(s[i], s[j]) }) {
		return s
	}
	out := append([]T(nil), s...)
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

// orderedInterfaces and orderedImplementations also put each member's method
// list in order, which the canonical comparators compare element by element and
// therefore require. They copy unconditionally: these collections are declarations
// of the analysed module, in the tens, not the millions.
func orderedInterfaces(in []InterfaceType) []InterfaceType {
	out := append([]InterfaceType(nil), in...)
	for i := range out {
		methods := append([]string(nil), out[i].Methods...)
		sort.Strings(methods)
		out[i].Methods = methods
	}
	return orderedBy(out, InterfaceTypeLess)
}

func orderedImplementations(in []InterfaceImplementation) []InterfaceImplementation {
	out := append([]InterfaceImplementation(nil), in...)
	for i := range out {
		methods := append([]ImplementedMethod(nil), out[i].Methods...)
		sort.Slice(methods, func(a, b int) bool { return ImplementedMethodLess(methods[a], methods[b]) })
		out[i].Methods = methods
	}
	return orderedBy(out, InterfaceImplementationLess)
}

// The describers. Each renders ONE member through the canonical marshaller, so
// what a difference is reported over is the same shape the record is sealed in,
// and a field added to that shape is described without being named here.
func describeNode(n CallNode) (map[string]json.RawMessage, error) {
	return canonicalMember("nodes", CallGraphRecord{Nodes: []CallNode{n}})
}

func describeEdge(e CallEdge) (map[string]json.RawMessage, error) {
	return canonicalMember("edges", CallGraphRecord{Edges: []CallEdge{e}})
}

func describeInterface(i InterfaceType) (map[string]json.RawMessage, error) {
	return canonicalMember("interfaces", CallGraphRecord{Interfaces: []InterfaceType{i}})
}

func describeImplementation(im InterfaceImplementation) (map[string]json.RawMessage, error) {
	return canonicalMember("implementations", CallGraphRecord{Implementations: []InterfaceImplementation{im}})
}

// canonicalMember marshals a record holding one member and reads that member
// back as its canonical fields.
func canonicalMember(field string, one CallGraphRecord) (map[string]json.RawMessage, error) {
	data, err := marshalCanonical(one)
	if err != nil {
		return nil, fmt.Errorf("marshal %s member for generation diff: %w", field, err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("read canonical %s member as fields: %w", field, err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(top[field], &items); err != nil {
		return nil, fmt.Errorf("read canonical %s member as fields: %w", field, err)
	}
	if len(items) != 1 {
		return nil, fmt.Errorf("canonical %s rendered %d members for one: %w", field, len(items), errors.ErrUnsupported)
	}
	return memberFields(items[0])
}

// identityOf renders a member's identity from its canonical fields.
//
// A field the member does not STATE is left out rather than joined as a blank.
// An omitempty identity field — an edge's kind is the one in tree — is absent
// from every edge sealed without it, and joining a blank for it gave every such
// identity a trailing separator and made "states no kind" render identically to
// "states the empty kind". A stated empty value is quoted for the same reason:
// the two are different facts and an identity may not collapse them.
func identityOf(field string, fields map[string]json.RawMessage) string {
	keys := collectionIdentity[field]
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		raw, stated := fields[key]
		if !stated {
			continue
		}
		if v := renderJSON(raw); v != "" {
			parts = append(parts, v)
		} else {
			parts = append(parts, `""`)
		}
	}
	return strings.Join(parts, " ")
}

// collectionIdentity names, per canonical collection, the fields that identify
// one member. Two members sharing an identity are the same thing described
// twice; two identities are two different things.
var collectionIdentity = map[string][]string{
	"nodes":           {"id"},
	"edges":           {"from_id", "to_id", "call_site", "kind"},
	"interfaces":      {"id"},
	"implementations": {"interface_id", "type_id"},
}

// recordFields is the canonical shape of a record as a field map, with the
// circumstances of the run — its time, its seal, its derivation — set aside.
func recordFields(r CallGraphRecord) (map[string]json.RawMessage, error) {
	r = withoutRunCircumstance(r)
	// The collections are compared from the records themselves, so rendering them
	// here only to skip them is the whole of what made this unaffordable. The
	// counts stated alongside them are not collections and are still compared.
	r.Nodes, r.Edges, r.Interfaces, r.Implementations = nil, nil, nil, nil
	data, err := marshalCanonical(r)
	if err != nil {
		return nil, fmt.Errorf("marshal record for generation diff: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("read canonical record as fields: %w", err)
	}
	return fields, nil
}

// memberFields decomposes one canonical member into its fields.
func memberFields(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("read canonical collection member for generation diff: %w", err)
	}
	return fields, nil
}

// firstDifference names the first canonical field two members of one collection
// state differently.
func firstDifference(id string, left, right map[string]json.RawMessage) (MemberChange, bool) {
	for _, name := range sortedKeys(left, right) {
		l, r := renderJSON(left[name]), renderJSON(right[name])
		if l != r {
			return MemberChange{ID: id, Field: name, Left: l, Right: r}, true
		}
	}
	return MemberChange{}, false
}

// sortedKeys is the union of two field maps' keys, sorted.
func sortedKeys(a, b map[string]json.RawMessage) []string {
	seen := make(map[string]bool, len(a)+len(b))
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// renderJSON renders a canonical value for a reader: a JSON string unquoted, so
// a walk identifier reads as itself, anything else compacted. An absent value
// renders empty, which is what a record that states nothing for a field says.
func renderJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}
