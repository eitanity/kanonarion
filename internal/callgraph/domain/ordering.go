package domain

// This file holds the one canonical ordering per collection in a
// CallGraphRecord. There was previously one comparator inside the hasher and a
// second on the record, and they had drifted: the record's edge comparator
// tiebroke on Kind and the hasher's did not. Neither covered every field the
// canonical wire shape carries, so neither was a total order and the relative
// order of two edges that tied on the shared prefix was whatever the sort
// happened to produce.
//
// Each comparator below is keyed on every field its collection puts on the
// wire, so no two distinct elements compare equal and the sorted order is a
// function of the set alone. That makes sort.Slice correct here.
// sort.SliceStable would not be an alternative: stability decides ties by input
// order, which would make the sealed bytes depend on the order the analyser
// emitted its elements.

// CallNodeLess is the canonical ordering for CallNode slices. ID identifies a
// node, so the remaining keys only ever decide a pair the analyser emitted
// twice under one ID with different facts — a state no stored record is in,
// and one this ordering resolves rather than leaves to the sort.
func CallNodeLess(a, b CallNode) bool {
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	if a.Module != b.Module {
		return a.Module < b.Module
	}
	if a.Package != b.Package {
		return a.Package < b.Package
	}
	if a.Symbol != b.Symbol {
		return a.Symbol < b.Symbol
	}
	if a.Receiver != b.Receiver {
		return a.Receiver < b.Receiver
	}
	if a.Position.File != b.Position.File {
		return a.Position.File < b.Position.File
	}
	if a.Position.Line != b.Position.Line {
		return a.Position.Line < b.Position.Line
	}
	if a.IsExternal != b.IsExternal {
		return !a.IsExternal
	}
	if a.IsExportedAPI != b.IsExportedAPI {
		return !a.IsExportedAPI
	}
	if a.UsesUnsafePointer != b.UsesUnsafePointer {
		return !a.UsesUnsafePointer
	}
	if a.IsAssemblyOrLinkname != b.IsAssemblyOrLinkname {
		return !a.IsAssemblyOrLinkname
	}
	if a.UsesPlugin != b.UsesPlugin {
		return !a.UsesPlugin
	}
	if a.IsTest != b.IsTest {
		return !a.IsTest
	}
	return false
}

// CallEdgeLess is the canonical ordering for CallEdge slices. The endpoints and
// the call site come first because that is the order a reader scans an edge
// list in; Kind, Confidence, ReflectDispatch and IsTest follow so that two
// edges between one pair of nodes at one call site still have a defined order.
func CallEdgeLess(a, b CallEdge) bool {
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
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Confidence != b.Confidence {
		return a.Confidence < b.Confidence
	}
	if a.ReflectDispatch != b.ReflectDispatch {
		return !a.ReflectDispatch
	}
	return false
}

// InterfaceTypeLess is the canonical ordering for InterfaceType slices. Methods
// are compared last and element by element, so two declarations sharing an ID
// still order by their method sets rather than by emission order. Sort the
// method lists themselves before comparing.
func InterfaceTypeLess(a, b InterfaceType) bool {
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	if a.Package != b.Package {
		return a.Package < b.Package
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Position.File != b.Position.File {
		return a.Position.File < b.Position.File
	}
	if a.Position.Line != b.Position.Line {
		return a.Position.Line < b.Position.Line
	}
	if a.IsTest != b.IsTest {
		return !a.IsTest
	}
	return stringsLess(a.Methods, b.Methods)
}

// ImplementedMethodLess is the canonical ordering for the method list of one
// implementation.
func ImplementedMethodLess(a, b ImplementedMethod) bool {
	if a.Method != b.Method {
		return a.Method < b.Method
	}
	return a.NodeID < b.NodeID
}

// InterfaceImplementationLess is the canonical ordering for
// InterfaceImplementation slices. Sort each implementation's method list with
// ImplementedMethodLess before comparing, so the final key compares like with
// like.
func InterfaceImplementationLess(a, b InterfaceImplementation) bool {
	if a.InterfaceID != b.InterfaceID {
		return a.InterfaceID < b.InterfaceID
	}
	if a.TypeID != b.TypeID {
		return a.TypeID < b.TypeID
	}
	if a.Package != b.Package {
		return a.Package < b.Package
	}
	if a.Position.File != b.Position.File {
		return a.Position.File < b.Position.File
	}
	if a.Position.Line != b.Position.Line {
		return a.Position.Line < b.Position.Line
	}
	if a.IsTest != b.IsTest {
		return !a.IsTest
	}
	if len(a.Methods) != len(b.Methods) {
		return len(a.Methods) < len(b.Methods)
	}
	for i := range a.Methods {
		if a.Methods[i] != b.Methods[i] {
			return ImplementedMethodLess(a.Methods[i], b.Methods[i])
		}
	}
	return false
}

// stringsLess orders two string slices lexicographically, shorter-first on a
// shared prefix.
func stringsLess(a, b []string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
