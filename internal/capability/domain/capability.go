package domain

import "slices"

// Capability is what a reached function can do, decided from its identity
// (package, receiver, symbol) or from a body fact recorded on it. The values
// are kanonarion's own; CapslockCategory maps each back to capslock's coarser
// vocabulary for readers who compare the two tools.
type Capability string

// Act tier: the operations a reviewer acts on.
const (
	// CapabilityExecProcess starts another program.
	CapabilityExecProcess Capability = "EXEC_PROCESS"
	// CapabilityExecDynamic loads code chosen at runtime (the plugin package).
	CapabilityExecDynamic Capability = "EXEC_DYNAMIC"
	// CapabilityNetDial opens an outbound connection or resolves a name.
	CapabilityNetDial Capability = "NET_DIAL"
	// CapabilityNetListen accepts inbound connections.
	CapabilityNetListen Capability = "NET_LISTEN"
	// CapabilityNetTransfer reads or writes an established connection or body.
	CapabilityNetTransfer Capability = "NET_TRANSFER"
	// CapabilityFSRead names a path and reads it.
	CapabilityFSRead Capability = "FS_READ"
	// CapabilityFSWrite creates, changes or removes a filesystem entry.
	CapabilityFSWrite Capability = "FS_WRITE"
	// CapabilityEnvRead reads the process environment.
	CapabilityEnvRead Capability = "ENV_READ"
	// CapabilityEnvWrite changes the process environment or working directory.
	CapabilityEnvWrite Capability = "ENV_WRITE"
	// CapabilitySyscallDirect makes a system call through syscall or x/sys.
	CapabilitySyscallDirect Capability = "SYSCALL_DIRECT"
	// CapabilityCgoCall calls into C through cgo.
	CapabilityCgoCall Capability = "CGO_CALL"
	// CapabilityUnsafePointer is the module's own unsafe.Pointer conversion.
	CapabilityUnsafePointer Capability = "UNSAFE_POINTER"
	// CapabilityReflectDynamic dispatches or mutates through reflection.
	CapabilityReflectDynamic Capability = "REFLECT_DYNAMIC"
)

// Context tier: printed, ranked below Act.
const (
	// CapabilityNetInspect parses, formats or reads metadata; no socket I/O.
	CapabilityNetInspect Capability = "NET_INSPECT"
	// CapabilityFSStream reads or writes an already-open handle.
	CapabilityFSStream Capability = "FS_STREAM"
	// CapabilityPathPure manipulates a path string without touching the disk.
	CapabilityPathPure Capability = "PATH_PURE"
	// CapabilityReflectInspect inspects types and values through reflection.
	CapabilityReflectInspect Capability = "REFLECT_INSPECT"
	// CapabilityHostIdentity reads who and where the process is.
	CapabilityHostIdentity Capability = "HOST_IDENTITY"
	// CapabilityProcControl exits, signals or inspects processes.
	CapabilityProcControl Capability = "PROC_CONTROL"
	// CapabilityLogWrite writes through the log packages.
	CapabilityLogWrite Capability = "LOG_WRITE"
)

// CapabilityRuntimeInternal is the runtime's own machinery: suppressed by
// default, still recorded and counted.
const CapabilityRuntimeInternal Capability = "RUNTIME_INTERNAL"

// Tier ranks a capability for presentation. It is a property of the value.
type Tier string

const (
	// TierAct is ranked first.
	TierAct Tier = "act"
	// TierContext is printed below Act.
	TierContext Tier = "context"
	// TierSuppressed is hidden in text unless asked for, and always counted.
	TierSuppressed Tier = "suppressed"
)

// tierRank orders tiers Act, Context, Suppressed.
func tierRank(t Tier) int {
	switch t {
	case TierAct:
		return 0
	case TierContext:
		return 1
	default:
		return 2
	}
}

// capabilityLess orders capabilities by tier, then name.
func capabilityLess(a, b Capability) bool {
	if ta, tb := tierRank(a.Tier()), tierRank(b.Tier()); ta != tb {
		return ta < tb
	}
	return a < b
}

// capabilityInfo is the per-value table: tier and capslock category together,
// so a new value cannot be added with one and not the other.
var capabilityInfo = map[Capability]struct {
	tier     Tier
	capslock string
}{
	CapabilityExecProcess:     {TierAct, "EXEC"},
	CapabilityExecDynamic:     {TierAct, "ARBITRARY_EXECUTION"},
	CapabilityNetDial:         {TierAct, "NETWORK"},
	CapabilityNetListen:       {TierAct, "NETWORK"},
	CapabilityNetTransfer:     {TierAct, "NETWORK"},
	CapabilityFSRead:          {TierAct, "FILES"},
	CapabilityFSWrite:         {TierAct, "FILES"},
	CapabilityEnvRead:         {TierAct, "READ_SYSTEM_STATE"},
	CapabilityEnvWrite:        {TierAct, "MODIFY_SYSTEM_STATE"},
	CapabilitySyscallDirect:   {TierAct, "SYSTEM_CALLS"},
	CapabilityCgoCall:         {TierAct, "CGO"},
	CapabilityUnsafePointer:   {TierAct, "UNSAFE_POINTER"},
	CapabilityReflectDynamic:  {TierAct, "REFLECT"},
	CapabilityNetInspect:      {TierContext, "NETWORK"},
	CapabilityFSStream:        {TierContext, "FILES"},
	CapabilityPathPure:        {TierContext, "FILES"},
	CapabilityReflectInspect:  {TierContext, "REFLECT"},
	CapabilityHostIdentity:    {TierContext, "READ_SYSTEM_STATE"},
	CapabilityProcControl:     {TierContext, "OPERATING_SYSTEM"},
	CapabilityLogWrite:        {TierContext, "MODIFY_SYSTEM_STATE"},
	CapabilityRuntimeInternal: {TierSuppressed, "RUNTIME"},
}

// AllCapabilities returns the taxonomy in presentation order: Act, Context,
// Suppressed, each tier in declaration order.
func AllCapabilities() []Capability {
	return []Capability{
		CapabilityExecProcess, CapabilityExecDynamic,
		CapabilityNetDial, CapabilityNetListen, CapabilityNetTransfer,
		CapabilityFSRead, CapabilityFSWrite,
		CapabilityEnvRead, CapabilityEnvWrite,
		CapabilitySyscallDirect, CapabilityCgoCall, CapabilityUnsafePointer,
		CapabilityReflectDynamic,
		CapabilityNetInspect, CapabilityFSStream, CapabilityPathPure,
		CapabilityReflectInspect, CapabilityHostIdentity, CapabilityProcControl,
		CapabilityLogWrite,
		CapabilityRuntimeInternal,
	}
}

// Valid reports whether c is a member of the taxonomy.
func (c Capability) Valid() bool {
	return slices.Contains(AllCapabilities(), c)
}

// Tier is the presentation tier of c. A value outside the taxonomy ranks with
// the suppressed tier, the side that cannot promote it above a real label.
func (c Capability) Tier() Tier {
	if info, ok := capabilityInfo[c]; ok {
		return info.tier
	}
	return TierSuppressed
}

// CapslockCategory is the capslock CAPABILITY_* name c maps onto, without the
// prefix. The map is many-to-one and lossy; empty for a value outside the
// taxonomy.
func (c Capability) CapslockCategory() string {
	return capabilityInfo[c].capslock
}

// Reach says how deliberately a capability is reached, decided from the callee
// alone. Evaluated in declaration order; the first match wins.
type Reach string

const (
	// ReachUnanalyzed is a callee with an assembly or //go:linkname body: the
	// graph cannot see what it does.
	ReachUnanalyzed Reach = "UNANALYZED"
	// ReachPkgLinkage is a package initialiser: the package is linked, nothing
	// in it was called.
	ReachPkgLinkage Reach = "PKG_LINKAGE"
	// ReachRuntimePlumbing is an unexported callee: machinery behind an API
	// rather than the API.
	ReachRuntimePlumbing Reach = "RUNTIME_PLUMBING"
	// ReachDirectCall is an exported function called by name.
	ReachDirectCall Reach = "DIRECT_CALL"
)

// IsPlumbing is the one plumbing predicate findings and rows share: reach
// RUNTIME_PLUMBING, or an unexported callee whose body the graph cannot see
// (reach UNANALYZED, such as a runtime_* linkname).
func IsPlumbing(reach Reach, symbol string) bool {
	return reach == ReachRuntimePlumbing || (reach == ReachUnanalyzed && !exportedSymbol(symbol))
}

// witnessRank orders witnesses for the single-version report: a direct call,
// then an exported unanalysed body, then plumbing, then an unexported
// unanalysed body. Every non-plumbing witness outranks every plumbing one, so
// the chosen witness is plumbing only when no other exists.
func witnessRank(reach Reach, symbol string) int {
	switch {
	case reach == ReachDirectCall:
		return 4
	case reach == ReachUnanalyzed && exportedSymbol(symbol):
		return 3
	case reach == ReachRuntimePlumbing:
		return 2
	case reach == ReachUnanalyzed:
		return 1
	default:
		return 0
	}
}

// CallerKind is the kind of the function whose own code makes the call or
// carries the body fact. It says what the caller is, not what reaches it.
type CallerKind string

const (
	// CallerTestInit is the initialiser of a test package.
	CallerTestInit CallerKind = "TEST_INIT"
	// CallerInit is a package initialiser.
	CallerInit CallerKind = "INIT"
	// CallerTest is declared in a _test.go file or an external test package.
	CallerTest CallerKind = "TEST"
	// CallerMain is a program's main function.
	CallerMain CallerKind = "MAIN"
	// CallerExportedAPI is part of the module's public API, or handed to a
	// caller outside Go by an export directive.
	CallerExportedAPI CallerKind = "EXPORTED_API"
	// CallerInternal is everything else the module owns.
	CallerInternal CallerKind = "INTERNAL"
)

// callerKindRank is the diff's ranking: what runs with nobody choosing to call
// it first, then the public surface, then the rest.
func callerKindRank(k CallerKind) int {
	switch k {
	case CallerInit:
		return 0
	case CallerTestInit:
		return 1
	case CallerExportedAPI:
		return 2
	case CallerTest:
		return 3
	case CallerInternal:
		return 4
	default: // CallerMain
		return 5
	}
}

// Collapsed reports whether a diff collapses rows of this kind to one line per
// callee with a caller count, rather than enumerating each caller.
func (k CallerKind) Collapsed() bool {
	return k == CallerTest || k == CallerInternal
}

// ClassifiedBy says whether a label came from a rule that names the callee or
// from its package's default, so an approximation is visible.
type ClassifiedBy string

const (
	// ClassifiedByRule is a rule naming the symbol, the receiver, or the whole
	// package as one capability.
	ClassifiedByRule ClassifiedBy = "rule"
	// ClassifiedByPackageDefault is the fallback for a callee in a sink package
	// that no rule names.
	ClassifiedByPackageDefault ClassifiedBy = "package_default"
)

// CapabilityBasis says what a witnessing path actually established. It is
// emitted on every finding: only BasisUse is a capability of the analysed
// module, and the other two name the weaker thing the path proved instead of
// leaving the reader to infer it from the sink.
type CapabilityBasis string

const (
	// BasisUse is a capability of the analysed module: its code calls into a
	// sink, or the body fact is recorded on a node the module owns.
	BasisUse CapabilityBasis = "use"
	// BasisLinkageOnly is a path whose sink is another package's init. The
	// package is linked and its initialiser ran; nothing in it was called, so
	// the package's capability is not the analysed module's.
	BasisLinkageOnly CapabilityBasis = "linkage_only"
	// BasisCalleeBodyFact is a body fact (unsafe.Pointer use) recorded on an
	// external callee. The fact is true of that function, not of the code that
	// calls it.
	BasisCalleeBodyFact CapabilityBasis = "callee_body_fact"
)

// AllCapabilityBases returns the basis vocabulary in a stable order.
func AllCapabilityBases() []CapabilityBasis {
	return []CapabilityBasis{BasisUse, BasisLinkageOnly, BasisCalleeBodyFact}
}

// Explanation is the one-line reason a reader is shown beside a finding that is
// not a capability of the analysed module. BasisUse has none: it needs no
// qualification.
func (b CapabilityBasis) Explanation() string {
	switch b {
	case BasisLinkageOnly:
		return "linkage only: the package is linked and its initialiser ran; nothing in it was called"
	case BasisCalleeBodyFact:
		return "callee body fact: the fact is recorded on that external function, not on this module's code"
	default:
		return ""
	}
}
