package domain

import "slices"

// Capability is a sensitive capability category a reachable code path can
// exercise. The taxonomy mirrors capslock's CAPABILITY_* categories so
// kanonarion reports are directly comparable.
type Capability string

const (
	// CapabilityNetwork is opening sockets or making network connections.
	CapabilityNetwork Capability = "NETWORK"
	// CapabilityFiles is reading or writing the filesystem.
	CapabilityFiles Capability = "FILES"
	// CapabilityExec is starting other programs (os/exec).
	CapabilityExec Capability = "EXEC"
	// CapabilityArbitraryExecution is running code chosen at runtime (plugins,
	// generated code) beyond a fixed os/exec call.
	CapabilityArbitraryExecution Capability = "ARBITRARY_EXECUTION"
	// CapabilityReflect is use of the reflect package.
	CapabilityReflect Capability = "REFLECT"
	// CapabilityUnsafePointer is use of unsafe.Pointer.
	CapabilityUnsafePointer Capability = "UNSAFE_POINTER"
	// CapabilityCGo is calling into C via cgo.
	CapabilityCGo Capability = "CGO"
	// CapabilitySystemCalls is direct system calls (syscall / x/sys).
	CapabilitySystemCalls Capability = "SYSTEM_CALLS"
	// CapabilityRuntime is use of low-level runtime facilities.
	CapabilityRuntime Capability = "RUNTIME"
	// CapabilityReadSystemState is reading process/host state (env, user).
	CapabilityReadSystemState Capability = "READ_SYSTEM_STATE"
	// CapabilityModifySystemState is changing process/host state (env,
	// signals, logging).
	CapabilityModifySystemState Capability = "MODIFY_SYSTEM_STATE"
	// CapabilityOperatingSystem is other OS-level interaction (pid, hostname).
	CapabilityOperatingSystem Capability = "OPERATING_SYSTEM"
)

// AllCapabilities returns the full taxonomy in a stable, documented order.
func AllCapabilities() []Capability {
	return []Capability{
		CapabilityNetwork,
		CapabilityFiles,
		CapabilityExec,
		CapabilityArbitraryExecution,
		CapabilityReflect,
		CapabilityUnsafePointer,
		CapabilityCGo,
		CapabilitySystemCalls,
		CapabilityRuntime,
		CapabilityReadSystemState,
		CapabilityModifySystemState,
		CapabilityOperatingSystem,
	}
}

// Valid reports whether c is a member of the taxonomy.
func (c Capability) Valid() bool {
	return slices.Contains(AllCapabilities(), c)
}

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
	// BasisCalleeBodyFact is a body fact (unsafe.Pointer use, an
	// assembly/linkname body) recorded on an external callee. The fact is true
	// of that function, not of the code that calls it.
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
