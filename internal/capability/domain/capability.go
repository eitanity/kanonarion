package domain

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
	for _, known := range AllCapabilities() {
		if c == known {
			return true
		}
	}
	return false
}
