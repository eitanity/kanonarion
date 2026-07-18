package domain

import (
	"strings"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Copyright 2023 Google LLC
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-SnippetName: Capslock stdlib capability classification data
// SPDX-SnippetComment: Transcribed from github.com/google/capslock@v0.3.2, interesting/interesting.cm
//
// The two maps below are the third-party-derived data. Capslock's per-function
// taxonomy carries historical precedence only: kanonarion owns its own
// capability labels (see capability.go), so an entry adopts Capslock's
// which-function-carries-which-capability judgement expressed in kanonarion's
// vocabulary, not Capslock's exact label names. The SPDX tags above are the
// machine-readable attribution record consumed by `kanonarion notice`; keep
// them and the closing SPDX-SnippetEnd intact when editing the maps.

// funcSinks classifies individual stdlib functions and methods that are more
// precise than their package's default. It takes precedence over pkgSinks so a
// multi-capability package (e.g. "os" spans files, environment, process state,
// and exec) is not collapsed to a single capability. Keys are built by funcKey:
// "importPath.Symbol" for free functions and "importPath.RecvType.Symbol" for
// methods, with the receiver reduced to its bare type name (no pointer star, no
// package qualifier) so pointer and value receivers share one key.
var funcSinks = map[string]Capability{
	// os: environment reads/writes and process identity are distinct from the
	// package's dominant file capability.
	"os.Getenv":    CapabilityReadSystemState,
	"os.LookupEnv": CapabilityReadSystemState,
	"os.Environ":   CapabilityReadSystemState,
	"os.Setenv":    CapabilityModifySystemState,
	"os.Unsetenv":  CapabilityModifySystemState,
	"os.Clearenv":  CapabilityModifySystemState,
	"os.Getpid":    CapabilityOperatingSystem,
	"os.Getppid":   CapabilityOperatingSystem,
	"os.Hostname":  CapabilityOperatingSystem,
	"os.Exit":      CapabilityOperatingSystem,

	// os: reads of process/host state that the FILES default would mislabel.
	"os.Executable":    CapabilityReadSystemState,
	"os.Getwd":         CapabilityReadSystemState,
	"os.TempDir":       CapabilityReadSystemState,
	"os.UserHomeDir":   CapabilityReadSystemState,
	"os.UserConfigDir": CapabilityReadSystemState,
	"os.UserCacheDir":  CapabilityReadSystemState,
	"os.ExpandEnv":     CapabilityReadSystemState,
	"os.FindProcess":   CapabilityReadSystemState,
	"os.Getuid":        CapabilityReadSystemState,
	"os.Getgid":        CapabilityReadSystemState,
	"os.Geteuid":       CapabilityReadSystemState,
	"os.Getegid":       CapabilityReadSystemState,
	"os.Getgroups":     CapabilityReadSystemState,
	"os.Getpagesize":   CapabilityReadSystemState,

	// os: changing the working directory mutates process state, not a file.
	"os.Chdir":      CapabilityModifySystemState,
	"os.File.Chdir": CapabilityModifySystemState,

	// os: spawning a process is exec, not a file operation.
	"os.StartProcess": CapabilityExec,

	// os/exec: resolving a binary on PATH only reads the filesystem; it does
	// not itself start a process.
	"os/exec.LookPath": CapabilityFiles,

	// net: enumerating interfaces reads host state rather than touching the
	// network.
	"net.Interfaces":       CapabilityReadSystemState,
	"net.InterfaceByName":  CapabilityReadSystemState,
	"net.InterfaceByIndex": CapabilityReadSystemState,
	"net.InterfaceAddrs":   CapabilityReadSystemState,

	// syscall: reading an environment variable is a state read, not a raw
	// system call in the privileged sense.
	"syscall.Getenv": CapabilityReadSystemState,

	// runtime: locating GOROOT and reading build info are state reads.
	"runtime.GOROOT":              CapabilityReadSystemState,
	"runtime/debug.ReadBuildInfo": CapabilityReadSystemState,
	// runtime/debug: dumping the heap writes a file.
	"runtime/debug.WriteHeapDump": CapabilityFiles,
}

// pkgSinks maps a stdlib package import path to the capability that reaching
// any function in it witnesses, used as the fallback when funcSinks has no
// entry for the callee. Entries are exact import-path matches; the taxonomy is
// adopted from Capslock's sink map (see the attribution note above).
var pkgSinks = map[string]Capability{
	// Network.
	"net":           CapabilityNetwork,
	"net/http":      CapabilityNetwork,
	"net/rpc":       CapabilityNetwork,
	"net/smtp":      CapabilityNetwork,
	"net/textproto": CapabilityNetwork,
	// Files (os is dominated by file operations; env/process/exec are refined
	// in funcSinks above).
	"os":            CapabilityFiles,
	"io/ioutil":     CapabilityFiles,
	"path/filepath": CapabilityFiles,
	// Exec.
	"os/exec": CapabilityExec,
	// Plugins / arbitrary execution.
	"plugin": CapabilityArbitraryExecution,
	// Reflection.
	"reflect": CapabilityReflect,
	// Unsafe.
	"unsafe": CapabilityUnsafePointer,
	// Cgo.
	"runtime/cgo": CapabilityCGo,
	// System calls.
	"syscall":                  CapabilitySystemCalls,
	"golang.org/x/sys/unix":    CapabilitySystemCalls,
	"golang.org/x/sys/windows": CapabilitySystemCalls,
	// Runtime.
	"runtime":       CapabilityRuntime,
	"runtime/debug": CapabilityRuntime,
	// Read system state.
	"os/user": CapabilityReadSystemState,
	// Modify system state (signals, logging).
	"os/signal":  CapabilityModifySystemState,
	"log":        CapabilityModifySystemState,
	"log/syslog": CapabilityModifySystemState,
}

// SPDX-SnippetEnd

// funcKey builds the funcSinks lookup key for a callee. Free functions
// (receiver == "") key on "importPath.Symbol"; methods key on
// "importPath.RecvType.Symbol" with the receiver reduced to its bare type name
// so a pointer receiver ("*File") and a value receiver ("File") share one key.
func funcKey(pkg, receiver, symbol string) string {
	if receiver == "" {
		return pkg + "." + symbol
	}
	return pkg + "." + strings.TrimPrefix(receiver, "*") + "." + symbol
}

// SinkCapability classifies a callee by its package import path, receiver type,
// and symbol. It returns the capability witnessed by reaching that function and
// true when the callee is a sink. A function-level classification (funcSinks)
// wins over the package default (pkgSinks); a callee in no sink package returns
// false. Each function-identity key carries exactly one capability — the
// multi-capability-per-node case (an identity sink plus a body-level fact) is
// handled by NodeCapabilities, not here.
func SinkCapability(pkg, receiver, symbol string) (Capability, bool) {
	if c, ok := funcSinks[funcKey(pkg, receiver, symbol)]; ok {
		return c, true
	}
	if c, ok := pkgSinks[pkg]; ok {
		return c, true
	}
	return "", false
}

// NodeCapabilities returns every capability witnessed by reaching node n. It
// combines the callee-identity classification (SinkCapability over the node's
// package, receiver, and symbol) with the node's body-level facts:
// UsesUnsafePointer witnesses UNSAFE_POINTER and IsAssemblyOrLinkname witnesses
// ARBITRARY_EXECUTION. The body-level facts close the under-approximation gap
// where a sink is a property of a function's body rather than its identity —
// the unsafe package exposes no callable functions, and assembly/linkname
// leaves have no call edges into them, so neither can be caught by the sink map
// alone. The returned slice has no duplicate capabilities.
func NodeCapabilities(n cgdomain.CallNode) []Capability {
	var caps []Capability
	if c, ok := SinkCapability(n.Package, n.Receiver, n.Symbol); ok {
		caps = append(caps, c)
	}
	if n.UsesUnsafePointer && !containsCapability(caps, CapabilityUnsafePointer) {
		caps = append(caps, CapabilityUnsafePointer)
	}
	if n.IsAssemblyOrLinkname && !containsCapability(caps, CapabilityArbitraryExecution) {
		caps = append(caps, CapabilityArbitraryExecution)
	}
	return caps
}

func containsCapability(caps []Capability, c Capability) bool {
	for _, existing := range caps {
		if existing == c {
			return true
		}
	}
	return false
}
