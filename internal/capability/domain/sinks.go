package domain

import (
	"strings"
	"unicode"
	"unicode/utf8"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
)

// symbols is a set of symbol names.
type symbols map[string]struct{}

func symbolSet(names ...string) symbols {
	s := make(symbols, len(names))
	for _, n := range names {
		s[n] = struct{}{}
	}
	return s
}

func (s symbols) has(name string) bool {
	_, ok := s[name]
	return ok
}

// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Copyright 2023 Google LLC
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-SnippetName: Capslock stdlib capability classification data
// SPDX-SnippetComment: Transcribed from github.com/google/capslock@v0.3.2, interesting/interesting.cm
//
// The tables below began as Capslock's which-function-carries-which-capability
// judgement over the standard library. The labels they assign are kanonarion's
// own taxonomy (capability.go), not Capslock's names, and the split of each
// package into labels is kanonarion's. The SPDX tags above are the
// machine-readable attribution record consumed by `kanonarion notice`; keep
// them and the closing SPDX-SnippetEnd intact when editing the tables.

var (
	envReadSymbols  = symbolSet("Getenv", "LookupEnv", "Environ", "ExpandEnv")
	envWriteSymbols = symbolSet("Setenv", "Unsetenv", "Clearenv", "Chdir")

	hostIdentityOS = symbolSet("Hostname", "Getpid", "Getppid", "Getuid", "Getgid", "Geteuid",
		"Getegid", "Getgroups", "Getpagesize", "Executable", "Getwd", "TempDir", "UserHomeDir",
		"UserConfigDir", "UserCacheDir")

	netPackages = symbolSet("net", "net/http", "net/textproto", "net/rpc", "net/smtp")
	netDial     = symbolSet("Dial", "DialTCP", "DialUDP", "DialIP", "DialUnix", "DialTimeout",
		"DialContext", "FileConn", "FilePacketConn", "SendMail", "NewClient", "NewClientWithCodec",
		"NewClientConn", "RoundTrip", "Do", "Get", "Head", "Post", "PostForm")
	// netDialReceivers is load-bearing: without it (Header).Get and
	// (MIMEHeader).Get classify as dials.
	netDialReceivers = symbolSet("", "Client", "Transport", "ClientConn", "Dialer", "Resolver", "Conn")
	netListen        = symbolSet("Listen", "ListenTCP", "ListenUDP", "ListenIP", "ListenUnix",
		"ListenPacket", "ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS", "ServeCodec",
		"Accept", "AcceptTCP", "AcceptUnix", "HandleHTTP", "NewServer", "Register")
	netTransfer = symbolSet("Cmd", "Call", "Push", "Flush", "Hijack", "Pipe", "ServeContent",
		"ServeFile", "ServeHTTP", "FileServer", "FileServerFS", "ReadRequest", "ReadResponse",
		"CloseWrite", "SyscallConn")
	netInspect = symbolSet("ParseIP", "ParseCIDR", "ParseMAC", "SplitHostPort", "JoinHostPort",
		"CanonicalMIMEHeaderKey", "StatusText", "NewRequest", "LocalAddr", "RemoteAddr", "SetDeadline")
	netInspectHeader    = symbolSet("Get", "Set", "Add", "Del", "Values")
	netInspectReceivers = symbolSet("IP", "IPNet", "IPMask")

	pathPure = symbolSet("Join", "Clean", "Base", "Dir", "Ext", "Split", "SplitList", "ToSlash",
		"FromSlash", "IsAbs", "IsLocal", "Match", "Rel", "VolumeName", "HasPrefix", "Localize")
	pathRead = symbolSet("Abs", "EvalSymlinks", "Glob", "Walk", "WalkDir")

	// osProcessReceivers inspect or signal a process; every method is
	// PROC_CONTROL, as the os/exec exit-status types are.
	osProcessReceivers = symbolSet("Process", "ProcessState")
	osProcControl      = symbolSet("Exit", "FindProcess", "Kill", "Signal", "Wait", "ExitCode")
	osWrite            = symbolSet("Create", "CreateTemp", "OpenFile", "Mkdir", "MkdirAll", "MkdirTemp",
		"Remove", "RemoveAll", "Rename", "Link", "Symlink", "Truncate", "Chmod", "Chown", "Chtimes",
		"WriteFile", "TempFile", "Write", "WriteAt", "WriteString", "WriteTo", "ReadFrom", "Sync")
	// osRead holds the operations that name a path. A read on an open handle is
	// often an io.Reader dispatch target, not a deliberate file read.
	osRead = symbolSet("Open", "OpenRoot", "ReadFile", "ReadDir", "Readdir", "Readdirnames",
		"Readlink", "Lstat", "Stat", "DirFS", "SameFile")
	osStream = symbolSet("Read", "ReadAt", "Seek", "Close", "Fd", "Name", "NewFile", "FS", "ReadAll")

	ioutilSymbols = map[string]Capability{
		"ReadFile": CapabilityFSRead, "ReadDir": CapabilityFSRead,
		"WriteFile": CapabilityFSWrite, "TempFile": CapabilityFSWrite, "TempDir": CapabilityFSWrite,
		"ReadAll": CapabilityFSStream, "NopCloser": CapabilityFSStream, "Discard": CapabilityFSStream,
	}

	// execStart builds a command; every (*Cmd) method operates one.
	execStart = symbolSet("Command", "CommandContext")
	// execStatusReceivers format or unwrap an exit status, which runs nothing.
	execStatusReceivers = symbolSet("ExitError", "Error")

	reflectDynamic = symbolSet("Call", "CallSlice", "Method", "MethodByName", "Methods", "MakeFunc",
		"NewAt", "Select", "Send", "Recv", "UnsafeAddr", "Pointer")

	// wholePackage names packages whose every function carries one label.
	wholePackage = map[string]Capability{
		"plugin":                   CapabilityExecDynamic,
		"syscall":                  CapabilitySyscallDirect,
		"golang.org/x/sys/unix":    CapabilitySyscallDirect,
		"golang.org/x/sys/windows": CapabilitySyscallDirect,
		"log":                      CapabilityLogWrite,
		"log/syslog":               CapabilityLogWrite,
		"os/signal":                CapabilityProcControl,
		"runtime/cgo":              CapabilityCgoCall,
		"runtime":                  CapabilityRuntimeInternal,
	}
)

// SPDX-SnippetEnd

// Classification is the label one callee carries and how it was decided.
type Classification struct {
	Capability Capability
	By         ClassifiedBy
}

func byRule(c Capability) (Classification, bool) {
	return Classification{Capability: c, By: ClassifiedByRule}, true
}

func byDefault(c Capability) (Classification, bool) {
	return Classification{Capability: c, By: ClassifiedByPackageDefault}, true
}

// bareReceiver strips a pointer star and any package qualifier.
func bareReceiver(receiver string) string {
	r := strings.TrimPrefix(receiver, "*")
	if i := strings.LastIndex(r, "."); i >= 0 {
		r = r[i+1:]
	}
	return r
}

// envPackage is os, syscall or any golang.org/x/sys package.
func envPackage(pkg string) bool {
	return pkg == "os" || pkg == "syscall" || strings.HasPrefix(pkg, "golang.org/x/sys/")
}

// SinkCapability classifies a callee by import path, receiver and symbol.
// The rules are evaluated in order and the first match wins; a callee in no
// sink package returns false. UNSAFE_POINTER is never an identity label: it
// comes only from the body fact (see NodeCapabilities).
func SinkCapability(pkg, receiver, symbol string) (Classification, bool) {
	bare := bareReceiver(receiver)
	free := receiver == ""
	switch {
	case isEnvRead(pkg, bare, free, symbol):
		return byRule(CapabilityEnvRead)
	case isEnvWrite(pkg, bare, free, symbol):
		return byRule(CapabilityEnvWrite)
	case isHostIdentity(pkg, bare, free, symbol):
		return byRule(CapabilityHostIdentity)
	case netPackages.has(pkg):
		return classifyNet(bare, symbol)
	}
	if classify, ok := packageRules[pkg]; ok {
		return classify(bare, symbol)
	}
	if c, ok := wholePackage[pkg]; ok {
		return byRule(c)
	}
	return Classification{}, false
}

// packageRules holds rules 5-9 and 11: packages split by symbol or receiver.
var packageRules = map[string]func(bare, symbol string) (Classification, bool){
	"path/filepath": classifyPath,
	"os":            classifyOS,
	"io/ioutil":     classifyIoutil,
	"os/exec":       classifyExec,
	"reflect":       classifyReflect,
	"runtime/debug": classifyRuntimeDebug,
}

// isEnvRead is rule 1.
func isEnvRead(pkg, bare string, free bool, symbol string) bool {
	if pkg == "os/exec" {
		return bare == "Cmd" && symbol == "Environ"
	}
	return free && envPackage(pkg) && envReadSymbols.has(symbol)
}

// isEnvWrite is rule 2.
func isEnvWrite(pkg, bare string, free bool, symbol string) bool {
	if pkg == "os" && bare == "File" {
		return symbol == "Chdir"
	}
	return free && envPackage(pkg) && envWriteSymbols.has(symbol)
}

// isHostIdentity is rule 3: who and where the process is.
func isHostIdentity(pkg, bare string, free bool, symbol string) bool {
	switch pkg {
	case "os":
		return free && hostIdentityOS.has(symbol)
	case "os/user":
		return true
	case "runtime":
		return free && symbol == "GOROOT"
	case "runtime/debug":
		return symbol == "ReadBuildInfo"
	case "net":
		// net.Interface* over the funcSinks key: the free functions and the
		// methods on Interface.
		if free {
			return strings.HasPrefix(symbol, "Interface")
		}
		return strings.HasPrefix(bare, "Interface")
	}
	return false
}

// classifyNet is rule 4, over net, net/http, net/textproto, net/rpc, net/smtp.
func classifyNet(bare, symbol string) (Classification, bool) {
	switch {
	case netDial.has(symbol) && netDialReceivers.has(bare),
		(strings.HasPrefix(symbol, "Lookup") || strings.HasPrefix(symbol, "Resolve")) && bare != "Header":
		return byRule(CapabilityNetDial)
	case netListen.has(symbol):
		return byRule(CapabilityNetListen)
	case strings.HasPrefix(symbol, "Read"), strings.HasPrefix(symbol, "Write"), netTransfer.has(symbol):
		return byRule(CapabilityNetTransfer)
	case netInspect.has(symbol), bare == "Header" && netInspectHeader.has(symbol), netInspectReceivers.has(bare):
		return byRule(CapabilityNetInspect)
	}
	return byDefault(CapabilityNetInspect)
}

// classifyPath is rule 5.
func classifyPath(_, symbol string) (Classification, bool) {
	switch {
	case pathPure.has(symbol):
		return byRule(CapabilityPathPure)
	case pathRead.has(symbol):
		return byRule(CapabilityFSRead)
	}
	return byDefault(CapabilityPathPure)
}

// classifyOS is rule 6 for os, after rules 1-3 took env and host identity.
func classifyOS(bare, symbol string) (Classification, bool) {
	switch {
	case osProcessReceivers.has(bare):
		return byRule(CapabilityProcControl)
	case symbol == "StartProcess":
		return byRule(CapabilityExecProcess)
	case osProcControl.has(symbol):
		return byRule(CapabilityProcControl)
	case osWrite.has(symbol):
		return byRule(CapabilityFSWrite)
	case osRead.has(symbol):
		return byRule(CapabilityFSRead)
	case osStream.has(symbol):
		return byRule(CapabilityFSStream)
	}
	return byDefault(CapabilityFSStream)
}

// classifyIoutil is rule 6 for io/ioutil, which follows os by symbol.
func classifyIoutil(_, symbol string) (Classification, bool) {
	if c, ok := ioutilSymbols[symbol]; ok {
		return byRule(c)
	}
	return byDefault(CapabilityFSStream)
}

// classifyReflect is rule 9.
func classifyReflect(_, symbol string) (Classification, bool) {
	if reflectDynamic.has(symbol) || strings.HasPrefix(symbol, "Set") {
		return byRule(CapabilityReflectDynamic)
	}
	return byDefault(CapabilityReflectInspect)
}

// classifyRuntimeDebug is rule 11, then rule 12 for the rest of the package.
func classifyRuntimeDebug(_, symbol string) (Classification, bool) {
	if symbol == "WriteHeapDump" {
		return byRule(CapabilityFSWrite)
	}
	return byRule(CapabilityRuntimeInternal)
}

// classifyExec is rule 7.
func classifyExec(bare, symbol string) (Classification, bool) {
	switch {
	case symbol == "LookPath":
		return byRule(CapabilityFSRead)
	case execStatusReceivers.has(bare):
		return byRule(CapabilityProcControl)
	case bare == "Cmd", execStart.has(symbol):
		return byRule(CapabilityExecProcess)
	}
	return byDefault(CapabilityExecProcess)
}

// NodeReach is how deliberately reaching n uses its capability. First match
// wins; unexportedness is tested on the symbol, as "first rune is not
// upper-case", so net.(*conn).Read stays a direct call and _Cgo_use does not.
func NodeReach(n cgdomain.CallNode) Reach {
	switch {
	case n.IsAssemblyOrLinkname:
		return ReachUnanalyzed
	case cgdomain.IsInitSymbol(n.Symbol):
		return ReachPkgLinkage
	}
	if !exportedSymbol(n.Symbol) {
		return ReachRuntimePlumbing
	}
	return ReachDirectCall
}

// exportedSymbol is "first rune is upper-case", so _Cgo_use is unexported.
func exportedSymbol(symbol string) bool {
	r, _ := utf8.DecodeRuneInString(symbol)
	return unicode.IsUpper(r)
}

// NodeCallerKind is the kind of n as the function making a call. First match
// wins.
func NodeCallerKind(n cgdomain.CallNode) CallerKind {
	isInit := cgdomain.IsInitSymbol(n.Symbol)
	switch {
	case isInit && n.IsTest:
		return CallerTestInit
	case isInit:
		return CallerInit
	case n.IsTest:
		return CallerTest
	case n.Symbol == "main" && n.Receiver == "" && !cgdomain.IsSyntheticTestMain(n.Package, n.Symbol, n.Receiver):
		return CallerMain
	case n.IsExportedAPI, !n.ExportDirective.IsZero():
		return CallerExportedAPI
	}
	return CallerInternal
}

// wrapperPackage returns the import path inside a promoted-method wrapper ID,
// "(*pkg.T).M" or "(pkg.T).M", and false for any other ID. Type arguments are
// cut first: they can hold dotted paths of their own.
func wrapperPackage(id string) (string, bool) {
	if !strings.HasPrefix(id, "(") {
		return "", false
	}
	end := strings.Index(id, ")")
	if end < 0 {
		return "", false
	}
	inner := strings.TrimPrefix(id[1:end], "*")
	if i := strings.Index(inner, "["); i >= 0 {
		inner = inner[:i]
	}
	dot := strings.LastIndex(inner, ".")
	if dot <= 0 {
		return "", false
	}
	return inner[:dot], true
}

// ClassificationPackage is the package a node's label is decided in. A
// promoted-method wrapper is stored under the embedded method's package with
// the embedding type's receiver, so (*os/exec.ExitError).String sits in "os";
// when the ID's own package is a sink package it decides, receiver kept.
func ClassificationPackage(n cgdomain.CallNode) string {
	if p, ok := wrapperPackage(n.ID); ok && p != n.Package {
		if _, sink := SinkCapability(p, n.Receiver, n.Symbol); sink {
			return p
		}
	}
	return n.Package
}

// NodeCapability is one capability a node can witness, with what reaching it
// establishes, how deliberately, and how the label was decided.
type NodeCapability struct {
	Capability   Capability
	Basis        CapabilityBasis
	Reach        Reach
	ClassifiedBy ClassifiedBy
}

// NodeCapabilities returns every capability reaching n could witness.
//
// Identity comes first, then the UsesUnsafePointer body fact, the only source
// of UNSAFE_POINTER. An assembly or linkname body yields no capability: the
// graph cannot see what it does, so it is reported as unanalysed instead.
//
// Two shapes are classified but are not the analysed module's capability, so
// each carries its own basis: an external package's init (linkage), and a body
// fact on an external node, which classifies that function and not its caller.
// An owned node's own body fact is a direct call: its own code does it.
func NodeCapabilities(n cgdomain.CallNode) []NodeCapability {
	var caps []NodeCapability
	reach := NodeReach(n)
	if cl, ok := SinkCapability(ClassificationPackage(n), n.Receiver, n.Symbol); ok {
		basis := BasisUse
		if n.IsExternal && cgdomain.IsInitSymbol(n.Symbol) {
			basis = BasisLinkageOnly
		}
		caps = append(caps, NodeCapability{Capability: cl.Capability, Basis: basis, Reach: reach, ClassifiedBy: cl.By})
	}
	if n.UsesUnsafePointer {
		nc := NodeCapability{Capability: CapabilityUnsafePointer, Basis: BasisUse, Reach: ReachDirectCall, ClassifiedBy: ClassifiedByRule}
		if n.IsExternal {
			nc.Basis, nc.Reach = BasisCalleeBodyFact, reach
		}
		caps = append(caps, nc)
	}
	return caps
}
