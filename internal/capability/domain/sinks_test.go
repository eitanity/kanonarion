package domain

import (
	"reflect"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func TestSinkCapabilityFunctionLevelWinsOverPackage(t *testing.T) {
	cases := []struct {
		name     string
		pkg      string
		receiver string
		symbol   string
		want     Capability
	}{
		// os defaults to FILES, refined per function.
		{"os.Setenv", "os", "", "Setenv", CapabilityModifySystemState},
		{"os.Getenv", "os", "", "Getenv", CapabilityReadSystemState},
		{"os.StartProcess is exec not files", "os", "", "StartProcess", CapabilityExec},
		{"os.Executable reads state", "os", "", "Executable", CapabilityReadSystemState},
		{"os.Chdir modifies state", "os", "", "Chdir", CapabilityModifySystemState},
		// os/exec defaults to EXEC, but LookPath only reads the filesystem.
		{"os/exec.LookPath is files not exec", "os/exec", "", "LookPath", CapabilityFiles},
		// net defaults to NETWORK, but interface enumeration reads host state.
		{"net.Interfaces reads state", "net", "", "Interfaces", CapabilityReadSystemState},
		{"net.InterfaceByName reads state", "net", "", "InterfaceByName", CapabilityReadSystemState},
		// syscall defaults to SYSTEM_CALLS, but Getenv is a state read.
		{"syscall.Getenv reads state", "syscall", "", "Getenv", CapabilityReadSystemState},
		// runtime defaults to RUNTIME, refined for state reads and heap dumps.
		{"runtime.GOROOT reads state", "runtime", "", "GOROOT", CapabilityReadSystemState},
		{"runtime/debug.ReadBuildInfo reads state", "runtime/debug", "", "ReadBuildInfo", CapabilityReadSystemState},
		{"runtime/debug.WriteHeapDump writes a file", "runtime/debug", "", "WriteHeapDump", CapabilityFiles},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SinkCapability(tc.pkg, tc.receiver, tc.symbol)
			if !ok {
				t.Fatalf("%s should be a sink", tc.name)
			}
			if got != tc.want {
				t.Errorf("%s = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestSinkCapabilityReceiverQualifiedMethod(t *testing.T) {
	// (*os.File).Chdir is a MODIFY_SYSTEM_STATE method while package os defaults
	// to FILES. Pointer and value receiver spellings must share the one key.
	for _, recv := range []string{"*File", "File"} {
		got, ok := SinkCapability("os", recv, "Chdir")
		if !ok {
			t.Fatalf("(%s).Chdir should be a sink", recv)
		}
		if got != CapabilityModifySystemState {
			t.Errorf("os (%s).Chdir = %q, want %q", recv, got, CapabilityModifySystemState)
		}
	}

	// A method whose receiver-qualified key is not in funcSinks falls back to
	// the package default rather than matching a same-named free function.
	got, ok := SinkCapability("os", "*File", "Read")
	if !ok || got != CapabilityFiles {
		t.Errorf("(*os.File).Read = %q,%v want %q", got, ok, CapabilityFiles)
	}
}

func TestSinkCapabilityPackageLevel(t *testing.T) {
	cases := map[string]Capability{
		"net/http":    CapabilityNetwork,
		"os":          CapabilityFiles,
		"os/exec":     CapabilityExec,
		"reflect":     CapabilityReflect,
		"unsafe":      CapabilityUnsafePointer,
		"runtime/cgo": CapabilityCGo,
		"syscall":     CapabilitySystemCalls,
		"runtime":     CapabilityRuntime,
		"os/user":     CapabilityReadSystemState,
		"os/signal":   CapabilityModifySystemState,
		"plugin":      CapabilityArbitraryExecution,
	}
	for pkg, want := range cases {
		got, ok := SinkCapability(pkg, "", "SomeFunc")
		if !ok {
			t.Errorf("%s should be a sink", pkg)
			continue
		}
		if got != want {
			t.Errorf("%s = %q, want %q", pkg, got, want)
		}
	}
}

func TestSinkCapabilityMiss(t *testing.T) {
	if _, ok := SinkCapability("strings", "", "Split"); ok {
		t.Error("strings.Split should not be a sink")
	}
}

func TestNodeCapabilitiesBodyFacts(t *testing.T) {
	cases := []struct {
		name string
		node cgdomain.CallNode
		want []NodeCapability
	}{
		{
			name: "plain sink from package identity",
			node: cgdomain.CallNode{Package: "net/http", Symbol: "Get", IsExternal: true},
			want: []NodeCapability{{CapabilityNetwork, BasisUse}},
		},
		{
			name: "unsafe.Pointer body fact on the module's own node",
			node: cgdomain.CallNode{Package: "m/internal", Symbol: "toBytes", UsesUnsafePointer: true},
			want: []NodeCapability{{CapabilityUnsafePointer, BasisUse}},
		},
		{
			name: "assembly/linkname body fact on the module's own node",
			node: cgdomain.CallNode{Package: "m/internal", Symbol: "asmRound", IsAssemblyOrLinkname: true},
			want: []NodeCapability{{CapabilityArbitraryExecution, BasisUse}},
		},
		{
			name: "both body facts on one owned node",
			node: cgdomain.CallNode{Package: "m", Symbol: "F", UsesUnsafePointer: true, IsAssemblyOrLinkname: true},
			want: []NodeCapability{
				{CapabilityUnsafePointer, BasisUse},
				{CapabilityArbitraryExecution, BasisUse},
			},
		},
		{
			name: "sink identity plus a body fact",
			node: cgdomain.CallNode{Package: "reflect", Symbol: "ValueOf", IsExternal: true, UsesUnsafePointer: true},
			want: []NodeCapability{
				{CapabilityReflect, BasisUse},
				{CapabilityUnsafePointer, BasisCalleeBodyFact},
			},
		},
		{
			name: "no sink and no facts",
			node: cgdomain.CallNode{Package: "strings", Symbol: "Split", IsExternal: true},
			want: nil,
		},
		{
			name: "unsafe package identity and unsafe body fact do not duplicate",
			node: cgdomain.CallNode{Package: "unsafe", Symbol: "Pointer", IsExternal: true, UsesUnsafePointer: true},
			want: []NodeCapability{{CapabilityUnsafePointer, BasisUse}},
		},
		{
			name: "plugin identity and assembly fact do not duplicate ARBITRARY_EXECUTION",
			node: cgdomain.CallNode{Package: "plugin", Symbol: "Open", IsExternal: true, IsAssemblyOrLinkname: true},
			want: []NodeCapability{{CapabilityArbitraryExecution, BasisUse}},
		},
		{
			name: "unsafe.Pointer body fact on an external callee classifies the callee",
			node: cgdomain.CallNode{
				Package: "sync", Receiver: "*RWMutex", Symbol: "Lock",
				IsExternal: true, UsesUnsafePointer: true,
			},
			want: []NodeCapability{{CapabilityUnsafePointer, BasisCalleeBodyFact}},
		},
		{
			name: "linkname body fact on an external callee classifies the callee",
			node: cgdomain.CallNode{
				Package: "time", Symbol: "Sleep", IsExternal: true, IsAssemblyOrLinkname: true,
			},
			want: []NodeCapability{{CapabilityArbitraryExecution, BasisCalleeBodyFact}},
		},
		{
			name: "an external package init is linkage, not use",
			node: cgdomain.CallNode{Package: "os/exec", Symbol: "init", IsExternal: true},
			want: []NodeCapability{{CapabilityExec, BasisLinkageOnly}},
		},
		{
			name: "a generated init#N is linkage too",
			node: cgdomain.CallNode{Package: "io/ioutil", Symbol: "init#1", IsExternal: true},
			want: []NodeCapability{{CapabilityFiles, BasisLinkageOnly}},
		},
		{
			name: "an owned init in a sink-named package is the module's own code",
			node: cgdomain.CallNode{Package: "os", Symbol: "init"},
			want: []NodeCapability{{CapabilityFiles, BasisUse}},
		},
		{
			name: "a real call into the init's package is unaffected",
			node: cgdomain.CallNode{Package: "os/exec", Symbol: "Command", IsExternal: true},
			want: []NodeCapability{{CapabilityExec, BasisUse}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NodeCapabilities(tc.node)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("NodeCapabilities = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCapabilityBasisExplanation pins the reader-facing line for each basis:
// only "use" is silent, because only "use" needs no qualification.
func TestCapabilityBasisExplanation(t *testing.T) {
	if got := BasisUse.Explanation(); got != "" {
		t.Errorf("BasisUse explanation = %q, want empty", got)
	}
	for _, b := range []CapabilityBasis{BasisLinkageOnly, BasisCalleeBodyFact} {
		if BasisLinkageOnly.Explanation() == BasisCalleeBodyFact.Explanation() {
			t.Fatal("the two qualified bases must not share one explanation")
		}
		if got := b.Explanation(); got == "" {
			t.Errorf("%s has no explanation", b)
		}
	}
	if want := []CapabilityBasis{BasisUse, BasisLinkageOnly, BasisCalleeBodyFact}; !reflect.DeepEqual(AllCapabilityBases(), want) {
		t.Errorf("AllCapabilityBases = %v, want %v", AllCapabilityBases(), want)
	}
}
