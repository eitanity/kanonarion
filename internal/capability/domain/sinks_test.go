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
		want []Capability
	}{
		{
			name: "plain sink from package identity",
			node: cgdomain.CallNode{Package: "net/http", Symbol: "Get"},
			want: []Capability{CapabilityNetwork},
		},
		{
			name: "unsafe.Pointer body fact on a non-sink node",
			node: cgdomain.CallNode{Package: "goja/unistring", Symbol: "AsUtf16", UsesUnsafePointer: true},
			want: []Capability{CapabilityUnsafePointer},
		},
		{
			name: "assembly/linkname body fact on a non-sink node",
			node: cgdomain.CallNode{Package: "internal/cpuinfo", Symbol: "x86extensions", IsAssemblyOrLinkname: true},
			want: []Capability{CapabilityArbitraryExecution},
		},
		{
			name: "both body facts on one node",
			node: cgdomain.CallNode{Package: "x", Symbol: "F", UsesUnsafePointer: true, IsAssemblyOrLinkname: true},
			want: []Capability{CapabilityUnsafePointer, CapabilityArbitraryExecution},
		},
		{
			name: "sink identity plus a body fact",
			node: cgdomain.CallNode{Package: "reflect", Symbol: "ValueOf", UsesUnsafePointer: true},
			want: []Capability{CapabilityReflect, CapabilityUnsafePointer},
		},
		{
			name: "no sink and no facts",
			node: cgdomain.CallNode{Package: "strings", Symbol: "Split"},
			want: nil,
		},
		{
			name: "unsafe package identity and unsafe body fact do not duplicate",
			node: cgdomain.CallNode{Package: "unsafe", Symbol: "Pointer", UsesUnsafePointer: true},
			want: []Capability{CapabilityUnsafePointer},
		},
		{
			name: "plugin identity and assembly fact do not duplicate ARBITRARY_EXECUTION",
			node: cgdomain.CallNode{Package: "plugin", Symbol: "Open", IsAssemblyOrLinkname: true},
			want: []Capability{CapabilityArbitraryExecution},
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
