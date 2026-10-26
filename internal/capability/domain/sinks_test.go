package domain

import (
	"reflect"
	"testing"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
)

type sinkCase struct {
	name     string
	pkg      string
	receiver string
	symbol   string
	want     Capability
	by       ClassifiedBy
}

func runSinkCases(t *testing.T, cases []sinkCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SinkCapability(tc.pkg, tc.receiver, tc.symbol)
			if !ok {
				t.Fatalf("%s.%s.%s should be a sink", tc.pkg, tc.receiver, tc.symbol)
			}
			want := Classification{Capability: tc.want, By: tc.by}
			if got != want {
				t.Errorf("SinkCapability(%q, %q, %q) = %+v, want %+v", tc.pkg, tc.receiver, tc.symbol, got, want)
			}
		})
	}
}

const (
	rule = ClassifiedByRule
	dflt = ClassifiedByPackageDefault
)

// Rules 1-3: environment and host identity, ahead of every package rule.
func TestSinkCapability_EnvironmentAndHostIdentity(t *testing.T) {
	runSinkCases(t, []sinkCase{
		{"os.Getenv", "os", "", "Getenv", CapabilityEnvRead, rule},
		{"os.ExpandEnv", "os", "", "ExpandEnv", CapabilityEnvRead, rule},
		{"syscall.Getenv", "syscall", "", "Getenv", CapabilityEnvRead, rule},
		{"x/sys/unix.Environ", "golang.org/x/sys/unix", "", "Environ", CapabilityEnvRead, rule},
		{"x/sys/plan9.Getenv is any x/sys package", "golang.org/x/sys/plan9", "", "Getenv", CapabilityEnvRead, rule},
		{"(*Cmd).Environ", "os/exec", "*Cmd", "Environ", CapabilityEnvRead, rule},
		{"os.Setenv", "os", "", "Setenv", CapabilityEnvWrite, rule},
		{"os.Chdir", "os", "", "Chdir", CapabilityEnvWrite, rule},
		{"syscall.Clearenv", "syscall", "", "Clearenv", CapabilityEnvWrite, rule},
		{"(*File).Chdir", "os", "*File", "Chdir", CapabilityEnvWrite, rule},
		{"(File).Chdir shares the key", "os", "File", "Chdir", CapabilityEnvWrite, rule},
		{"os.Hostname", "os", "", "Hostname", CapabilityHostIdentity, rule},
		{"os.TempDir only names a directory", "os", "", "TempDir", CapabilityHostIdentity, rule},
		{"os/user, the whole package", "os/user", "", "Current", CapabilityHostIdentity, rule},
		{"runtime.GOROOT", "runtime", "", "GOROOT", CapabilityHostIdentity, rule},
		{"runtime/debug.ReadBuildInfo", "runtime/debug", "", "ReadBuildInfo", CapabilityHostIdentity, rule},
		{"net.Interfaces", "net", "", "Interfaces", CapabilityHostIdentity, rule},
		{"net.InterfaceAddrs", "net", "", "InterfaceAddrs", CapabilityHostIdentity, rule},
		{"(*Interface).Addrs", "net", "*Interface", "Addrs", CapabilityHostIdentity, rule},
	})
}

// The env rules take free functions only: a method of the same name on some
// other receiver is not reading the environment.
func TestSinkCapability_EnvRulesAreFreeFunctionsOnly(t *testing.T) {
	runSinkCases(t, []sinkCase{
		{"(*File).Getenv is not env", "os", "*File", "Getenv", CapabilityFSStream, dflt},
		{"(*Cmd).Getenv is exec", "os/exec", "*Cmd", "Getenv", CapabilityExecProcess, rule},
		{"(*File).Hostname is not host identity", "os", "*File", "Hostname", CapabilityFSStream, dflt},
		{"runtime.(*T).GOROOT is runtime", "runtime", "*T", "GOROOT", CapabilityRuntimeInternal, rule},
	})
}

// Rule 4 and its receiver condition: without it (Header).Get and
// (MIMEHeader).Get classify as dials.
func TestSinkCapability_Networking(t *testing.T) {
	runSinkCases(t, []sinkCase{
		{"net.Dial", "net", "", "Dial", CapabilityNetDial, rule},
		{"net/http.Get", "net/http", "", "Get", CapabilityNetDial, rule},
		{"(*Client).Do", "net/http", "*Client", "Do", CapabilityNetDial, rule},
		{"(*Transport).RoundTrip", "net/http", "*Transport", "RoundTrip", CapabilityNetDial, rule},
		{"(*Dialer).DialContext", "net", "*Dialer", "DialContext", CapabilityNetDial, rule},
		{"net/smtp.SendMail", "net/smtp", "", "SendMail", CapabilityNetDial, rule},
		{"net.LookupHost", "net", "", "LookupHost", CapabilityNetDial, rule},
		{"(*Resolver).LookupTXT", "net", "*Resolver", "LookupTXT", CapabilityNetDial, rule},
		{"net.ResolveTCPAddr", "net", "", "ResolveTCPAddr", CapabilityNetDial, rule},
		{"(Header).Get is not a dial", "net/http", "Header", "Get", CapabilityNetInspect, rule},
		{"(MIMEHeader).Get is not a dial", "net/textproto", "MIMEHeader", "Get", CapabilityNetInspect, dflt},
		{"(Header).Lookup is not a dial", "net/http", "Header", "Lookup", CapabilityNetInspect, dflt},
		{"net.Listen", "net", "", "Listen", CapabilityNetListen, rule},
		{"(*TCPListener).Accept", "net", "*TCPListener", "Accept", CapabilityNetListen, rule},
		{"(*Server).Serve", "net/http", "*Server", "Serve", CapabilityNetListen, rule},
		{"net/rpc.Register", "net/rpc", "", "Register", CapabilityNetListen, rule},
		{"(*conn).Read, unexported receiver", "net", "*conn", "Read", CapabilityNetTransfer, rule},
		{"(*conn).Write", "net", "*conn", "Write", CapabilityNetTransfer, rule},
		{"net/http.ReadRequest", "net/http", "", "ReadRequest", CapabilityNetTransfer, rule},
		{"(HandlerFunc).ServeHTTP", "net/http", "HandlerFunc", "ServeHTTP", CapabilityNetTransfer, rule},
		{"(*Client).Call", "net/rpc", "*Client", "Call", CapabilityNetTransfer, rule},
		{"net.ParseIP", "net", "", "ParseIP", CapabilityNetInspect, rule},
		{"net/http.NewRequest", "net/http", "", "NewRequest", CapabilityNetInspect, rule},
		{"(Header).Set", "net/http", "Header", "Set", CapabilityNetInspect, rule},
		{"(IP).String", "net", "IP", "String", CapabilityNetInspect, rule},
		{"(*IPNet).Contains", "net", "*IPNet", "Contains", CapabilityNetInspect, rule},
		{"(*TCPAddr).String, package default", "net", "*TCPAddr", "String", CapabilityNetInspect, dflt},
		{"net/http.init, package default", "net/http", "", "init", CapabilityNetInspect, dflt},
	})
}

// Rules 5-7: path strings, os by operation, io/ioutil by symbol, os/exec.
func TestSinkCapability_FilesAndProcesses(t *testing.T) {
	runSinkCases(t, []sinkCase{
		{"filepath.Join", "path/filepath", "", "Join", CapabilityPathPure, rule},
		{"filepath.Abs", "path/filepath", "", "Abs", CapabilityFSRead, rule},
		{"filepath.WalkDir", "path/filepath", "", "WalkDir", CapabilityFSRead, rule},
		{"filepath.init, package default", "path/filepath", "", "init", CapabilityPathPure, dflt},
		{"os.StartProcess", "os", "", "StartProcess", CapabilityExecProcess, rule},
		{"os.Exit", "os", "", "Exit", CapabilityProcControl, rule},
		{"(*Process).Kill", "os", "*Process", "Kill", CapabilityProcControl, rule},
		{"(*ProcessState).String inspects a process", "os", "*ProcessState", "String", CapabilityProcControl, rule},
		{"(*ProcessState).Success", "os", "*ProcessState", "Success", CapabilityProcControl, rule},
		{"(*Process).Pid, ahead of the symbol tables", "os", "*Process", "Pid", CapabilityProcControl, rule},
		{"(*ProcessState).Sys, not the FS_STREAM default", "os", "ProcessState", "Sys", CapabilityProcControl, rule},
		{"os.WriteFile", "os", "", "WriteFile", CapabilityFSWrite, rule},
		{"os.OpenFile can create", "os", "", "OpenFile", CapabilityFSWrite, rule},
		{"(*File).Write", "os", "*File", "Write", CapabilityFSWrite, rule},
		{"os.Open names a path", "os", "", "Open", CapabilityFSRead, rule},
		{"os.ReadFile", "os", "", "ReadFile", CapabilityFSRead, rule},
		{"(*File).Read is a handle read", "os", "*File", "Read", CapabilityFSStream, rule},
		{"(*File).Close", "os", "*File", "Close", CapabilityFSStream, rule},
		{"os.IsNotExist, package default", "os", "", "IsNotExist", CapabilityFSStream, dflt},
		{"ioutil.ReadFile", "io/ioutil", "", "ReadFile", CapabilityFSRead, rule},
		{"ioutil.ReadDir", "io/ioutil", "", "ReadDir", CapabilityFSRead, rule},
		{"ioutil.WriteFile", "io/ioutil", "", "WriteFile", CapabilityFSWrite, rule},
		{"ioutil.TempFile", "io/ioutil", "", "TempFile", CapabilityFSWrite, rule},
		{"ioutil.TempDir creates a directory", "io/ioutil", "", "TempDir", CapabilityFSWrite, rule},
		{"ioutil.ReadAll", "io/ioutil", "", "ReadAll", CapabilityFSStream, rule},
		{"ioutil.NopCloser", "io/ioutil", "", "NopCloser", CapabilityFSStream, rule},
		{"ioutil.init, package default", "io/ioutil", "", "init", CapabilityFSStream, dflt},
		{"exec.LookPath only searches PATH", "os/exec", "", "LookPath", CapabilityFSRead, rule},
		{"exec.Command", "os/exec", "", "Command", CapabilityExecProcess, rule},
		{"(*Cmd).Run", "os/exec", "*Cmd", "Run", CapabilityExecProcess, rule},
		{"exec.init, package default", "os/exec", "", "init", CapabilityExecProcess, dflt},
		{"(*ExitError).Error runs nothing", "os/exec", "*ExitError", "Error", CapabilityProcControl, rule},
		{"(ExitError).String", "os/exec", "ExitError", "String", CapabilityProcControl, rule},
		{"(*ExitError).ExitCode", "os/exec", "*ExitError", "ExitCode", CapabilityProcControl, rule},
		{"(*Error).Unwrap", "os/exec", "*Error", "Unwrap", CapabilityProcControl, rule},
	})
}

// Rules 8-12.
func TestSinkCapability_RemainingPackages(t *testing.T) {
	runSinkCases(t, []sinkCase{
		{"plugin.Open", "plugin", "", "Open", CapabilityExecDynamic, rule},
		{"(*Plugin).Lookup", "plugin", "*Plugin", "Lookup", CapabilityExecDynamic, rule},
		{"(Value).Call", "reflect", "Value", "Call", CapabilityReflectDynamic, rule},
		{"(Value).SetInt, the Set prefix", "reflect", "Value", "SetInt", CapabilityReflectDynamic, rule},
		{"reflect.MakeFunc", "reflect", "", "MakeFunc", CapabilityReflectDynamic, rule},
		{"reflect.TypeOf, package default", "reflect", "", "TypeOf", CapabilityReflectInspect, dflt},
		{"syscall.Syscall", "syscall", "", "Syscall", CapabilitySyscallDirect, rule},
		{"unix.IoctlGetTermios", "golang.org/x/sys/unix", "", "IoctlGetTermios", CapabilitySyscallDirect, rule},
		{"windows.CloseHandle", "golang.org/x/sys/windows", "", "CloseHandle", CapabilitySyscallDirect, rule},
		{"debug.WriteHeapDump", "runtime/debug", "", "WriteHeapDump", CapabilityFSWrite, rule},
		{"debug.PrintStack", "runtime/debug", "", "PrintStack", CapabilityRuntimeInternal, rule},
		{"log.Printf", "log", "", "Printf", CapabilityLogWrite, rule},
		{"(*Writer).Crit", "log/syslog", "*Writer", "Crit", CapabilityLogWrite, rule},
		{"signal.Notify", "os/signal", "", "Notify", CapabilityProcControl, rule},
		{"cgo.NewHandle", "runtime/cgo", "", "NewHandle", CapabilityCgoCall, rule},
		{"runtime.GC", "runtime", "", "GC", CapabilityRuntimeInternal, rule},
	})
}

// A promoted-method wrapper is stored under the embedded method's package with
// the embedding type's receiver; its ID's own package decides when that is a
// sink package, and the receiver is kept.
func TestNodeCapabilities_PromotedMethodWrapper(t *testing.T) {
	cases := []struct {
		name string
		node cgdomain.CallNode
		pkg  string
		want Capability
		ok   bool
	}{
		{"(*os/exec.ExitError).String is the exit status, not a file stream",
			cgdomain.CallNode{ID: "(*os/exec.ExitError).String", Package: "os", Receiver: "*ExitError", Symbol: "String", IsExternal: true},
			"os/exec", CapabilityProcControl, true},
		{"value form (os/exec.ExitError).Exited",
			cgdomain.CallNode{ID: "(os/exec.ExitError).Exited", Package: "os", Receiver: "ExitError", Symbol: "Exited", IsExternal: true},
			"os/exec", CapabilityProcControl, true},
		{"a grpc-owned wrapper keeps the embedded package's label",
			cgdomain.CallNode{ID: "(*google.golang.org/grpc/test.lazyConn).Close", Package: "net", Receiver: "*lazyConn", Symbol: "Close", IsExternal: true},
			"net", CapabilityNetInspect, true},
		{"(*bufio.ReadWriter).Read is in no sink package",
			cgdomain.CallNode{ID: "(*bufio.ReadWriter).Read", Package: "bufio", Receiver: "*ReadWriter", Symbol: "Read", IsExternal: true},
			"bufio", "", false},
		{"a generic wrapper cuts its type arguments",
			cgdomain.CallNode{ID: "(*os/exec.ExitError[example.com/x.T]).Error", Package: "os", Receiver: "*ExitError", Symbol: "Error", IsExternal: true},
			"os/exec", CapabilityProcControl, true},
		{"a promoted Header.Get keeps its receiver, so it is not a dial",
			cgdomain.CallNode{ID: "(*example.com/m.req).Get", Package: "net/http", Receiver: "Header", Symbol: "Get", IsExternal: true},
			"net/http", CapabilityNetInspect, true},
		{"a plain node is classified by its package",
			cgdomain.CallNode{ID: "os.Getenv", Package: "os", Symbol: "Getenv", IsExternal: true},
			"os", CapabilityEnvRead, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassificationPackage(tc.node); got != tc.pkg {
				t.Errorf("ClassificationPackage = %q, want %q", got, tc.pkg)
			}
			caps := NodeCapabilities(tc.node)
			if (len(caps) > 0) != tc.ok || (tc.ok && caps[0].Capability != tc.want) {
				t.Errorf("NodeCapabilities = %+v, want %s (%v)", caps, tc.want, tc.ok)
			}
		})
	}
	for _, id := range []string{"(broken", "(nodot).M", "(.T).M"} {
		if p, ok := wrapperPackage(id); ok {
			t.Errorf("wrapperPackage(%q) = %q, want no package", id, p)
		}
	}
}

func TestSinkCapabilityMiss(t *testing.T) {
	for _, pkg := range []string{"strings", "unsafe", "golang.org/x/sys/cpu"} {
		if c, ok := SinkCapability(pkg, "", "Pointer"); ok {
			t.Errorf("%s.Pointer should not be a sink, got %+v", pkg, c)
		}
	}
}

func TestBareReceiverStripsStarAndQualifier(t *testing.T) {
	for in, want := range map[string]string{"*File": "File", "File": "File", "*os.File": "File", "": ""} {
		if got := bareReceiver(in); got != want {
			t.Errorf("bareReceiver(%q) = %q, want %q", in, got, want)
		}
	}
}

// Each reach rule, first match winning; unexportedness is the symbol's first
// rune not being upper-case, which keeps _Cgo_use out of DIRECT_CALL.
func TestNodeReach(t *testing.T) {
	cases := []struct {
		name string
		node cgdomain.CallNode
		want Reach
	}{
		{"asm body wins over everything", cgdomain.CallNode{Symbol: "init", IsAssemblyOrLinkname: true}, ReachUnanalyzed},
		{"init", cgdomain.CallNode{Symbol: "init"}, ReachPkgLinkage},
		{"init#2", cgdomain.CallNode{Symbol: "init#2"}, ReachPkgLinkage},
		{"unexported symbol", cgdomain.CallNode{Symbol: "readHosts"}, ReachRuntimePlumbing},
		{"underscore is not upper-case", cgdomain.CallNode{Symbol: "_Cgo_use"}, ReachRuntimePlumbing},
		{"empty symbol", cgdomain.CallNode{Symbol: ""}, ReachRuntimePlumbing},
		{"unexported receiver, exported symbol", cgdomain.CallNode{Receiver: "*conn", Symbol: "Read"}, ReachDirectCall},
		{"exported", cgdomain.CallNode{Symbol: "Dial"}, ReachDirectCall},
	}
	for _, tc := range cases {
		if got := NodeReach(tc.node); got != tc.want {
			t.Errorf("%s: NodeReach = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Each caller kind, first match winning.
func TestNodeCallerKind(t *testing.T) {
	wasm := cgdomain.ExportDirective{Kind: cgdomain.ExportWasm, Name: "run"}
	cases := []struct {
		name string
		node cgdomain.CallNode
		want CallerKind
	}{
		{"test init", cgdomain.CallNode{Symbol: "init", IsTest: true, IsExportedAPI: true}, CallerTestInit},
		{"init#1", cgdomain.CallNode{Symbol: "init#1", IsExportedAPI: true}, CallerInit},
		{"test", cgdomain.CallNode{Symbol: "TestX", IsTest: true, IsExportedAPI: true}, CallerTest},
		{"main", cgdomain.CallNode{Package: "m/cmd/x", Symbol: "main"}, CallerMain},
		{"synthetic test main is not MAIN", cgdomain.CallNode{Package: "m.test", Symbol: "main"}, CallerInternal},
		{"a main method is not MAIN", cgdomain.CallNode{Package: "m", Receiver: "*T", Symbol: "main"}, CallerInternal},
		{"exported API", cgdomain.CallNode{Symbol: "Do", IsExportedAPI: true}, CallerExportedAPI},
		{"export directive", cgdomain.CallNode{Symbol: "run", ExportDirective: wasm}, CallerExportedAPI},
		{"internal", cgdomain.CallNode{Symbol: "helper"}, CallerInternal},
	}
	for _, tc := range cases {
		if got := NodeCallerKind(tc.node); got != tc.want {
			t.Errorf("%s: NodeCallerKind = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestNodeCapabilitiesBodyFacts(t *testing.T) {
	cases := []struct {
		name string
		node cgdomain.CallNode
		want []NodeCapability
	}{
		{
			name: "plain sink from identity",
			node: cgdomain.CallNode{Package: "net/http", Symbol: "Get", IsExternal: true},
			want: []NodeCapability{{CapabilityNetDial, BasisUse, ReachDirectCall, rule}},
		},
		{
			name: "unsafe.Pointer body fact on the module's own node is a direct call",
			node: cgdomain.CallNode{Package: "m/internal", Symbol: "toBytes", UsesUnsafePointer: true},
			want: []NodeCapability{{CapabilityUnsafePointer, BasisUse, ReachDirectCall, rule}},
		},
		{
			name: "an assembly/linkname body yields no capability",
			node: cgdomain.CallNode{Package: "m/internal", Symbol: "asmRound", IsAssemblyOrLinkname: true},
			want: nil,
		},
		{
			name: "an owned asm body with unsafe use is still a direct call",
			node: cgdomain.CallNode{Package: "m", Symbol: "f", UsesUnsafePointer: true, IsAssemblyOrLinkname: true},
			want: []NodeCapability{{CapabilityUnsafePointer, BasisUse, ReachDirectCall, rule}},
		},
		{
			name: "sink identity plus a callee body fact",
			node: cgdomain.CallNode{Package: "reflect", Symbol: "ValueOf", IsExternal: true, UsesUnsafePointer: true},
			want: []NodeCapability{
				{CapabilityReflectInspect, BasisUse, ReachDirectCall, dflt},
				{CapabilityUnsafePointer, BasisCalleeBodyFact, ReachDirectCall, rule},
			},
		},
		{
			name: "no sink and no facts",
			node: cgdomain.CallNode{Package: "strings", Symbol: "Split", IsExternal: true},
			want: nil,
		},
		{
			name: "the unsafe package is not an identity sink",
			node: cgdomain.CallNode{Package: "unsafe", Symbol: "init", IsExternal: true},
			want: nil,
		},
		{
			name: "an external asm callee with an identity label keeps it, unanalysed",
			node: cgdomain.CallNode{Package: "plugin", Symbol: "Open", IsExternal: true, IsAssemblyOrLinkname: true},
			want: []NodeCapability{{CapabilityExecDynamic, BasisUse, ReachUnanalyzed, rule}},
		},
		{
			name: "unsafe.Pointer body fact on an external callee classifies the callee",
			node: cgdomain.CallNode{
				Package: "sync", Receiver: "*RWMutex", Symbol: "lockSlow",
				IsExternal: true, UsesUnsafePointer: true,
			},
			want: []NodeCapability{{CapabilityUnsafePointer, BasisCalleeBodyFact, ReachRuntimePlumbing, rule}},
		},
		{
			name: "an external package init is linkage, not use",
			node: cgdomain.CallNode{Package: "os/exec", Symbol: "init", IsExternal: true},
			want: []NodeCapability{{CapabilityExecProcess, BasisLinkageOnly, ReachPkgLinkage, dflt}},
		},
		{
			name: "an owned init in a sink-named package is the module's own code",
			node: cgdomain.CallNode{Package: "os", Symbol: "init"},
			want: []NodeCapability{{CapabilityFSStream, BasisUse, ReachPkgLinkage, dflt}},
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
