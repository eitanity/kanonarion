package cli

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	"code.eitanity.com/kanonarion/internal/cli/testfakes"
	"code.eitanity.com/kanonarion/internal/coordinate"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	ifacesqlite "code.eitanity.com/kanonarion/internal/iface/adapters/store/sqlite"
	ifaceapp "code.eitanity.com/kanonarion/internal/iface/application"
	ifacedomain "code.eitanity.com/kanonarion/internal/iface/domain"
	ifaceports "code.eitanity.com/kanonarion/internal/iface/ports"
)

// The symbol index is keyed on the pipeline version, so a module held only at a
// superseded one is invisible to symbol-find and symbol-context. These tests
// hold a miss over such a module apart from "nothing exports this name".

// symbolStoreModule is one interface record a fixture store holds.
type symbolStoreModule struct {
	path, version, pipeline, fn string
	// typ and method, when set, add a type declaring that method.
	typ, method string
	// pkg is the package's import path; empty is the module root.
	pkg string
}

// seedSymbolStore writes a real store holding the given interface records, so
// the lookups run end to end through Run.
func seedSymbolStore(t *testing.T, mods ...symbolStoreModule) string {
	t.Helper()
	root := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the fixture store: %v", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("closing the fixture store: %v", cerr)
		}
	}()
	if merr := sqlitestore.Apply(db, allMigrations()); merr != nil {
		t.Fatalf("migrating the fixture store: %v", merr)
	}
	store := ifacesqlite.New(db)
	for _, m := range mods {
		coord, cerr := coordinate.NewModuleCoordinate(m.path, m.version)
		if cerr != nil {
			t.Fatal(cerr)
		}
		importPath := m.path
		if m.pkg != "" {
			importPath = m.pkg
		}
		pkg := ifacedomain.PackageInterface{
			ImportPath: importPath, Name: packageName(importPath),
			Funcs: []ifacedomain.FuncDecl{{Name: m.fn, Signature: "func " + m.fn + "()"}},
		}
		if m.typ != "" {
			pkg.Types = []ifacedomain.TypeDecl{{
				Name: m.typ, Kind: ifacedomain.TypeKindStruct, Signature: "type " + m.typ + " struct{}",
				Methods: []ifacedomain.MethodDecl{{Name: m.method, Signature: "func (" + m.typ + ") " + m.method + "() string"}},
			}}
		}
		rec := ifacedomain.InterfaceRecord{
			SchemaVersion:    ifacedomain.InterfaceSchemaVersion,
			Ecosystem:        fetchdomain.EcosystemGo,
			Coordinate:       coord,
			Packages:         []ifacedomain.PackageInterface{pkg},
			OverallStatus:    ifacedomain.InterfaceStatusExtracted,
			ExtractedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			PipelineVersion:  m.pipeline,
			ArtefactIdentity: "zip:h1:" + m.path + "@" + m.version,
		}
		rec, err = ifacedomain.InterfaceRecordHasher{}.SetContentHash(rec)
		if err != nil {
			t.Fatalf("sealing %s: %v", coord, err)
		}
		if perr := store.PutInterfaceRecord(context.Background(), rec); perr != nil {
			t.Fatalf("seeding %s: %v", coord, perr)
		}
	}
	return root
}

var (
	servedModule = symbolStoreModule{path: "example.com/served", version: "v1.0.0", pipeline: ifaceapp.PipelineVersion, fn: "Served"}
	heldModule   = symbolStoreModule{path: "example.com/held", version: "v1.2.0", pipeline: supersededPipeline, fn: "Held"}
	heldOlder    = symbolStoreModule{path: "example.com/held", version: "v1.1.0", pipeline: supersededPipeline, fn: "Held"}
	uuidModule   = symbolStoreModule{path: "example.com/google/uuid", version: "v1.6.0", pipeline: ifaceapp.PipelineVersion,
		fn: "NewString", typ: "UUID", method: "String"}
	errorsModule = symbolStoreModule{path: "example.com/pkg/errors/v2", version: "v2.0.0", pipeline: ifaceapp.PipelineVersion, fn: "Wrap"}
	otherErrors  = symbolStoreModule{path: "example.com/other/errors", version: "v1.0.0", pipeline: ifaceapp.PipelineVersion, fn: "Wrap"}
)

// runSymbol runs one lookup and returns both streams and the exit code.
func runSymbol(t *testing.T, root string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := Run(append(args, "--store-root", root), &out, &errOut)
	code = 0
	if err != nil {
		code = ExitCodeForError(err)
		errOut.WriteString(err.Error())
	}
	return out.String(), errOut.String(), code
}

func wantContains(t *testing.T, label, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("%s is missing %q, got:\n%s", label, w, got)
		}
	}
}

func TestSymbolLookups_AllSupersededIsNotFound(t *testing.T) {
	root := seedSymbolStore(t, heldModule)
	for _, args := range [][]string{
		{"symbol-find", "Held"}, {"symbol-find", "Held", "--json"},
		{"symbol-find", "NothingExportsThis"},
		{"symbol-context", "Held"}, {"symbol-context", "Held", "--json"},
		{"symbol-context", "example.com/held.Held"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := runSymbol(t, root, args...)
			if code != ExitNotFound {
				t.Errorf("exit = %d, want %d", code, ExitNotFound)
			}
			if stdout != "" {
				t.Errorf("stdout must be empty on a miss, got %q", stdout)
			}
			if strings.Contains(stdout+stderr, "no exports found") {
				t.Errorf("a store it could not read was reported as no exports:\n%s", stderr)
			}
			wantContains(t, "the miss", stderr, supersededPipeline, "example.com/held@v1.2.0")
			// A bare name spans the store, so the statement is about the store.
			if !strings.Contains(args[1], ".") {
				wantContains(t, "the miss", stderr,
					"none of the 1 interface record(s) the store holds is at pipeline "+ifaceapp.PipelineVersion)
			}
		})
	}
}

func TestSymbolLookups_RemedyNamesTheCoordinateWhereTheModuleIsKnown(t *testing.T) {
	root := seedSymbolStore(t, heldModule, heldOlder, servedModule)
	_, stderr, code := runSymbol(t, root, "symbol-context", "example.com/held.Held")
	if code != ExitNotFound {
		t.Fatalf("exit = %d, want %d", code, ExitNotFound)
	}
	wantContains(t, "symbol-context", stderr,
		"kanonarion interface example.com/held@v1.2.0",
		"1 other version(s) of example.com/held are held")

	// symbol-find spans every module, so it keeps the general form.
	_, stderr, code = runSymbol(t, root, "symbol-find", "Held")
	if code != ExitNotFound {
		t.Fatalf("exit = %d, want %d", code, ExitNotFound)
	}
	wantContains(t, "symbol-find", stderr,
		"2 module(s) that could answer are held only at a superseded interface pipeline",
		"example.com/held@v1.2.0, example.com/held@v1.1.0",
		"kanonarion interface <module>@<version>",
		"kanonarion interface-list --all-generations")
}

func TestSymbolLookups_MixedStoreAnswerNamesWhatItDidNotRead(t *testing.T) {
	root := seedSymbolStore(t, heldModule, servedModule)
	for _, args := range [][]string{
		{"symbol-find", "Served"}, {"symbol-find", "Served", "--json"},
		{"symbol-context", "Served"}, {"symbol-context", "Served", "--json"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := runSymbol(t, root, args...)
			if code != 0 {
				t.Fatalf("exit = %d, want 0; stderr:\n%s", code, stderr)
			}
			wantContains(t, "the answer", stdout, "example.com/served")
			wantContains(t, "the notice", stderr, "notice: 1 module(s) that could answer",
				"example.com/held@v1.2.0")
		})
	}
	// A qualified name narrows to the module owning its package, so the
	// superseded module elsewhere does not bear on the answer.
	stdout, stderr, code := runSymbol(t, root, "symbol-context", "example.com/served.Served")
	if code != 0 || !strings.Contains(stdout, "example.com/served.Served") {
		t.Fatalf("exit = %d, stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stderr, "notice:") {
		t.Errorf("a module that does not own the package was reported unread:\n%s", stderr)
	}
}

func TestSymbolLookups_MixedStoreMissNamesTheUnreadModule(t *testing.T) {
	root := seedSymbolStore(t, heldModule, servedModule)
	for _, args := range [][]string{{"symbol-find", "Held"}, {"symbol-context", "Held"}} {
		stdout, stderr, code := runSymbol(t, root, args...)
		if code != ExitNotFound || stdout != "" {
			t.Errorf("%v: exit = %d, stdout %q; want 4 and empty", args, code, stdout)
		}
		wantContains(t, strings.Join(args, " "), stderr,
			"1 module(s) that could answer are held only at a superseded interface pipeline",
			"example.com/held@v1.2.0")
	}
	// The remedy is the coordinate when only one module went unread.
	_, stderr, _ := runSymbol(t, root, "symbol-context", "Held")
	wantContains(t, "symbol-context", stderr, "kanonarion interface example.com/held@v1.2.0")
}

func TestSymbolLookups_ServedStoreAnswersAsBefore(t *testing.T) {
	root := seedSymbolStore(t, servedModule)
	stdout, stderr, code := runSymbol(t, root, "symbol-find", "Served")
	if code != 0 || !strings.Contains(stdout, "example.com/served@v1.0.0") || stderr != "" {
		t.Errorf("symbol-find: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	// A name nothing served exports, with nothing unread, is a measured none.
	stdout, _, code = runSymbol(t, root, "symbol-context", "Absent")
	if code != 0 || !strings.Contains(stdout, `no exports found for symbol "Absent"`) {
		t.Errorf("symbol-context: exit %d, stdout %q", code, stdout)
	}
}

func TestSymbolLookups_EmptyInterfaceStoreIsNotFound(t *testing.T) {
	root := seedSymbolStore(t)
	for _, args := range [][]string{
		{"symbol-find", "X"}, {"symbol-find", "X", "--json"},
		{"symbol-context", "X"}, {"symbol-context", "X", "--json"},
	} {
		stdout, stderr, code := runSymbol(t, root, args...)
		if code != ExitNotFound || stdout != "" {
			t.Errorf("%v: exit = %d, stdout %q; want 4 and empty", args, code, stdout)
		}
		wantContains(t, strings.Join(args, " "), stderr, "the interface store is empty",
			"kanonarion local .")
	}
}

func TestSymbolContext_NamedModuleWithoutAServedRecordIsNotFound(t *testing.T) {
	root := seedSymbolStore(t, heldModule, servedModule)
	stdout, stderr, code := runSymbol(t, root, "symbol-context", "Held", "--module", "example.com/held@v1.2.0", "--json")
	if code != ExitNotFound || stdout != "" {
		t.Errorf("superseded module: exit = %d, stdout %q; want 4 and empty", code, stdout)
	}
	wantContains(t, "superseded module", stderr, "kanonarion interface example.com/held@v1.2.0")
	stdout, stderr, code = runSymbol(t, root, "symbol-context", "Held", "--module", "example.com/never@v1.0.0")
	if code != ExitNotFound || stdout != "" {
		t.Errorf("never-extracted module: exit = %d, stdout %q; want 4 and empty", code, stdout)
	}
	wantContains(t, "never-extracted module", stderr, "kanonarion interface example.com/never@v1.0.0")
}

func TestParseSymbolQuery(t *testing.T) {
	// A method's qualifier is the package and its receiver, and a package whose
	// path holds a dot still owns its module.
	q := parseSymbolQuery("gopkg.in/yaml.v3.Node.Decode")
	refs := q.keep([]ifaceports.SymbolRef{
		{PackagePath: "gopkg.in/yaml.v3", ParentType: "Node", SymbolName: "Decode"},
		{PackagePath: "gopkg.in/yaml.v3", ParentType: "Decoder", SymbolName: "Decode"},
	})
	if len(refs) != 1 || refs[0].ParentType != "Node" {
		t.Errorf("keep = %+v, want the Node method only", refs)
	}
	if !q.owns("gopkg.in/yaml.v3") || q.owns("gopkg.in/other") || !parseSymbolQuery("Bare").owns("any") {
		t.Error("owns does not follow the qualifier")
	}

	for _, tc := range []struct {
		arg  string
		want symbolQuery
	}{
		{"NewString", symbolQuery{name: "NewString"}},
		{"github.com/google/uuid.NewString", symbolQuery{qualifier: "github.com/google/uuid", name: "NewString"}},
		{"encoding/json.Decoder.Decode", symbolQuery{qualifier: "encoding/json.Decoder", name: "Decode"}},
		{"fmt.Println", symbolQuery{qualifier: "fmt", name: "Println"}},
		{"gopkg.in/yaml.v3.Marshal", symbolQuery{qualifier: "gopkg.in/yaml.v3", name: "Marshal"}},
		{"example.com/a.b/pkg", symbolQuery{name: "example.com/a.b/pkg"}},
		{".Name", symbolQuery{name: ".Name"}},
		{"pkg.", symbolQuery{name: "pkg."}},
	} {
		if got := parseSymbolQuery(tc.arg); got != tc.want {
			t.Errorf("parseSymbolQuery(%q) = %+v, want %+v", tc.arg, got, tc.want)
		}
	}
}

// A census over more modules than a line can name counts them instead, and the
// remedy falls back to the general form when several modules went unread.
func TestInterfaceCensus_ManyUnreadModulesAreCounted(t *testing.T) {
	var stored []ifaceports.InterfaceGeneration
	for i := range unreadModulesNamed + 1 {
		stored = append(stored, ifaceports.InterfaceGeneration{
			ModulePath: "example.com/m" + string(rune('a'+i)), ModuleVersion: "v1.0.0", PipelineVersion: supersededPipeline,
		})
	}
	stored = append(stored, ifaceports.InterfaceGeneration{
		ModulePath: "example.com/served", ModuleVersion: "v1.0.0", PipelineVersion: ifaceapp.PipelineVersion,
	}, ifaceports.InterfaceGeneration{ModulePath: "not a path", ModuleVersion: "", PipelineVersion: supersededPipeline})
	u := interfaceCensus(stored, coordinate.ModuleSet{}, symbolQuery{})
	line := u.statement()
	if !strings.Contains(line, "11 module(s) that could answer") || strings.Contains(line, "example.com/ma") {
		t.Errorf("statement = %q, want a count without names", line)
	}
	if got := u.coordinateRemedy(symbolQuery{}); got != u.generalRemedy() {
		t.Errorf("several unread modules must keep the general remedy, got %q", got)
	}
	var buf bytes.Buffer
	if err := (unreadInterfaceModules{}).writeNotice(&buf, "x"); err != nil || buf.Len() != 0 {
		t.Errorf("nothing unread must write nothing, got %q, %v", buf.String(), err)
	}
	if err := u.writeNotice(failingWriter{}, "x"); err == nil {
		t.Error("a failed notice write must be reported")
	}
}

// The census reads generation keys, never the composing summary listing: on a
// store of thousands of superseded records composing them took seconds.
func TestInterfaceCensus_ReadsKeysNotComposedSummaries(t *testing.T) {
	uc := testfakes.NewFakeQueryInterface()
	uc.SetList([]ifaceports.InterfaceSummary{{ModulePath: "example.com/held", ModuleVersion: "v1.0.0", PipelineVersion: supersededPipeline}})
	if _, err := readInterfaceCensus(context.Background(), uc, coordinate.ModuleSet{}, symbolQuery{}); err != nil {
		t.Fatal(err)
	}
	withJSON(t, false)
	if err := interfaceListWith(context.Background(), 50, 0, false, uc, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	// One composing read: the page itself.
	if len(uc.ListFilters) != 1 {
		t.Errorf("composing reads = %d (%+v), want only the page", len(uc.ListFilters), uc.ListFilters)
	}
	uc.Err = errStoreUnreadable
	if _, err := readInterfaceCensus(context.Background(), uc, coordinate.ModuleSet{}, symbolQuery{}); err == nil {
		t.Error("a census that cannot be read must be reported")
	}
}

// Every qualified form a reader meets resolves: the full import path, the
// package name a Go caller writes (less a major-version element), the
// receiver alone as the name column prints it, and the package name with the
// receiver.
func TestSymbolLookups_QualifiedFormsResolve(t *testing.T) {
	root := seedSymbolStore(t, uuidModule, errorsModule)
	for _, tc := range []struct{ arg, want string }{
		{"errors.Wrap", "example.com/pkg/errors/v2"},
		{"example.com/pkg/errors/v2.Wrap", "example.com/pkg/errors/v2"},
		{"uuid.NewString", "example.com/google/uuid"},
		{"UUID.String", "example.com/google/uuid"},
		{"uuid.UUID.String", "example.com/google/uuid"},
		{"example.com/google/uuid.UUID.String", "example.com/google/uuid"},
	} {
		for _, cmd := range []string{"symbol-find", "symbol-context"} {
			stdout, stderr, code := runSymbol(t, root, cmd, tc.arg)
			if code != 0 || !strings.Contains(stdout, tc.want) || strings.Contains(stdout, "no exports found") {
				t.Errorf("%s %s: exit %d, stdout %q, stderr %q", cmd, tc.arg, code, stdout, stderr)
			}
		}
	}
}

// A short qualifier several packages answer to lists them all, as a bare name
// does.
func TestSymbolLookups_ShortQualifierListsEveryPackageItNames(t *testing.T) {
	root := seedSymbolStore(t, errorsModule, otherErrors)
	for _, cmd := range []string{"symbol-find", "symbol-context"} {
		stdout, _, code := runSymbol(t, root, cmd, "errors.Wrap")
		if code != 0 || !strings.Contains(stdout, "example.com/pkg/errors/v2") || !strings.Contains(stdout, "example.com/other/errors") {
			t.Errorf("%s: exit %d, stdout %q", cmd, code, stdout)
		}
	}
}

// A qualifier that names none of the packages exporting the bare name is a
// miss, but not a definitive one: stderr names who does export it.
func TestSymbolLookups_QualifiedMissNamesWhoExportsTheName(t *testing.T) {
	root := seedSymbolStore(t, errorsModule)
	for _, args := range [][]string{{"symbol-find", "foo.Wrap"}, {"symbol-context", "foo.Wrap"}, {"symbol-context", "foo.Wrap", "--json"}} {
		stdout, stderr, code := runSymbol(t, root, args...)
		if code != 0 || strings.Contains(stdout, "example.com/pkg/errors/v2") {
			t.Errorf("%v: exit %d, stdout %q", args, code, stdout)
		}
		wantContains(t, strings.Join(args, " "), stderr,
			`"Wrap" is exported by example.com/pkg/errors/v2, which the qualifier "foo" did not match`)
	}
	// A bare miss, and a qualified miss of a name nothing exports, add nothing.
	for _, arg := range []string{"Absent", "foo.Absent"} {
		_, stderr, _ := runSymbol(t, root, "symbol-find", arg)
		if strings.Contains(stderr, "notice:") {
			t.Errorf("%s: unexpected notice %q", arg, stderr)
		}
	}
}

// The superseded census applies the same qualifier rule: the module whose
// package name the qualifier writes is one that could answer.
func TestSymbolLookups_ShortQualifierOverASupersededModuleIsNotFound(t *testing.T) {
	held := errorsModule
	held.pipeline = supersededPipeline
	root := seedSymbolStore(t, held, uuidModule)
	for _, cmd := range []string{"symbol-find", "symbol-context"} {
		stdout, stderr, code := runSymbol(t, root, cmd, "errors.Wrap")
		if code != ExitNotFound || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q; want 4 and empty", cmd, code, stdout)
		}
		wantContains(t, cmd, stderr, "example.com/pkg/errors/v2@v2.0.0")
		// A package name could name a subpackage of the superseded module too,
		// so the answer says it did not read it.
		stdout, stderr, code = runSymbol(t, root, cmd, "uuid.NewString")
		if code != 0 || !strings.Contains(stdout, "example.com/google/uuid") {
			t.Errorf("%s uuid.NewString: exit %d, stdout %q", cmd, code, stdout)
		}
		wantContains(t, cmd+" uuid.NewString", stderr, "notice: 1 module(s) that could answer", "example.com/pkg/errors/v2@v2.0.0")
		// An import-path qualifier stays exact.
		_, stderr, _ = runSymbol(t, root, cmd, "example.com/google/uuid.NewString")
		if strings.Contains(stderr, "notice:") {
			t.Errorf("%s: an import-path qualifier counted a module outside it: %q", cmd, stderr)
		}
	}
}

// A package name can name a subpackage whose name the module's own path does
// not carry, so a superseded module is unread whatever its path ends in.
func TestSymbolLookups_ShortQualifierCountsASupersededSubpackage(t *testing.T) {
	root := seedSymbolStore(t, symbolStoreModule{
		path: "github.com/x/y", version: "v1.0.0", pipeline: supersededPipeline, fn: "Foo", pkg: "github.com/x/y/errors",
	}, uuidModule)
	for _, cmd := range []string{"symbol-find", "symbol-context"} {
		stdout, stderr, code := runSymbol(t, root, cmd, "errors.Foo")
		if code != ExitNotFound || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q; want 4 and empty", cmd, code, stdout)
		}
		wantContains(t, cmd, stderr, "github.com/x/y@v1.0.0")
	}
}

func TestPackageNameAndOwns(t *testing.T) {
	for path, want := range map[string]string{
		"github.com/pkg/errors": "errors", "example.com/mod/v2": "mod", "gopkg.in/yaml.v3": "yaml",
		"v2": "v2", "example.com/x.y": "x.y", "example.com/vx": "vx",
	} {
		if got := packageName(path); got != want {
			t.Errorf("packageName(%q) = %q, want %q", path, got, want)
		}
	}
	for _, tc := range []struct {
		arg, module string
		want        bool
	}{
		{"errors.Wrap", "github.com/pkg/errors", true},
		{"errors.Wrap", "github.com/google/uuid", true},
		{"UUID.String", "github.com/any/module", true},
		{"uuid.UUID.String", "github.com/google/uuid", true},
		{"github.com/google/uuid/sub.F", "github.com/google/uuid", true},
		{"github.com/google/uuid.F", "github.com/pkg/errors", false},
		{"Bare", "anything", true},
	} {
		if got := parseSymbolQuery(tc.arg).owns(tc.module); got != tc.want {
			t.Errorf("owns(%q, %q) = %v, want %v", tc.arg, tc.module, got, tc.want)
		}
	}
	var buf bytes.Buffer
	if err := parseSymbolQuery("foo.Wrap").writeExcluded(failingWriter{}, []ifaceports.SymbolRef{{PackagePath: "a"}}); err == nil {
		t.Error("a failed notice write must be reported")
	}
	refs := []ifaceports.SymbolRef{{PackagePath: "c"}, {PackagePath: "a"}, {PackagePath: "b"}, {PackagePath: "a"}}
	if err := parseSymbolQuery("foo.Wrap").writeExcluded(&buf, refs); err != nil ||
		!strings.Contains(buf.String(), "exported by a, b and 1 other package(s)") {
		t.Errorf("notice = %q, %v", buf.String(), err)
	}
}
