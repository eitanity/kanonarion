package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
)

// renderRecord renders a record the way interface-show does.
func renderRecord(t *testing.T, r ifacedomain.InterfaceRecord) string {
	t.Helper()
	var buf bytes.Buffer
	if err := printRecordText(r, newPromotionIndex(r), &buf); err != nil {
		t.Fatalf("printRecordText: %v", err)
	}
	return buf.String()
}

// embeddingRecord is one package whose types exercise every promotion rule:
// a method declared on the embedded type, a method the embedder redeclares,
// a name two embeddings offer at the same depth, a promotion two levels down,
// and an embedding of a type this record does not describe.
func embeddingRecord() ifacedomain.InterfaceRecord {
	base := ifacedomain.TypeDecl{
		Name: "Base", Kind: ifacedomain.TypeKindStruct,
		Fields:  []ifacedomain.FieldDecl{{Name: "BaseField", Type: "int"}},
		Methods: []ifacedomain.MethodDecl{{Name: "Alg", Signature: "func (b *Base) Alg() string"}},
	}
	middle := ifacedomain.TypeDecl{
		Name: "Middle", Kind: ifacedomain.TypeKindStruct,
		Fields: []ifacedomain.FieldDecl{{Name: "*Base", Type: "*Base", Embedded: true}},
	}
	deep := ifacedomain.TypeDecl{
		Name: "Deep", Kind: ifacedomain.TypeKindStruct,
		Fields: []ifacedomain.FieldDecl{{Name: "Middle", Type: "Middle", Embedded: true}},
	}
	shadow := ifacedomain.TypeDecl{
		Name: "Shadow", Kind: ifacedomain.TypeKindStruct,
		Fields:  []ifacedomain.FieldDecl{{Name: "*Base", Type: "*Base", Embedded: true}},
		Methods: []ifacedomain.MethodDecl{{Name: "Alg", Signature: "func (s *Shadow) Alg() string"}},
	}
	other := ifacedomain.TypeDecl{
		Name: "Other", Kind: ifacedomain.TypeKindStruct,
		Methods: []ifacedomain.MethodDecl{{Name: "Alg", Signature: "func (o *Other) Alg() string"}},
	}
	ambiguous := ifacedomain.TypeDecl{
		Name: "Ambiguous", Kind: ifacedomain.TypeKindStruct,
		Fields: []ifacedomain.FieldDecl{
			{Name: "*Base", Type: "*Base", Embedded: true},
			{Name: "Other", Type: "Other", Embedded: true},
		},
	}
	foreign := ifacedomain.TypeDecl{
		Name: "Foreign", Kind: ifacedomain.TypeKindStruct,
		Fields: []ifacedomain.FieldDecl{{Name: "bytes.Buffer", Type: "bytes.Buffer", Embedded: true}},
	}
	return ifacedomain.InterfaceRecord{
		Packages: []ifacedomain.PackageInterface{{
			Name: "mypkg", ImportPath: "example.com/iface/mypkg",
			Types: []ifacedomain.TypeDecl{ambiguous, base, deep, foreign, middle, other, shadow},
		}},
	}
}

// TestPrintRecordText_StructFields: the type line is not the whole of what a
// type prints. Every field the record holds is named, with its type and tag.
func TestPrintRecordText_StructFields(t *testing.T) {
	r := ifacedomain.InterfaceRecord{
		Packages: []ifacedomain.PackageInterface{{
			Name: "mypkg", ImportPath: "example.com/iface/mypkg",
			Types: []ifacedomain.TypeDecl{{
				Name: "Token", Kind: ifacedomain.TypeKindStruct,
				Fields: []ifacedomain.FieldDecl{
					{Name: "Raw", Type: "string", Tag: "`json:\"raw\"`"},
					{Name: "Valid", Type: "bool"},
				},
				Methods: []ifacedomain.MethodDecl{
					{Name: "SigningString", Signature: "func (t *Token) SigningString() (string, error)"},
				},
			}},
		}},
	}

	out := renderRecord(t, r)
	for _, want := range []string{
		"field Raw string `json:\"raw\"`",
		"field Valid bool",
		"func (t *Token) SigningString() (string, error)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "func func") {
		t.Errorf("method line doubles the func keyword:\n%s", out)
	}
}

// TestPrintRecordText_PromotedMethods: a method callable on a type only
// because of an embedding is shown, marked as promoted and naming the
// embedding it arrives through — never merged into the declared set.
func TestPrintRecordText_PromotedMethods(t *testing.T) {
	out := renderRecord(t, embeddingRecord())
	lines := strings.Split(out, "\n")

	find := func(typeName string) []string {
		var block []string
		in := false
		for _, l := range lines {
			switch {
			case strings.HasPrefix(l, "  type "+typeName+" "):
				in = true
			case strings.HasPrefix(l, "  type "):
				in = false
			case in:
				block = append(block, l)
			}
		}
		return block
	}

	middle := strings.Join(find("Middle"), "\n")
	if !strings.Contains(middle, "promoted func (b *Base) Alg() string  // via *Base") {
		t.Errorf("Middle does not report Alg as promoted:\n%s", middle)
	}
	if !strings.Contains(middle, "promoted field BaseField int  // via *Base") {
		t.Errorf("Middle does not report BaseField as promoted:\n%s", middle)
	}
	if !strings.Contains(middle, "embeds *Base") {
		t.Errorf("Middle does not name its embedding:\n%s", middle)
	}

	deep := strings.Join(find("Deep"), "\n")
	if !strings.Contains(deep, "// via Middle -> *Base") {
		t.Errorf("Deep does not name the two-step embedding chain:\n%s", deep)
	}

	shadow := strings.Join(find("Shadow"), "\n")
	if strings.Contains(shadow, "promoted func (b *Base) Alg") {
		t.Errorf("Shadow redeclares Alg, so nothing is promoted for that name:\n%s", shadow)
	}
	if !strings.Contains(shadow, "func (s *Shadow) Alg() string") {
		t.Errorf("Shadow's own Alg is missing:\n%s", shadow)
	}

	ambiguous := strings.Join(find("Ambiguous"), "\n")
	if strings.Contains(ambiguous, "promoted func") && strings.Contains(ambiguous, "Alg") {
		t.Errorf("Alg is offered by two embeddings at one depth, so Go promotes neither:\n%s", ambiguous)
	}

	foreign := strings.Join(find("Foreign"), "\n")
	if !strings.Contains(foreign, "[promotions from bytes.Buffer not shown") {
		t.Errorf("an embedding this record cannot resolve must be named, not dropped:\n%s", foreign)
	}
}

// TestPrintRecordText_PromotionSurvivesSymbolFilter: --symbol narrows what is
// printed, not what a printed type is said to offer. The embedded type is
// filtered out of the record; the promotion it explains still resolves.
func TestPrintRecordText_PromotionSurvivesSymbolFilter(t *testing.T) {
	r := embeddingRecord()
	idx := newPromotionIndex(r)
	filtered := filterRecord(r, "", "Middle")

	var buf bytes.Buffer
	if err := printRecordText(filtered, idx, &buf); err != nil {
		t.Fatalf("printRecordText: %v", err)
	}
	if !strings.Contains(buf.String(), "promoted func (b *Base) Alg() string") {
		t.Errorf("promotion lost when the embedded type is filtered out:\n%s", buf.String())
	}
}

// TestPrintRecordText_UndeclaredConstTypeIsStated: a value the record holds no
// type for says so, rather than printing a blank column a reader cannot tell
// from a truncated line.
func TestPrintRecordText_UndeclaredConstTypeIsStated(t *testing.T) {
	r := ifacedomain.InterfaceRecord{
		Packages: []ifacedomain.PackageInterface{{
			Name: "mypkg", ImportPath: "example.com/iface/mypkg",
			Consts: []ifacedomain.ValueDecl{{Name: "Typed", Type: "uint32"}, {Name: "Bare"}},
		}},
	}
	out := renderRecord(t, r)
	if !strings.Contains(out, "const Typed uint32") {
		t.Errorf("typed const missing its type:\n%s", out)
	}
	if !strings.Contains(out, "const Bare (no declared type)") {
		t.Errorf("untyped const does not state that it has no declared type:\n%s", out)
	}
}

// TestPrintRecordText_AgreesWithJSONSymbolSet: the two renderings of one record
// answer the same question, so every declaration the JSON carries for a
// struct-bearing package is named in the text.
func TestPrintRecordText_AgreesWithJSONSymbolSet(t *testing.T) {
	r := embeddingRecord()
	r.Packages[0].Funcs = []ifacedomain.FuncDecl{{Name: "New", Signature: "func New() *Base"}}
	r.Packages[0].Consts = []ifacedomain.ValueDecl{{Name: "MaxSize", Type: "int"}}
	r.Packages[0].Vars = []ifacedomain.ValueDecl{{Name: "Default", Type: "*Base"}}

	out := renderRecord(t, r)

	raw, err := json.Marshal(toInterfaceRecordJSON(r))
	if err != nil {
		t.Fatalf("marshalling record: %v", err)
	}
	var doc struct {
		Packages []struct {
			Types []struct {
				Name    string                  `json:"name"`
				Fields  []struct{ Name string } `json:"fields"`
				Methods []struct{ Name string } `json:"methods"`
			} `json:"types"`
			Funcs  []struct{ Name string } `json:"funcs"`
			Consts []struct{ Name string } `json:"consts"`
			Vars   []struct{ Name string } `json:"vars"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshalling record: %v", err)
	}

	var want []string
	for _, p := range doc.Packages {
		for _, ty := range p.Types {
			want = append(want, ty.Name)
			for _, f := range ty.Fields {
				want = append(want, f.Name)
			}
			for _, m := range ty.Methods {
				want = append(want, m.Name)
			}
		}
		for _, f := range p.Funcs {
			want = append(want, f.Name)
		}
		for _, c := range p.Consts {
			want = append(want, c.Name)
		}
		for _, v := range p.Vars {
			want = append(want, v.Name)
		}
	}
	if len(want) == 0 {
		t.Fatal("no symbols read out of the JSON rendering")
	}
	for _, name := range want {
		if !strings.Contains(out, name) {
			t.Errorf("JSON carries %q, text output does not name it:\n%s", name, out)
		}
	}
}

// TestBuildInterface_CarriesMethods: the context section lists a type by its
// signature, which for a struct names its fields and no method at all. Without
// the methods the section describes a package as having none, and the symbol
// count printed beside it agrees with that.
func TestBuildInterface_CarriesMethods(t *testing.T) {
	coord := makeIfaceCoord(t)
	uc := testfakes.NewFakeQueryInterface()
	uc.AddRecord(coord, ifaceapp.PipelineVersion, ifacedomain.InterfaceRecord{
		Coordinate:    coord,
		OverallStatus: ifacedomain.InterfaceStatusExtracted,
		Packages: []ifacedomain.PackageInterface{{
			Name: "mypkg", ImportPath: "example.com/iface/mypkg",
			Types: []ifacedomain.TypeDecl{{
				Name: "Token", Kind: ifacedomain.TypeKindStruct,
				Signature: "type Token struct { Raw string }",
				Methods: []ifacedomain.MethodDecl{
					{Name: "SigningString", Signature: "func (t *Token) SigningString() (string, error)"},
				},
			}},
		}},
	})

	out := buildInterface(context.Background(), coord, uc, true, "")
	if len(out.Packages) != 1 {
		t.Fatalf("len(Packages) = %d, want 1", len(out.Packages))
	}
	got := out.Packages[0].Methods
	if len(got) != 1 || !strings.Contains(got[0], "SigningString") {
		t.Errorf("context section drops the methods the record holds: %+v", got)
	}
}
