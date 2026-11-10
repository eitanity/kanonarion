package staticcha_test

import (
	"context"
	"log/slog"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
)

var lookupCoord = coordinatetest.MustNew("example.com/lookupmod", "v1.0.0")

// lookupModuleFiles holds each lookup kind with a constant name, a computed
// name and no name, and two lookups on one line that name different methods.
var lookupModuleFiles = map[string]string{
	"go.mod": "module example.com/lookupmod\n\ngo 1.21\n",
	"lookup.go": `package lookupmod

import (
	"reflect"
	"strings"
)

type D struct{}

func (D) Run() {}

func ValueConst() { reflect.ValueOf(D{}).MethodByName("Run") }

func TypeConst() { reflect.TypeOf(D{}).MethodByName("Run") }

func ValueComputed(s string) { reflect.ValueOf(D{}).MethodByName(strings.TrimSpace(s)) }

func TypeComputed(s string) { reflect.TypeOf(D{}).MethodByName(s + "x") }

func ByIndex() { reflect.ValueOf(D{}).Method(0); reflect.TypeOf(D{}).Method(0) }

func TwoOnOneLine() { v := reflect.ValueOf(D{}); v.MethodByName("Run"); v.MethodByName("Stop") }

func SameTwice() { v := reflect.ValueOf(D{}); v.MethodByName("Run"); v.MethodByName("Run") }
`,
}

// TestAnalyse_RecordsTheConstantNameOfAMethodByNameLookup is the extraction half
// of binding a lookup to the methods of its name: a constant argument is
// recorded on the edge, a computed one and every other callee record nothing,
// and two lookups sharing an edge record nothing unless they agree.
func TestAnalyse_RecordsTheConstantNameOfAMethodByNameLookup(t *testing.T) {
	t.Parallel()

	a := staticcha.New("0.1.0", "", slog.Default())
	zipPath := writeZipToTemp(t, makeZip(t, lookupCoord, lookupModuleFiles))
	rec, err := a.Analyse(context.Background(), zipPath, lookupCoord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("OverallStatus = %v (%s), want Extracted", rec.OverallStatus, rec.FailureDetail)
	}

	const (
		valueLookup = "reflect.(Value).MethodByName"
		typeLookup  = "reflect.(*rtype).MethodByName"
	)
	want := []struct {
		from, to, name string
	}{
		{"example.com/lookupmod.ValueConst", valueLookup, "Run"},
		{"example.com/lookupmod.TypeConst", typeLookup, "Run"},
		{"example.com/lookupmod.ValueComputed", valueLookup, ""},
		{"example.com/lookupmod.TypeComputed", typeLookup, ""},
		{"example.com/lookupmod.ByIndex", "reflect.(Value).Method", ""},
		{"example.com/lookupmod.ByIndex", "reflect.(*rtype).Method", ""},
		{"example.com/lookupmod.TwoOnOneLine", valueLookup, ""},
		{"example.com/lookupmod.SameTwice", valueLookup, "Run"},
	}
	for _, w := range want {
		found := false
		for _, e := range rec.Edges {
			if e.FromID != w.from || e.ToID != w.to {
				continue
			}
			found = true
			if e.LookupName != w.name {
				t.Errorf("%s -> %s at %s:%d records lookup name %q, want %q",
					e.FromID, e.ToID, e.CallSite.File, e.CallSite.Line, e.LookupName, w.name)
			}
		}
		if !found {
			t.Errorf("no edge %s -> %s", w.from, w.to)
		}
	}
	for _, e := range rec.Edges {
		if e.LookupName != "" && e.ToID != valueLookup && e.ToID != typeLookup {
			t.Errorf("%s -> %s records lookup name %q; only a MethodByName edge may", e.FromID, e.ToID, e.LookupName)
		}
	}
}

// analyseTemplateModule analyses a one-file module holding src and returns the
// lookup name its template Execute edges record.
func analyseTemplateModule(t *testing.T, name, src string) []string {
	t.Helper()
	coord := coordinatetest.MustNew("example.com/"+name, "v1.0.0")
	files := map[string]string{
		"go.mod":  "module example.com/" + name + "\n\ngo 1.21\n",
		"tmpl.go": "package " + name + "\n\n" + src,
	}
	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("OverallStatus = %v (%s), want Extracted", rec.OverallStatus, rec.FailureDetail)
	}
	var names []string
	for _, e := range rec.Edges {
		if e.ToID == "text/template.(*Template).Execute" || e.ToID == "html/template.(*Template).ExecuteTemplate" {
			names = append(names, e.LookupName)
		}
	}
	if len(names) == 0 {
		t.Fatal("no template Execute edge was recorded")
	}
	return names
}

// TestAnalyse_RecordsTheNamesAModulesConstantTemplatesUse: every Execute edge
// carries the field and method names of every constant text its module parses,
// read from chains, variables, pipelines, branches and defined templates.
// A module that parses text it cannot read records no name set, and one whose
// constant texts name nothing records the explicit empty set.
func TestAnalyse_RecordsTheNamesAModulesConstantTemplatesUse(t *testing.T) {
	t.Parallel()

	const execute = `
func Render(w io.Writer, v any) error {
	return template.Must(template.New("a").Parse(text)).Execute(w, v)
}
`
	for _, tt := range []struct {
		name, src, want string
	}{
		{name: "tmplall", want: "Count,Each,Inner,Items,Lang,Name,Run,Title", src: `import (
	"io"
	"text/template"
)

const text = "{{define \"row\"}}{{.Title}}{{end}}{{.Name}}{{$x := .Lang}}{{$x.Run}}{{range .Items}}{{.Each}}{{end}}{{with .Inner}}{{if .Count}}{{template \"row\" .}}{{end}}{{end}}{{len .Name | printf \"%d\"}}{{myfn .Run}}{{(.Inner).Count}}{{template \"row\"}}"
` + execute},
		{name: "tmplnone", want: domain.TemplateNamesNone, src: `import (
	"io"
	"text/template"
)

const text = "hello"
` + execute},
		{name: "tmplfiles", want: "", src: `import (
	"io"
	"text/template"
)

const text = "{{.Name}}"

func Load() { template.Must(template.ParseFiles("x.tmpl")) }
` + execute},
		{name: "tmplcomputed", want: "", src: `import (
	"io"
	"os"
	"text/template"
)

var text = os.Getenv("T")
` + execute},
		{name: "tmpldelims", want: "", src: `import (
	"io"
	"text/template"
)

const text = "[[.Name]]"

func Render(w io.Writer, v any) error {
	return template.Must(template.New("a").Delims("[[", "]]").Parse(text)).Execute(w, v)
}
`},
		{name: "tmplbad", want: "", src: `import (
	"io"
	"text/template"
)

const text = "{{.Name"

func Render(w io.Writer, v any) error {
	t, _ := template.New("a").Parse(text)
	return t.Execute(w, v)
}
`},
		{name: "tmplforeign", want: "", src: `import (
	"io"
	"text/template"
)

func Render(t *template.Template, w io.Writer, v any) error { return t.Execute(w, v) }
`},
		{name: "tmplhtml", want: "Name", src: `import (
	"html/template"
	"io"
)

func Render(w io.Writer, v any) error {
	return template.Must(template.New("a").Parse("{{.Name}}")).ExecuteTemplate(w, "a", v)
}
`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, got := range analyseTemplateModule(t, tt.name, tt.src) {
				if got != tt.want {
					t.Errorf("the Execute edge records lookup name %q, want %q", got, tt.want)
				}
			}
		})
	}
}
