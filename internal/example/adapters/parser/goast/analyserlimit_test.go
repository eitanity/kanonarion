package goast

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// unreadable stands in for a test file with a generic method, which a go1.26
// parser refuses; the suite runs on one toolchain, so it uses a file no parser
// reads under a directive newer than the Go the seam reports.
const unreadableTest = "package m_test\n\nfunc ExampleLost() {\n\tprintln(1)\n"

func limitZip(t *testing.T, prefix, directive string) []byte {
	t.Helper()
	return buildZip(t, prefix, map[string]string{
		"go.mod":            "module example.com/m\n\ngo " + directive + "\n",
		"genmeth_test.go":   unreadableTest,
		"ok/ok_test.go":     "package ok_test\n\nfunc ExampleOk() {\n\tprintln(1)\n\t// Output: 1\n}\n",
		"ok/broken_test.go": unreadableTest,
	})
}

// Under a go directive newer than this binary's Go, a refused _test.go file is
// unread, not failed: its examples were never looked at, and the files that
// did parse still yield theirs.
func TestParse_AnalyserLimitIsNotAParseFailure(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.26.6")
	defer restore()
	prefix := "example.com/m@v1.0.0/"

	res, err := Parser{}.Parse(limitZip(t, prefix, "1.27.2"), prefix)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Failures) != 0 {
		t.Errorf("failures = %v: the module was not judged", res.Failures)
	}
	if res.Unread == nil {
		t.Fatal("no unread files reported")
	}
	if res.Unread.Limit != (gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}) ||
		strings.Join(res.Unread.Files, ",") != "genmeth_test.go,ok/broken_test.go" {
		t.Errorf("unread = %+v", *res.Unread)
	}
	if len(res.Examples) != 1 || res.Examples[0].Name != "ExampleOk" {
		t.Errorf("examples = %+v, want ExampleOk from the file that parsed", res.Examples)
	}
}

// The control: under a directive this binary covers, the same files are the
// module's parse failures and nothing is unread.
func TestParse_RefusalUnderACoveredDirectiveIsAFailure(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.26.6")
	defer restore()
	prefix := "example.com/m@v1.0.0/"

	res, err := Parser{}.Parse(limitZip(t, prefix, "1.25"), prefix)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Unread != nil || len(res.Failures) != 2 {
		t.Errorf("unread %v, failures %v; want two failures and nothing unread", res.Unread, res.Failures)
	}
	// The failure text is what it always was: nothing the classification adds.
	for _, f := range res.Failures {
		if !strings.HasPrefix(f.Error, "parsing "+f.File+": "+f.File+":") {
			t.Errorf("failure text changed: %q", f.Error)
		}
	}
}
