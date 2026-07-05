package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/example/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestExampleStatusString(t *testing.T) {
	cases := []struct {
		status domain.ExampleStatus
		want   string
	}{
		{domain.ExampleStatusFound, "Found"},
		{domain.ExampleStatusNone, "None"},
		{domain.ExampleStatusExtractionFailed, "ExtractionFailed"},
		{domain.ExampleStatusCancelled, "Cancelled"},
		{domain.ExampleStatusUnknown, "Unknown"},
		{domain.ExampleStatus(99), "Unknown"},
	}
	for _, tc := range cases {
		if got := tc.status.String(); got != tc.want {
			t.Errorf("ExampleStatus(%d).String() = %q; want %q", int(tc.status), got, tc.want)
		}
	}
}

func TestSortExamples(t *testing.T) {
	coord := mustCoord(t, "example.com/m", "v1.0.0")
	r := domain.ExampleRecord{
		Coordinate: coord,
		Examples: []domain.ExampleEntry{
			{Package: "b", AssociatedSymbol: "A", Name: "ExampleA"},
			{Package: "a", AssociatedSymbol: "Z", Name: "ExampleZ"},
			{Package: "a", AssociatedSymbol: "A", Name: "ExampleA_second"},
			{Package: "a", AssociatedSymbol: "A", Name: "ExampleA"},
		},
		ParseFailures: []domain.ParseFailure{
			{File: "z_test.go"},
			{File: "a_test.go"},
		},
	}
	r.SortExamples()

	order := []string{
		r.Examples[0].Package + "/" + r.Examples[0].Name,
		r.Examples[1].Package + "/" + r.Examples[1].Name,
		r.Examples[2].Package + "/" + r.Examples[2].Name,
		r.Examples[3].Package + "/" + r.Examples[3].Name,
	}
	want := []string{"a/ExampleA", "a/ExampleA_second", "a/ExampleZ", "b/ExampleA"}
	for i, w := range want {
		if order[i] != w {
			t.Errorf("SortExamples[%d] = %q; want %q", i, order[i], w)
		}
	}

	if r.ParseFailures[0].File != "a_test.go" {
		t.Errorf("ParseFailures not sorted: first = %q", r.ParseFailures[0].File)
	}
}

func TestDeriveAssociatedSymbol(t *testing.T) {
	cases := []struct {
		funcName   string
		wantSymbol string
		wantSub    string
	}{
		{"ExampleFoo", "Foo", ""},
		{"ExampleClient_Do", "Client.Do", ""},
		{"ExampleClient_Do_advanced", "Client.Do", "advanced"},
		{"ExampleFoo_bar", "Foo", "bar"},
		{"ExampleFoo_bar_baz", "Foo", "bar_baz"},
		{"ExampleFoo_Bar_baz", "Foo.Bar", "baz"},
		{"Example", "Example", ""},           // degenerate: no suffix
		{"NotAnExample", "NotAnExample", ""}, // no "Example" prefix
		{"Example__Foo", "Foo", ""},          // consecutive underscores — empty parts skipped
	}
	for _, tc := range cases {
		sym, sub := domain.DeriveAssociatedSymbol(tc.funcName)
		if sym != tc.wantSymbol || sub != tc.wantSub {
			t.Errorf("DeriveAssociatedSymbol(%q) = (%q, %q); want (%q, %q)",
				tc.funcName, sym, sub, tc.wantSymbol, tc.wantSub)
		}
	}
}

func mustCoord(t *testing.T, path, version string) fetchdomain.ModuleCoordinate {
	t.Helper()
	c, err := fetchdomain.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}
