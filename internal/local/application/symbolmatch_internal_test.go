package application

import "testing"

// TestFindInBinary_ReceiverForms pins the matching contract between the
// advisory's symbol spelling and the symbol table's: OSV writes methods as
// "Type.Method"; nm mangles a pointer receiver as "(*Type).Method". A finding
// must not read absent because of the receiver's spelling.
func TestFindInBinary_ReceiverForms(t *testing.T) {
	const mod = "example.com/lib"
	table := map[string]struct{}{
		"example.com/lib.(*Parser).ParseUnverified": {},
		"example.com/lib.Keyfunc.Verify":            {},
		"example.com/lib.ParseAcceptLanguage":       {},
		"example.com/lib.(*Broken":                  {},
	}

	cases := []struct {
		name   string
		affSym string
		want   string
	}{
		{"pointer-receiver method matches the OSV spelling", "Parser.ParseUnverified", "example.com/lib.(*Parser).ParseUnverified"},
		{"pointer-receiver method matches the stored star spelling", "*Parser.ParseUnverified", "example.com/lib.(*Parser).ParseUnverified"},
		{"value-receiver method matches unchanged", "Keyfunc.Verify", "example.com/lib.Keyfunc.Verify"},
		{"package-level function matches unchanged", "ParseAcceptLanguage", "example.com/lib.ParseAcceptLanguage"},
		{"absent method stays absent", "Parser.Parse", ""},
		{"a malformed receiver spelling never matches by accident", "Broken", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := findInBinary(tc.affSym, mod, table); got != tc.want {
				t.Errorf("findInBinary(%q) = %q, want %q", tc.affSym, got, tc.want)
			}
		})
	}
}

// TestNormalizeReceiver pins the normalisation's edges across the three
// spellings in play (nm "(*T).M", stored "*T.M", OSV "T.M"): only a complete
// receiver spelling is rewritten; anything else passes through untouched.
func TestNormalizeReceiver(t *testing.T) {
	cases := map[string]string{
		"(*Parser).ParseUnverified": "Parser.ParseUnverified",
		"*Parser.ParseUnverified":   "Parser.ParseUnverified",
		"Parser.ParseUnverified":    "Parser.ParseUnverified",
		"ParseAcceptLanguage":       "ParseAcceptLanguage",
		"(*Broken":                  "(*Broken",
		"(*A).B.C":                  "A.B.C",
		"*noDotAfterStar":           "*noDotAfterStar",
	}
	for in, want := range cases {
		if got := normalizeReceiver(in); got != want {
			t.Errorf("normalizeReceiver(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFindInBinary_GenericAndInitForms pins the nm spellings a plain name
// comparison missed: a generic instantiation carries its type arguments, and a
// package whose only initialiser is func init() links as init.0.
func TestFindInBinary_GenericAndInitForms(t *testing.T) {
	cases := []struct {
		name   string
		mod    string
		affSym string
		table  string
	}{
		{"generic function", "example.com/gen", "Max", "example.com/gen/lib.Max[go.shape.int]"},
		{"generic method, pointer receiver", "example.com/gen", "Box.Get", "example.com/gen/lib.(*Box[go.shape.string]).Get"},
		{"generic method, value receiver", "example.com/gen", "Box.Peek", "example.com/gen/lib.Box[go.shape.string].Peek"},
		{"nested type arguments holding paths", "example.com/gen", "Pair.Left",
			"example.com/gen/lib.(*Pair[go.shape.struct { example.com/gen/lib.V []example.com/gen/lib.Box[go.shape.int] },go.shape.string]).Left"},
		{"init against init.0", "example.com/i", "init", "example.com/i/a.init.0"},
		{"init against init", "example.com/i", "init", "example.com/i/b.init"},
		{"non-generic control", "example.com/gen", "Plain", "example.com/gen/lib.Plain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := findInBinary(tc.affSym, tc.mod, map[string]struct{}{tc.table: {}}); got != tc.table {
				t.Errorf("findInBinary(%q) = %q, want %q", tc.affSym, got, tc.table)
			}
		})
	}
}

// TestFindInBinary_InitMatchesOnlyInitialisers keeps "init" from reaching a
// closure or a declaration that merely starts with the word.
func TestFindInBinary_InitMatchesOnlyInitialisers(t *testing.T) {
	for _, sym := range []string{"example.com/i/a.init.0.func1", "example.com/i/a.initialise", "example.com/i/a.init."} {
		if got := findInBinary("init", "example.com/i", map[string]struct{}{sym: {}}); got != "" {
			t.Errorf("init matched %q", got)
		}
	}
}
