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
