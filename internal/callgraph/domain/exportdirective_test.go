package domain_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func TestParseExportDirective(t *testing.T) {
	tests := []struct {
		comment     string
		want        domain.ExportDirective
		wantMatched bool
		wantErr     bool
	}{
		{comment: "//go:wasmexport parse", want: domain.ExportDirective{Kind: domain.ExportWasm, Name: "parse"}, wantMatched: true},
		{comment: "//export goParse", want: domain.ExportDirective{Kind: domain.ExportC, Name: "goParse"}, wantMatched: true},
		// TinyGo treats //go:export as //export, so it is recorded as one.
		{comment: "//go:export goParse", want: domain.ExportDirective{Kind: domain.ExportC, Name: "goParse"}, wantMatched: true},
		// TinyGo ignores an interrupt's arguments.
		{comment: "//go:interrupt", want: domain.ExportDirective{Kind: domain.ExportInterrupt}, wantMatched: true},
		{comment: "//go:interrupt INT0", want: domain.ExportDirective{Kind: domain.ExportInterrupt}, wantMatched: true},

		{comment: "//export", wantMatched: true, wantErr: true},
		{comment: "//go:wasmexport a b", wantMatched: true, wantErr: true},

		{comment: ""},
		{comment: "// export goParse"},
		{comment: "//exported goParse"},
		{comment: "//go:noinline"},
		{comment: "/* //export goParse */"},
	}
	for _, tt := range tests {
		t.Run(tt.comment, func(t *testing.T) {
			got, matched, err := domain.ParseExportDirective(tt.comment)
			if matched != tt.wantMatched {
				t.Fatalf("matched = %v, want %v", matched, tt.wantMatched)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, domain.ErrInvalidExportDirective) {
				t.Errorf("err = %v, want ErrInvalidExportDirective", err)
			}
			if got != tt.want {
				t.Errorf("directive = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestNewExportDirective_RefusesWhatNoToolchainAccepts(t *testing.T) {
	tests := []struct {
		name string
		kind domain.ExportKind
		sym  string
	}{
		{name: "zero value", kind: "", sym: ""},
		{name: "unknown kind", kind: "linkname", sym: "x"},
		{name: "wasm export with no name", kind: domain.ExportWasm},
		{name: "C export with a space in the name", kind: domain.ExportC, sym: "a b"},
		{name: "interrupt with a name", kind: domain.ExportInterrupt, sym: "INT0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := domain.NewExportDirective(tt.kind, tt.sym)
			if !errors.Is(err, domain.ErrInvalidExportDirective) {
				t.Fatalf("err = %v, want ErrInvalidExportDirective", err)
			}
			if !got.IsZero() {
				t.Errorf("a refused directive came back as %+v", got)
			}
		})
	}

	got, err := domain.NewExportDirective(domain.ExportWasm, "parse")
	if err != nil || got != (domain.ExportDirective{Kind: domain.ExportWasm, Name: "parse"}) {
		t.Errorf("NewExportDirective(wasmexport, parse) = %+v, %v", got, err)
	}
}

func TestExportDirective_String(t *testing.T) {
	tests := map[string]domain.ExportDirective{
		"//go:wasmexport parse": {Kind: domain.ExportWasm, Name: "parse"},
		"//export goParse":      {Kind: domain.ExportC, Name: "goParse"},
		"//go:interrupt":        {Kind: domain.ExportInterrupt},
		"":                      {},
	}
	for want, d := range tests {
		if got := d.String(); got != want {
			t.Errorf("%+v.String() = %q, want %q", d, got, want)
		}
	}
}

// exportedRecord is a sealable record whose one owned node carries d.
func exportedRecord(d domain.ExportDirective) domain.CallGraphRecord {
	rec := makeTestRecord()
	rec.Nodes[0].ExportDirective = d
	return rec
}

func TestExportDirective_RoundTripsThroughTheSeal(t *testing.T) {
	var h domain.CallGraphRecordHasher
	d := domain.ExportDirective{Kind: domain.ExportWasm, Name: "parse"}
	sealed, err := h.SetContentHash(exportedRecord(d))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	b, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(b, []byte(`"export_directive":{"kind":"wasmexport","name":"parse"}`)) {
		t.Errorf("the sealed bytes do not carry the directive:\n%s", b)
	}
	back, err := h.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	i := slices.IndexFunc(back.Nodes, func(n domain.CallNode) bool { return n.ID == sealed.Nodes[0].ID })
	if back.Nodes[i].ExportDirective != d {
		t.Errorf("round trip = %+v, want %+v", back.Nodes[i].ExportDirective, d)
	}

	// An interrupt has no name, and the key is left out rather than written empty.
	interrupt, err := h.Marshal(exportedRecord(domain.ExportDirective{Kind: domain.ExportInterrupt}))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(interrupt, []byte(`"export_directive":{"kind":"interrupt"}`)) {
		t.Errorf("the interrupt is not sealed as a nameless directive:\n%s", interrupt)
	}
}

// TestExportDirective_AbsentLeavesTheBytesAlone is what lets the field land
// without moving the seal of a node that carries none.
func TestExportDirective_AbsentLeavesTheBytesAlone(t *testing.T) {
	var h domain.CallGraphRecordHasher
	b, err := h.Marshal(makeTestRecord())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(b, []byte("export_directive")) {
		t.Errorf("a record with no directive writes the key:\n%s", b)
	}
}

func TestExportDirective_RefusedOnBothLegs(t *testing.T) {
	var h domain.CallGraphRecordHasher
	bad := exportedRecord(domain.ExportDirective{Kind: domain.ExportC})

	if _, err := h.SetContentHash(bad); !errors.Is(err, domain.ErrInvalidExportDirective) {
		t.Errorf("SetContentHash err = %v, want ErrInvalidExportDirective", err)
	}
	if _, err := h.Marshal(bad); !errors.Is(err, domain.ErrInvalidExportDirective) {
		t.Errorf("Marshal err = %v, want ErrInvalidExportDirective", err)
	}

	good, err := h.Marshal(exportedRecord(domain.ExportDirective{Kind: domain.ExportC, Name: "goParse"}))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tampered := bytes.Replace(good, []byte(`"name":"goParse"`), []byte(`"name":""`), 1)
	if bytes.Equal(tampered, good) {
		t.Fatal("the fixture no longer carries the name this test blanks")
	}
	if _, err := h.Unmarshal(tampered); !errors.Is(err, domain.ErrInvalidExportDirective) {
		t.Errorf("Unmarshal err = %v, want ErrInvalidExportDirective", err)
	}
}

func TestCallNodeLess_OrdersOnTheDirective(t *testing.T) {
	a := domain.CallNode{ID: "x", ExportDirective: domain.ExportDirective{Kind: domain.ExportC, Name: "a"}}
	b := domain.CallNode{ID: "x", ExportDirective: domain.ExportDirective{Kind: domain.ExportC, Name: "b"}}
	c := domain.CallNode{ID: "x", ExportDirective: domain.ExportDirective{Kind: domain.ExportWasm, Name: "a"}}
	if !domain.CallNodeLess(a, b) || domain.CallNodeLess(b, a) {
		t.Error("two nodes differing only in the exported name do not order")
	}
	if !domain.CallNodeLess(a, c) || domain.CallNodeLess(c, a) {
		t.Error("two nodes differing only in the directive kind do not order")
	}
}
