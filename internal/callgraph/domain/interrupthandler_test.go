package domain_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
)

var rp2GPIO = domain.SourcePosition{File: "src/machine/machine_rp2_gpio.go", Line: 246}

func TestNewInterruptHandler_RefusesWhatNoExtractionRecords(t *testing.T) {
	h, err := domain.NewInterruptHandler(domain.HandlerInterruptNew, rp2GPIO)
	if err != nil || h.Kind != domain.HandlerInterruptNew || h.Site != rp2GPIO {
		t.Fatalf("NewInterruptHandler = %+v, %v", h, err)
	}
	if got := h.SiteString(); got != "src/machine/machine_rp2_gpio.go:246" {
		t.Errorf("SiteString = %q", got)
	}
	if got := (domain.InterruptHandler{}).SiteString(); got != "" {
		t.Errorf("zero SiteString = %q", got)
	}
	for name, c := range map[string]struct {
		kind domain.HandlerKind
		site domain.SourcePosition
	}{
		"zero":         {},
		"unknown kind": {kind: "SetInterrupt", site: rp2GPIO},
		"no file":      {kind: domain.HandlerInterruptNew, site: domain.SourcePosition{Line: 3}},
		"no line":      {kind: domain.HandlerInterruptNew, site: domain.SourcePosition{File: "a.go"}},
	} {
		if _, err := domain.NewInterruptHandler(c.kind, c.site); !errors.Is(err, domain.ErrInvalidInterruptHandler) {
			t.Errorf("%s: err = %v, want ErrInvalidInterruptHandler", name, err)
		}
	}
}

func handledRecord(h domain.InterruptHandler) domain.CallGraphRecord {
	rec := makeTestRecord()
	rec.Nodes[0].InterruptHandler = h
	return rec
}

func TestInterruptHandler_RoundTripsThroughTheSeal(t *testing.T) {
	var h domain.CallGraphRecordHasher
	fact := domain.InterruptHandler{Kind: domain.HandlerInterruptNew, Site: rp2GPIO}
	sealed, err := h.SetContentHash(handledRecord(fact))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	b, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(b, []byte(`"interrupt_handler":{"kind":"interrupt.New","site":{"file":"src/machine/machine_rp2_gpio.go","line":246}}`)) {
		t.Errorf("the sealed bytes do not carry the handler:\n%s", b)
	}
	back, err := h.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	i := slices.IndexFunc(back.Nodes, func(n domain.CallNode) bool { return n.ID == sealed.Nodes[0].ID })
	if back.Nodes[i].InterruptHandler != fact {
		t.Errorf("round trip = %+v, want %+v", back.Nodes[i].InterruptHandler, fact)
	}
	plain, err := h.Marshal(makeTestRecord())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte("interrupt_handler")) {
		t.Errorf("a record with no handler writes the key:\n%s", plain)
	}
}

func TestInterruptHandler_RefusedOnBothLegs(t *testing.T) {
	var h domain.CallGraphRecordHasher
	bad := handledRecord(domain.InterruptHandler{Kind: domain.HandlerInterruptNew})
	if _, err := h.SetContentHash(bad); !errors.Is(err, domain.ErrInvalidInterruptHandler) {
		t.Errorf("SetContentHash err = %v, want ErrInvalidInterruptHandler", err)
	}
	good, err := h.Marshal(handledRecord(domain.InterruptHandler{Kind: domain.HandlerInterruptNew, Site: rp2GPIO}))
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(good, []byte(`"kind":"interrupt.New"`), []byte(`"kind":"irq"`), 1)
	if bytes.Equal(tampered, good) {
		t.Fatal("the fixture no longer carries the kind this test rewrites")
	}
	if _, err := h.Unmarshal(tampered); !errors.Is(err, domain.ErrInvalidInterruptHandler) {
		t.Errorf("Unmarshal err = %v, want ErrInvalidInterruptHandler", err)
	}
}

func TestCallNodeLess_OrdersOnTheHandler(t *testing.T) {
	at := func(kind domain.HandlerKind, file string, line int) domain.CallNode {
		return domain.CallNode{ID: "x", InterruptHandler: domain.InterruptHandler{Kind: kind, Site: domain.SourcePosition{File: file, Line: line}}}
	}
	for _, pair := range [][2]domain.CallNode{
		{at("", "", 0), at(domain.HandlerInterruptNew, "a.go", 1)},
		{at(domain.HandlerInterruptNew, "a.go", 9), at(domain.HandlerInterruptNew, "b.go", 1)},
		{at(domain.HandlerInterruptNew, "a.go", 1), at(domain.HandlerInterruptNew, "a.go", 2)},
	} {
		if !domain.CallNodeLess(pair[0], pair[1]) || domain.CallNodeLess(pair[1], pair[0]) {
			t.Errorf("%+v and %+v do not order", pair[0].InterruptHandler, pair[1].InterruptHandler)
		}
	}
}

// A handler is an entry point the hardware enters, whether or not anything
// reaches its registration, as an export directive is.
func TestSelectEntryPointRoots_AnInterruptHandlerIsAnEntryPoint(t *testing.T) {
	got := domain.SelectEntryPointRoots([]domain.RootCandidate{
		{ID: "example.com/fw.onUART", Symbol: "onUART", Handler: domain.InterruptHandler{Kind: domain.HandlerInterruptNew, Site: rp2GPIO}},
		{ID: "example.com/fw.helper", Symbol: "helper"},
	}, domain.RootScopeProduction)
	if !slices.Equal(got, []string{"example.com/fw.onUART"}) {
		t.Errorf("SelectEntryPointRoots = %v, want the handler only", got)
	}
}
