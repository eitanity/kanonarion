package application

import (
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
)

// An implementation that records no node for the queried method must not
// fabricate one.
func TestMethodNodeID_MissReturnsEmpty(t *testing.T) {
	impl := domain.InterfaceImplementation{
		Methods: []domain.ImplementedMethod{{Method: "Put", NodeID: "x.Put"}},
	}
	if got := methodNodeID(impl, "Get"); got != "" {
		t.Errorf("methodNodeID for an unrecorded method = %q, want empty", got)
	}
}
