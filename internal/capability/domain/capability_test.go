package domain

import "testing"

func TestAllCapabilitiesAreValid(t *testing.T) {
	caps := AllCapabilities()
	if len(caps) != 21 {
		t.Fatalf("AllCapabilities len = %d, want 21 (13 Act, 7 Context, 1 Suppressed)", len(caps))
	}
	seen := make(map[Capability]bool)
	tiers := make(map[Tier]int)
	for _, c := range caps {
		if !c.Valid() {
			t.Errorf("%q reported invalid but is in AllCapabilities", c)
		}
		if seen[c] {
			t.Errorf("%q appears twice in AllCapabilities", c)
		}
		if c.CapslockCategory() == "" {
			t.Errorf("%q has no capslock category", c)
		}
		seen[c] = true
		tiers[c.Tier()]++
	}
	if tiers[TierAct] != 13 || tiers[TierContext] != 7 || tiers[TierSuppressed] != 1 {
		t.Errorf("tier sizes = %v, want act 13, context 7, suppressed 1", tiers)
	}
	if len(capabilityInfo) != len(caps) {
		t.Errorf("capabilityInfo has %d entries for %d values", len(capabilityInfo), len(caps))
	}
}

func TestCapabilityValidRejectsUnknown(t *testing.T) {
	for _, c := range []Capability{"NONSENSE", "", "NETWORK"} {
		if c.Valid() {
			t.Errorf("%q should be invalid", c)
		}
		if c.Tier() != TierSuppressed || c.CapslockCategory() != "" {
			t.Errorf("%q: tier %q capslock %q, want suppressed and none", c, c.Tier(), c.CapslockCategory())
		}
	}
}

// The compatibility map is many-to-one and documented; this pins it.
func TestCapslockCategoryMap(t *testing.T) {
	want := map[Capability]string{
		CapabilityExecProcess: "EXEC", CapabilityExecDynamic: "ARBITRARY_EXECUTION",
		CapabilityNetDial: "NETWORK", CapabilityNetListen: "NETWORK", CapabilityNetTransfer: "NETWORK",
		CapabilityNetInspect: "NETWORK",
		CapabilityFSRead:     "FILES", CapabilityFSWrite: "FILES", CapabilityFSStream: "FILES", CapabilityPathPure: "FILES",
		CapabilityEnvRead: "READ_SYSTEM_STATE", CapabilityHostIdentity: "READ_SYSTEM_STATE",
		CapabilityEnvWrite: "MODIFY_SYSTEM_STATE", CapabilityLogWrite: "MODIFY_SYSTEM_STATE",
		CapabilityProcControl: "OPERATING_SYSTEM", CapabilitySyscallDirect: "SYSTEM_CALLS",
		CapabilityCgoCall: "CGO", CapabilityUnsafePointer: "UNSAFE_POINTER",
		CapabilityReflectDynamic: "REFLECT", CapabilityReflectInspect: "REFLECT",
		CapabilityRuntimeInternal: "RUNTIME",
	}
	for c, cat := range want {
		if got := c.CapslockCategory(); got != cat {
			t.Errorf("%s.CapslockCategory() = %q, want %q", c, got, cat)
		}
	}
	if len(want) != len(AllCapabilities()) {
		t.Errorf("map pins %d values of %d", len(want), len(AllCapabilities()))
	}
}

func TestRankOrders(t *testing.T) {
	tiers := []Tier{TierAct, TierContext, TierSuppressed}
	for i := 1; i < len(tiers); i++ {
		if tierRank(tiers[i-1]) >= tierRank(tiers[i]) {
			t.Errorf("tier %s must rank above %s", tiers[i-1], tiers[i])
		}
	}
	witnesses := []struct {
		reach  Reach
		symbol string
	}{
		{ReachDirectCall, "Dial"}, {ReachUnanalyzed, "RawSyscall"}, {ReachRuntimePlumbing, "readHosts"},
		{ReachUnanalyzed, "runtime_AfterFork"}, {ReachPkgLinkage, "init"},
	}
	for i := 1; i < len(witnesses); i++ {
		a, b := witnesses[i-1], witnesses[i]
		if witnessRank(a.reach, a.symbol) <= witnessRank(b.reach, b.symbol) {
			t.Errorf("a %s %s witness is preferred over %s %s", a.reach, a.symbol, b.reach, b.symbol)
		}
	}
	for _, w := range witnesses {
		want := w.reach == ReachRuntimePlumbing || w.symbol == "runtime_AfterFork"
		if got := IsPlumbing(w.reach, w.symbol); got != want {
			t.Errorf("IsPlumbing(%s, %s) = %v, want %v", w.reach, w.symbol, got, want)
		}
	}
	order := []CallerKind{CallerInit, CallerTestInit, CallerExportedAPI, CallerTest, CallerInternal, CallerMain}
	for i := 1; i < len(order); i++ {
		if callerKindRank(order[i-1]) >= callerKindRank(order[i]) {
			t.Errorf("%s must rank above %s", order[i-1], order[i])
		}
	}
	for _, k := range order {
		if got, want := k.Collapsed(), k == CallerTest || k == CallerInternal; got != want {
			t.Errorf("%s.Collapsed() = %v, want %v", k, got, want)
		}
	}
	if !capabilityLess(CapabilityNetDial, CapabilityFSStream) || !capabilityLess(CapabilityEnvRead, CapabilityExecProcess) {
		t.Error("capabilities order by tier, then name")
	}
}
