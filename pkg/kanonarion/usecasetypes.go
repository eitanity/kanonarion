package kanonarion

import (
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	ifaceports "code.eitanity.com/kanonarion/internal/iface/ports"
	licapp "code.eitanity.com/kanonarion/internal/license/application"
	vulndomain "code.eitanity.com/kanonarion/internal/vuln/domain"
)

// InterfaceGeneration is one coordinate and pipeline version the store holds
// interface records at, as QueryInterfaceUseCase.ListInterfaceGenerations
// lists them.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version.
type InterfaceGeneration = ifaceports.InterfaceGeneration

// DepLicenseResult is one module's licence in QueryLicenseUseCase.ResolveForWalk:
// its primary SPDX identifier, or the error reading it.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version.
type DepLicenseResult = licapp.DepLicenseResult

// ReachabilityState is a finding's reachability as a FindingTimeline states it.
//
// Stability: result enumeration (compared by consumers); unstable pre-v1.
// Values may be added within a major version.
type ReachabilityState = vulndomain.ReachabilityState

// VCSHostAllowlist is the set of source hosts a fetch cross-verifies against,
// passed on ServeRequest. The zero value and DefaultVCSHostAllowlist report a
// host outside the built-in set and still contact it; NewVCSHostAllowlist
// refuses one outside the hosts it names.
//
// Stability: request value (passed by consumers); unstable pre-v1. Build it
// with the functions below.
type VCSHostAllowlist = fetchdomain.VCSHostAllowlist

// DefaultVCSHostAllowlist returns the built-in host set, which reports rather
// than refuses.
//
// Stability: constructor of VCSHostAllowlist; unstable pre-v1.
func DefaultVCSHostAllowlist() VCSHostAllowlist { return fetchdomain.DefaultVCSHostAllowlist() }

// NewVCSHostAllowlist returns an allowlist that refuses every host not in
// hosts. It refuses an empty or malformed list.
//
// Stability: constructor of VCSHostAllowlist; unstable pre-v1.
func NewVCSHostAllowlist(hosts []string) (VCSHostAllowlist, error) {
	return fetchdomain.NewVCSHostAllowlist(hosts) //nolint:wrapcheck // the domain error names the host it refused
}
