package storage_test

import (
	"testing"

	callgraphports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/composition/storage"
	directiveports "github.com/eitanity/kanonarion/internal/directive/ports"
	exampleports "github.com/eitanity/kanonarion/internal/example/ports"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	fipsports "github.com/eitanity/kanonarion/internal/fips/ports"
	godebugports "github.com/eitanity/kanonarion/internal/godebug/ports"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	nativeports "github.com/eitanity/kanonarion/internal/native/ports"
	sbomports "github.com/eitanity/kanonarion/internal/sbom/ports"
	stalenessports "github.com/eitanity/kanonarion/internal/staleness/ports"
	stdlibports "github.com/eitanity/kanonarion/internal/stdlib/ports"
	vendorports "github.com/eitanity/kanonarion/internal/vendortree/ports"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Each stub is a non-nil value of one port; Validate only asks whether a
// field is set, so no method is ever called.
type (
	facts        struct{ fetchports.FactStore }
	attestations struct{ fetchports.AttestationStore }
	auditSink    struct{ fetchports.AuditSink }
	blobs        struct{ fetchports.BlobStore }
	walks        struct{ walkports.WalkStore }
	presence     struct{ vulnports.WalkPresence }
	outcomes     struct {
		callgraphports.CallGraphOutcomeReader
	}
	licences    struct{ licenseports.LicenseStore }
	interfaces  struct{ ifaceports.InterfaceStore }
	callGraphs  struct{ callgraphports.CallGraphStore }
	examples    struct{ exampleports.ExampleStore }
	extractions struct{ extractports.ExtractionStore }
	vulns       struct{ vulnports.VulnerabilityStore }
	sboms       struct{ sbomports.SBOMStore }
	directives  struct{ directiveports.DirectiveStore }
	goDebug     struct{ godebugports.GoDebugStore }
	vendor      struct{ vendorports.VendorStore }
	fips        struct{ fipsports.FIPSStore }
	stdlib      struct{ stdlibports.Store }
	staleness   struct{ stalenessports.Ledger }
	native      struct{ nativeports.NativeStore }
)

func full() *storage.Storage {
	return &storage.Storage{
		Facts: facts{}, Attestations: attestations{}, Audit: auditSink{}, Blobs: blobs{},
		Walks: walks{}, WalkPresence: presence{}, CallGraphOutcomes: outcomes{}, Licenses: licences{}, Interfaces: interfaces{}, CallGraphs: callGraphs{},
		Examples: examples{}, Extractions: extractions{}, Vulnerabilities: vulns{}, SBOMs: sboms{},
		Directives: directives{}, GoDebug: goDebug{}, Vendor: vendor{}, FIPS: fips{},
		Stdlib: stdlib{}, Staleness: staleness{}, Native: native{},
	}
}

func TestValidate_NamesEveryUnsetRequiredField(t *testing.T) {
	err := (&storage.Storage{}).Validate()
	const want = "storage: Facts, Attestations, Audit, Blobs, Walks, WalkPresence, Licenses, Interfaces, " +
		"CallGraphs, CallGraphOutcomes, Examples, Extractions, Vulnerabilities, SBOMs, Directives, GoDebug, Vendor, FIPS, Stdlib, " +
		"Staleness, Native are unset"
	if err == nil || err.Error() != want {
		t.Fatalf("Validate() = %v, want %q", err, want)
	}
}

func TestValidate_NamesASingleUnsetField(t *testing.T) {
	st := full()
	st.Native = nil
	if err := st.Validate(); err == nil || err.Error() != "storage: Native is unset" {
		t.Fatalf("Validate() = %v, want %q", err, "storage: Native is unset")
	}
}

// Signer, Schema, Writable and Close are left nil here: each has a stated
// meaning when absent, so none is required.
func TestValidate_AcceptsAFullValueWithoutTheOptionalFields(t *testing.T) {
	if err := full().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestValidate_RefusesANilValue(t *testing.T) {
	var st *storage.Storage
	if err := st.Validate(); err == nil || err.Error() != "storage: no storage value" {
		t.Fatalf("Validate() = %v, want the nil-value refusal", err)
	}
}
