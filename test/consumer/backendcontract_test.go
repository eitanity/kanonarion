package consumer_test

import (
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/pkg/kanonarion"
)

// A backend whose fact store does not implement FactRecordComposer is refused
// when it is opened, by the exported name of what it lacks.
func TestConsumer_AFactStoreWithoutTheRequiredCapabilityIsRefused(t *testing.T) {
	st := &kanonarion.Storage{
		Facts: newFakePostgresFactStoreWithoutCompose(), Attestations: noAttestations{}, Audit: noAudit{}, Blobs: newFakeS3BlobStore(),
		Walks: noWalks{}, WalkPresence: stubPresence{}, Licenses: stubLicences{}, Interfaces: stubInterfaces{},
		CallGraphs: stubCallGraphs{}, CallGraphOutcomes: stubOutcomes{}, Examples: stubExamples{},
		Extractions: stubExtractions{}, Vulnerabilities: stubVulns{}, SBOMs: stubSBOMs{},
		Directives: stubDirectives{}, GoDebug: stubGoDebug{}, Vendor: stubVendor{}, FIPS: stubFIPS{},
		Stdlib: stubStdlib{}, Staleness: stubStaleness{}, Native: stubNative{},
	}
	_, _, err := kanonarion.OpenDriverFrom(st, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "FactRecordComposer") {
		t.Fatalf("OpenDriverFrom with a fact store that cannot compose = %v, want a refusal naming FactRecordComposer", err)
	}
}

// putGetOnly is a fact store with only the FactStore port.
type putGetOnly struct{ kanonarion.FactStore }

func newFakePostgresFactStoreWithoutCompose() kanonarion.FactStore {
	return putGetOnly{newFakePostgresFactStore()}
}
