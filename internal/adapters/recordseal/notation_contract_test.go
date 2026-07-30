package recordseal_test

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	exampledomain "github.com/eitanity/kanonarion/internal/example/domain"
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// sealedRecord is one domain's answer to "seal a record and hand back the bytes
// a store would persist, together with the seal it carries".
type sealedRecord struct {
	// domain names the hasher, so a failure says which one diverged.
	domain string
	// exclusions names the top-level fields this domain leaves out of its seal
	// on top of content_hash, exactly as its store passes them to the verifier.
	// A domain that excludes nothing leaves it empty.
	exclusions []string
	// seal returns the canonical bytes and the content hash embedded in them.
	seal func() (raw []byte, hash string, err error)
}

// sealOf drives one domain's hasher through the two calls every store makes on
// the write leg — seal the record, then marshal what the store persists.
//
// It is generic over the record type so the table below names the real hasher
// methods rather than restating each domain's error handling. A hasher that
// changed either signature stops compiling here, which is the earliest place
// this contract can notice.
//
// The record it seals is POPULATED rather than zero-valued; see populated and
// the doc on TestEveryDomainHasher_IsAcceptedBySelfConsistent for why that is
// the whole point of the fixture.
func sealOf[R any](
	domain string,
	exclusions []string,
	setContentHash func(R) (R, error),
	marshal func(R) ([]byte, error),
	contentHash func(R) string,
) sealedRecord {
	return sealedRecord{
		domain:     domain,
		exclusions: exclusions,
		seal: func() ([]byte, string, error) {
			sealed, err := setContentHash(populated[R]())
			if err != nil {
				return nil, "", fmt.Errorf("sealing a %s record: %w", domain, err)
			}
			raw, merr := marshal(sealed)
			if merr != nil {
				return nil, "", fmt.Errorf("marshalling a %s record: %w", domain, merr)
			}
			return raw, contentHash(sealed), nil
		},
	}
}

// fillDepth bounds how deep populated descends. Record shapes nest a few levels
// — a record holding findings holding a snapshot — and a bound is what keeps a
// self-referential type from recursing forever.
const fillDepth = 8

// fillTime is the instant every time field is filled with. Any non-zero value
// serves; a fixed one keeps a failure's bytes reproducible.
var fillTime = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

// populated returns a record with every settable field set to a NON-ZERO value.
//
// Zero-valued fixtures are why this contract could pass while the store could
// not verify a re-scanned record. A field a domain excludes from its seal is
// invisible in a zero record — the tags that carry provenance are omitzero or
// omitempty, so a zero one is dropped from the encoding entirely and the stored
// bytes happen to equal the sealed bytes. The divergence only exists once the
// field carries something, which in a live store is the normal state.
//
// It fills by reflection rather than by hand so the property holds for fields
// nobody thought about, including the ones a future domain adds. Unexported
// fields cannot be set and are left alone: a value object guarding its
// invariants behind them is not something a test may forge, and only TOP-LEVEL
// fields can be excluded from a seal, so the fields that matter here are
// reachable.
func populated[R any]() R {
	var r R
	fill(reflect.ValueOf(&r).Elem(), 0)
	return r
}

// fill sets v to a non-zero value, descending into composites.
func fill(v reflect.Value, depth int) {
	if depth > fillDepth || !v.CanSet() {
		return
	}
	if v.Type() == reflect.TypeOf(time.Time{}) {
		v.Set(reflect.ValueOf(fillTime))
		return
	}
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.String:
		v.SetString("x")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.Struct:
		for i := range v.NumField() {
			fill(v.Field(i), depth+1)
		}
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		fill(p.Elem(), depth+1)
		v.Set(p)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(s.Index(0), depth+1)
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		key := reflect.New(v.Type().Key()).Elem()
		fill(key, depth+1)
		val := reflect.New(v.Type().Elem()).Elem()
		fill(val, depth+1)
		m.SetMapIndex(key, val)
		v.Set(m)
	default:
		// Interfaces, channels and functions have no non-zero value this can
		// invent, and none of them appear in a canonical shape.
	}
}

// everyDomainHasher enumerates every record hasher in the repository.
//
// It is driven from the real hashers rather than from hand-written digests on
// purpose: a domain that changes its recipe, or a ninth hasher that arrives with
// a recipe of its own, is caught by construction rather than by someone
// remembering to add a case here.
//
// The exclusions each row states are the ones its store passes to the verifier,
// read from the domain itself where the domain declares any. A domain that
// excludes a field from its seal and does not say so here fails, because a
// populated record then carries a member the seal never covered.
func everyDomainHasher() []sealedRecord {
	return []sealedRecord{
		sealOf("callgraph.CallGraphRecordHasher", nil,
			callgraphdomain.CallGraphRecordHasher{}.SetContentHash,
			callgraphdomain.CallGraphRecordHasher{}.Marshal,
			func(r callgraphdomain.CallGraphRecord) string { return r.ContentHash }),
		sealOf("example.ExampleRecordHasher", nil,
			exampledomain.ExampleRecordHasher{}.SetContentHash,
			exampledomain.ExampleRecordHasher{}.Marshal,
			func(r exampledomain.ExampleRecord) string { return r.ContentHash }),
		sealOf("extract.ExtractionRunHasher", nil,
			extractdomain.ExtractionRunHasher{}.SetContentHash,
			extractdomain.ExtractionRunHasher{}.Marshal,
			func(r extractdomain.ExtractionRun) string { return r.ContentHash }),
		sealOf("fetch.CanonicalHasher", nil,
			fetchdomain.CanonicalHasher{}.SetContentHash,
			fetchdomain.CanonicalHasher{}.Marshal,
			func(r fetchdomain.FactRecord) string { return r.ContentHash }),
		sealOf("iface.InterfaceRecordHasher", nil,
			ifacedomain.InterfaceRecordHasher{}.SetContentHash,
			ifacedomain.InterfaceRecordHasher{}.Marshal,
			func(r ifacedomain.InterfaceRecord) string { return r.ContentHash }),
		sealOf("license.LicenseRecordHasher", nil,
			licensedomain.LicenseRecordHasher{}.SetContentHash,
			licensedomain.LicenseRecordHasher{}.Marshal,
			func(r licensedomain.LicenseRecord) string { return r.ContentHash }),
		sealOf("stdlib.FactsHasher", nil,
			stdlibdomain.FactsHasher{}.SetContentHash,
			stdlibdomain.FactsHasher{}.Marshal,
			func(f stdlibdomain.Facts) string { return f.ContentHash }),
		sealOf("vuln.VulnerabilityRecordHasher",
			vulndomain.VulnerabilityRecordHasher{}.SealExcludes(),
			vulndomain.VulnerabilityRecordHasher{}.SetContentHash,
			vulndomain.VulnerabilityRecordHasher{}.Marshal,
			func(r vulndomain.VulnerabilityRecord) string { return r.ContentHash }),
		sealOf("vuln.WalkScanRunHasher",
			vulndomain.WalkScanRunHasher{}.SealExcludes(),
			vulndomain.WalkScanRunHasher{}.SetContentHash,
			vulndomain.WalkScanRunHasher{}.Marshal,
			func(r vulndomain.WalkScanRun) string { return r.ContentHash }),
	}
}

// TestEveryDomainHasher_IsAcceptedBySelfConsistent pins the cross-domain fact
// that no single domain's test can pin: whatever a domain hasher emits, the
// shared verifier must accept it.
//
// This is the guard that was missing when SelfConsistent compared only against
// the prefixed notation. The vulnerability domain sealed bare hex, so the
// comparison could never hold, and Classify fell through to the wording reserved
// for altered bytes — an intact record reported as tampered with. Each domain
// tested its own notation and passed; nothing asserted the join.
//
// The fixtures are POPULATED and must stay that way. A zero-valued record does
// not exercise this contract, because the fields a domain leaves out of its seal
// are provenance tagged omitzero or omitempty: zero, they vanish from the
// encoding, so the stored bytes and the sealed bytes coincide and every domain
// passes whether or not its recipe agrees with what it stores. That is exactly
// how the vulnerability record's first-seen anchor got past this test and into a
// store, where every re-scanned record — the normal case — could not be
// verified. Do not "simplify" these fixtures back to zero values; doing so
// deletes the only thing this test measures beyond notation.
func TestEveryDomainHasher_IsAcceptedBySelfConsistent(t *testing.T) {
	t.Parallel()

	for _, d := range everyDomainHasher() {
		t.Run(d.domain, func(t *testing.T) {
			t.Parallel()

			raw, hash, err := d.seal()
			if err != nil {
				t.Fatalf("sealing a %s record: %v", d.domain, err)
			}
			if hash == "" {
				t.Fatalf("%s sealed a record with an empty content hash", d.domain)
			}

			consistent, err := recordseal.Excluding(d.exclusions...).SelfConsistent(raw, hash)
			if err != nil {
				t.Fatalf("SelfConsistent on %s bytes: %v", d.domain, err)
			}
			if !consistent {
				t.Errorf("recordseal.SelfConsistent rejects the seal %s emits (%q) with exclusions %v; "+
					"a record this verifier cannot classify is reported as altered rather than as old",
					d.domain, hash, d.exclusions)
			}
		})
	}
}

// TestEveryDomainHasher_IsAcceptedByVerifyBlob holds VerifyBlob to the same
// rule. It hard-coded the prefixed notation and was correct only because its
// sole caller happened to be a domain that used it — the same trap one function
// along, waiting for the next caller.
func TestEveryDomainHasher_IsAcceptedByVerifyBlob(t *testing.T) {
	t.Parallel()

	for _, d := range everyDomainHasher() {
		t.Run(d.domain, func(t *testing.T) {
			t.Parallel()

			raw, hash, err := d.seal()
			if err != nil {
				t.Fatalf("sealing a %s record: %v", d.domain, err)
			}
			if err := recordseal.Excluding(d.exclusions...).VerifyBlob(raw, hash); err != nil {
				t.Errorf("recordseal.VerifyBlob rejects the seal %s emits: %v", d.domain, err)
			}
		})
	}
}
